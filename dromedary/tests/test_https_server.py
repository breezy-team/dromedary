# Copyright (C) 2026 Jelmer Vernooĳ <jelmer@jelmer.uk>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

import errno
import os
import select
import socket
import ssl
import struct
import sys
import unittest
from unittest import mock

from dromedary.tests import http_server, https_server, ssl_certs


class _FakeTestCaseServer:
    _home_dir = os.getcwd()


def _reset(sock):
    """Close sock so that the peer sees a connection reset."""
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    sock.close()


def _wait_readable(sock, timeout=10.0):
    """Block until sock is readable (e.g. has a pending connection or RST)."""
    r, _, _ = select.select([sock], [], [], timeout)
    if not r:
        raise AssertionError(f"socket not readable within {timeout}s")


class TestDroppedConnections(unittest.TestCase):
    """A client that goes away before the TLS handshake must not kill the server."""

    def setUp(self):
        super().setUp()
        self.server = https_server.TestingThreadingHTTPSServer(
            ("127.0.0.1", 0),
            http_server.TestingHTTPRequestHandler,
            _FakeTestCaseServer(),
            ssl_certs.build_path("server_without_pass.key"),
            ssl_certs.build_path("server.crt"),
        )
        self.addCleanup(self.server.socket.close)
        self.server.serving = True

    def connect(self):
        host, port = self.server.server_address[:2]
        sock = socket.create_connection((host, port))
        self.addCleanup(sock.close)
        return sock

    def test_reset_before_accept(self):
        _reset(self.connect())
        good = self.connect()
        request, addr = self.server.get_request()
        self.addCleanup(request.close)
        self.assertEqual(good.getsockname(), addr)

    def test_reset_before_handshake(self):
        client = self.connect()
        request, addr = self.server.get_request()
        self.addCleanup(request.close)
        _reset(client)
        _wait_readable(request)
        self.assertFalse(self.server.verify_request(request, addr))

    def test_einval_in_wrap_socket_retried_on_macos(self):
        self.connect()
        second = self.connect()
        orig_wrap = ssl.SSLContext.wrap_socket
        calls = 0

        def wrap_once_einval(ctx, *args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError(errno.EINVAL, "Invalid argument")
            return orig_wrap(ctx, *args, **kwargs)

        with (
            mock.patch.object(sys, "platform", "darwin"),
            mock.patch.object(ssl.SSLContext, "wrap_socket", wrap_once_einval),
        ):
            request, addr = self.server.get_request()
        self.addCleanup(request.close)
        self.assertEqual(2, calls)
        self.assertEqual(second.getsockname(), addr)
        self.assertEqual(1, len(self.server.clients))
        self.assertEqual(second.getsockname(), self.server.clients[0][1])

    def test_einval_in_wrap_socket_propagates_off_macos(self):
        self.connect()
        try:
            with (
                mock.patch.object(sys, "platform", "linux"),
                mock.patch.object(
                    ssl.SSLContext,
                    "wrap_socket",
                    side_effect=OSError(errno.EINVAL, "Invalid argument"),
                ),
                self.assertRaises(OSError) as cm,
            ):
                self.server.get_request()
        finally:
            for sock, _addr, _thread in self.server.clients:
                sock.close()
        self.assertEqual(errno.EINVAL, cm.exception.errno)

    def test_einval_in_verify_request_is_not_swallowed(self):
        request = mock.Mock()
        request.do_handshake.side_effect = OSError(errno.EINVAL, "Invalid argument")
        with (
            mock.patch.object(sys, "platform", "darwin"),
            self.assertRaises(OSError) as cm,
        ):
            self.server.verify_request(request, ("127.0.0.1", 12345))
        self.assertEqual(errno.EINVAL, cm.exception.errno)

    def test_einval_in_context_setup_is_not_swallowed(self):
        with (
            mock.patch.object(sys, "platform", "darwin"),
            mock.patch.object(
                ssl.SSLContext,
                "load_cert_chain",
                side_effect=OSError(errno.EINVAL, "Invalid argument"),
            ),
            self.assertRaises(OSError) as cm,
        ):
            self.server.get_request()
        self.assertEqual(errno.EINVAL, cm.exception.errno)
