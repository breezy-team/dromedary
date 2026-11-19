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

import os
import socket
import struct
import time
import unittest

from dromedary.tests import http_server, https_server, ssl_certs


class _FakeTestCaseServer:
    _home_dir = os.getcwd()


def _reset(sock):
    """Close sock so that the peer sees a connection reset."""
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    sock.close()


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
        # Give the reset time to reach the server's accept queue.
        time.sleep(0.1)
        request, addr = self.server.get_request()
        self.addCleanup(request.close)
        self.assertEqual(good.getsockname(), addr)

    def test_reset_before_handshake(self):
        client = self.connect()
        request, addr = self.server.get_request()
        self.addCleanup(request.close)
        _reset(client)
        time.sleep(0.1)
        self.assertFalse(self.server.verify_request(request, addr))
