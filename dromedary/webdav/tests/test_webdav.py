# Copyright (C) 2006, 2007, 2008, 2013 Canonical Ltd
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
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

"""Tests for the webdav transport.

PROPFIND response parsing is covered in Rust by the unit tests in
``src/webdav/xml.rs``; this file only holds the few scenarios that
exercise the transport end-to-end against a canned HTTP server.
"""

from http.client import parse_headers

from dromedary import errors as transport_errors
from dromedary import tests
from dromedary.tests import http_server
from dromedary.webdav import webdav


class CannedRequestHandler(http_server.TestingHTTPRequestHandler):
    """An HTTP handler that replies with a canned response for each request.

    We assume that the incoming request is fully readable (we don't
    check what request it is, we just read until an empty line).
    """

    def _handle_one_request(self):
        # The communication between the client and the server is achieved
        # through the server defined in the client test case.
        tcs = self.server.test_case_server
        requestline = self.rfile.readline()
        # Read headers
        parse_headers(self.rfile)
        if requestline.startswith(b"POST"):
            # The body should be a single line (or we don't know where it ends
            # and we don't want to issue a blocking read)
            self.rfile.readline()

        self.wfile.write(tcs.canned_response)


class HatterHttpServer(http_server.HttpServer):
    """A server giving all sort of crazy responses (like Alice's Hatter).

    This is used to test various error cases in the webdav client.
    """

    def __init__(self):
        super().__init__(CannedRequestHandler, protocol_version="HTTP/1.1")
        self.canned_response = None


class TestDAVErrors(tests.TestCase):
    def setUp(self):
        super().setUp()
        self._transport = webdav.HttpDavTransport
        self.server = HatterHttpServer()
        self.server.start_server()
        self.addCleanup(self.server.stop_server)

    def get_transport(self):
        t = self._transport(self.server.get_url())
        return t

    def test_delete_replies_202(self):
        """A bogus return code for delete raises an error."""
        # Note: this response must be well-formed (blank line after
        # headers, Content-Length, Connection: close) — the Rust HTTP
        # client is strict about framing, unlike the old urllib.py
        # which silently tolerated truncated responses. The test
        # still exercises the code path we care about: a 202 reply
        # to DELETE (which WebDAV treats as unexpected).
        self.server.canned_response = b"""HTTP/1.1 202 OK\r
Date: Tue, 10 Aug 2013 14:38:56 GMT\r
Server: Apache/42 (Wonderland)\r
Content-Length: 0\r
Connection: close\r
\r
"""
        t = self.get_transport()
        self.assertRaises(transport_errors.InvalidHttpResponse, t.delete, "whatever")
