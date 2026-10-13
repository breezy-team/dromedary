# Copyright (C) 2026 Jelmer Vernooij
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

"""Tests for dromedary.http and dromedary.http.ca_bundle."""

import os
import ssl
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from dromedary import http
from dromedary._transport_rs.http import HttpClient
from dromedary.http import ca_bundle
from dromedary.tests import isolate_proxy_env


class TestGetCaPath(unittest.TestCase):
    def setUp(self):
        self._orig_env = os.environ.get("CURL_CA_BUNDLE")
        ca_bundle._clear_cache()
        self.addCleanup(self._restore_env)
        self.addCleanup(ca_bundle._clear_cache)

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmpdir = tmp.name
        self.bundle_a = os.path.join(self.tmpdir, "a.pem")
        self.bundle_b = os.path.join(self.tmpdir, "b.pem")

    def _restore_env(self):
        if self._orig_env is None:
            os.environ.pop("CURL_CA_BUNDLE", None)
        else:
            os.environ["CURL_CA_BUNDLE"] = self._orig_env

    def test_env_var_returned(self):
        os.environ["CURL_CA_BUNDLE"] = self.bundle_a
        self.assertEqual(self.bundle_a, ca_bundle.get_ca_path(use_cache=False))

    def test_empty_when_unset(self):
        os.environ.pop("CURL_CA_BUNDLE", None)
        # On non-Windows hosts the Windows-specific fallback doesn't fire, so
        # the result must be the empty string.
        if sys.platform != "win32":
            self.assertEqual("", ca_bundle.get_ca_path(use_cache=False))

    def test_cache_freezes_result(self):
        os.environ["CURL_CA_BUNDLE"] = self.bundle_a
        first = ca_bundle.get_ca_path(use_cache=True)
        os.environ["CURL_CA_BUNDLE"] = self.bundle_b
        second = ca_bundle.get_ca_path(use_cache=True)
        self.assertEqual(self.bundle_a, first)
        self.assertEqual(first, second)

    def test_cache_bypass_sees_new_value(self):
        os.environ["CURL_CA_BUNDLE"] = self.bundle_a
        ca_bundle.get_ca_path(use_cache=True)
        os.environ["CURL_CA_BUNDLE"] = self.bundle_b
        self.assertEqual(self.bundle_b, ca_bundle.get_ca_path(use_cache=False))

    def test_clear_cache_resets(self):
        os.environ["CURL_CA_BUNDLE"] = self.bundle_a
        ca_bundle.get_ca_path(use_cache=True)
        os.environ["CURL_CA_BUNDLE"] = self.bundle_b
        ca_bundle._clear_cache()
        self.assertEqual(self.bundle_b, ca_bundle.get_ca_path(use_cache=True))


class TestDefaultCaCerts(unittest.TestCase):
    def test_returns_string(self):
        result = http.default_ca_certs()
        self.assertIsInstance(result, str)
        self.assertNotEqual("", result)

    @unittest.skipIf(
        sys.platform in ("win32", "darwin"),
        "Linux/BSD-specific behaviour: macOS/Windows materialise the native "
        "root store to a tempfile rather than using a known on-disk location.",
    )
    def test_result_is_from_known_locations(self):
        # On Linux/BSD `default_ca_certs()` returns the first existing path
        # from `_ssl_ca_certs_known_locations` (or the first listed entry as
        # a breadcrumb when none exist on disk).
        self.assertIn(http.default_ca_certs(), http._ssl_ca_certs_known_locations)

    def test_known_locations_non_empty(self):
        self.assertGreater(len(http._ssl_ca_certs_known_locations), 0)
        self.assertTrue(
            all(isinstance(p, str) for p in http._ssl_ca_certs_known_locations)
        )


class TestDefaultCertReqs(unittest.TestCase):
    def test_platform_dependent(self):
        result = http.default_cert_reqs()
        if sys.platform in ("win32", "darwin"):
            self.assertEqual(ssl.CERT_NONE, result)
        else:
            self.assertEqual(ssl.CERT_REQUIRED, result)


class TestUserAgent(unittest.TestCase):
    def test_default_starts_with_dromedary(self):
        self.assertTrue(http.default_user_agent().startswith("Dromedary/"))

    def test_set_user_agent_roundtrips(self):
        original = http.default_user_agent()
        self.addCleanup(http.set_user_agent, original)
        http.set_user_agent("TestAgent/1.2.3")
        self.assertEqual("TestAgent/1.2.3", http.default_user_agent())


class TestCredentialLookup(unittest.TestCase):
    def setUp(self):
        self._original = http.get_credential_lookup()
        self.addCleanup(http.set_credential_lookup, self._original)

    def test_default_returns_no_credentials(self):
        self.assertEqual((None, None), http.get_credentials("https", "example.com"))

    def test_set_credential_lookup_is_used(self):
        seen = {}

        def lookup(protocol, host, port=None, path=None, realm=None):
            seen["args"] = (protocol, host, port, path, realm)
            return ("alice", "secret")

        http.set_credential_lookup(lookup)
        self.assertEqual(
            ("alice", "secret"),
            http.get_credentials("https", "example.com", port=443, path="/", realm="r"),
        )
        self.assertEqual(("https", "example.com", 443, "/", "r"), seen["args"])


class TestTokenProvider(unittest.TestCase):
    def setUp(self):
        self._original = http.get_token_provider()
        self.addCleanup(http.set_token_provider, self._original)

    def test_default_is_unset(self):
        http.set_token_provider(None)
        self.assertIsNone(http.get_token_provider())

    def test_set_and_get_roundtrip(self):
        def cb(protocol, host, port=None, path=None):
            return (None, None)

        http.set_token_provider(cb)
        self.assertIs(cb, http.get_token_provider())

    def test_clear_with_none(self):
        http.set_token_provider(lambda *a, **kw: (None, None))
        http.set_token_provider(None)
        self.assertIsNone(http.get_token_provider())


class _CaptureAuthHandler(BaseHTTPRequestHandler):
    """HTTP handler that records the request's Authorization header
    and replies 200 OK regardless. Used to verify that the dromedary
    client attaches preemptive bearer tokens.
    """

    def do_GET(self):
        self.server.last_authorization = self.headers.get("Authorization")
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, *args, **kwargs):  # silence stderr noise
        pass


class TestTokenProviderEndToEnd(unittest.TestCase):
    """Drive the Rust HTTP client against a stdlib HTTPServer to
    verify that a registered token provider results in an
    Authorization header on the wire.
    """

    def setUp(self):
        isolate_proxy_env(self)
        self._original_token = http.get_token_provider()
        self.addCleanup(http.set_token_provider, self._original_token)

        self.server = HTTPServer(("127.0.0.1", 0), _CaptureAuthHandler)
        self.server.last_authorization = None
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        self.addCleanup(self._stop_server)

    def _stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def _url(self, path="/"):
        host, port = self.server.server_address
        return f"http://{host}:{port}{path}"

    def test_token_attached_when_no_explicit_authorization(self):
        seen = []

        def lookup(protocol, host, port=None, path=None):
            seen.append((protocol, host, port, path))
            return ("abc123", "Bearer")

        http.set_token_provider(lookup)
        client = HttpClient()
        resp = client.request("GET", self._url("/foo"), [], b"")
        self.assertEqual(200, resp.status)
        self.assertEqual("Bearer abc123", self.server.last_authorization)
        # The provider was asked with the URL's components.
        self.assertEqual(1, len(seen))
        protocol, host, port, path = seen[0]
        self.assertEqual("http", protocol)
        self.assertEqual("127.0.0.1", host)
        self.assertEqual(self.server.server_address[1], port)
        self.assertEqual("/foo", path)

    def test_explicit_authorization_wins(self):
        http.set_token_provider(lambda *a, **kw: ("abc123", "Bearer"))
        client = HttpClient()
        resp = client.request(
            "GET", self._url(), [("Authorization", "Custom keep-me")], b""
        )
        self.assertEqual(200, resp.status)
        self.assertEqual("Custom keep-me", self.server.last_authorization)

    def test_provider_returning_none_skips_header(self):
        http.set_token_provider(lambda *a, **kw: (None, None))
        client = HttpClient()
        resp = client.request("GET", self._url(), [], b"")
        self.assertEqual(200, resp.status)
        self.assertIsNone(self.server.last_authorization)


class _RedirectHandler(BaseHTTPRequestHandler):
    """HTTP handler driven by ``server.routes``: a path maps to a
    redirect target, to ``"challenge"`` (401 Basic until credentials
    arrive) or to nothing (200). Every request is recorded.
    """

    def do_GET(self):
        self.server.seen.append((self.path, self.headers))
        action = self.server.routes.get(self.path)
        if action == "challenge" and "Authorization" not in self.headers:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="test"')
        elif action not in (None, "challenge"):
            self.send_response(302)
            self.send_header("Location", action)
        else:
            self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args, **kwargs):  # silence stderr noise
        pass


class TestRedirectCredentials(unittest.TestCase):
    """Drive the Rust HTTP client through redirects between two
    stdlib HTTPServers (two ports, so two origins) and check which of
    them receives the caller's credentials.
    """

    CREDENTIALS = {
        "Authorization": "token s3cret",
        "Proxy-Authorization": "Basic cHJveHk6czNjcmV0",
        "Cookie": "session=s3cret",
        "Private-Token": "s3cret",
    }
    HEADERS = {**CREDENTIALS, "X-Other": "plain"}

    def setUp(self):
        isolate_proxy_env(self)
        self._original_token = http.get_token_provider()
        self.addCleanup(http.set_token_provider, self._original_token)
        http.set_token_provider(None)
        self.first = self._start_server()
        self.other = self._start_server()

    def _start_server(self):
        server = HTTPServer(("127.0.0.1", 0), _RedirectHandler)
        server.routes = {}
        server.seen = []
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        self.addCleanup(self._stop_server, server, thread)
        return server

    def _stop_server(self, server, thread):
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    def _url(self, server, path, userinfo=""):
        host, port = server.server_address
        return f"http://{userinfo}{host}:{port}{path}"

    def _credentials_seen(self, server, path):
        """Return the credential headers ``server`` got for ``path``."""
        (headers,) = [h for p, h in server.seen if p == path]
        self.assertEqual("plain", headers.get("X-Other"))
        return {k: headers[k] for k in self.CREDENTIALS if k in headers}

    def _get(self, url):
        return HttpClient().request(
            "GET", url, list(self.HEADERS.items()), b"", follow_redirects=True
        )

    def test_same_origin_redirect_keeps_credentials(self):
        self.first.routes["/start"] = "/end"
        resp = self._get(self._url(self.first, "/start"))
        self.assertEqual(200, resp.status)
        self.assertEqual(self.CREDENTIALS, self._credentials_seen(self.first, "/start"))
        self.assertEqual(self.CREDENTIALS, self._credentials_seen(self.first, "/end"))

    def test_other_origin_gets_no_credentials(self):
        self.first.routes["/start"] = self._url(self.other, "/end")
        resp = self._get(self._url(self.first, "/start"))
        self.assertEqual(200, resp.status)
        self.assertEqual(self.CREDENTIALS, self._credentials_seen(self.first, "/start"))
        self.assertEqual({}, self._credentials_seen(self.other, "/end"))

    def test_other_origin_gets_no_credentials_from_transport(self):
        from dromedary.http.urllib import HttpTransport

        self.first.routes["/start"] = self._url(self.other, "/end")
        transport = HttpTransport(self._url(self.first, "/"))
        resp = transport.request(
            "GET", self._url(self.first, "/start"), headers=self.HEADERS, retries=3
        )
        self.assertEqual(200, resp.status)
        self.assertEqual(self.CREDENTIALS, self._credentials_seen(self.first, "/start"))
        self.assertEqual({}, self._credentials_seen(self.other, "/end"))

    def test_back_on_first_origin_gets_credentials_again(self):
        self.first.routes["/start"] = self._url(self.other, "/middle")
        self.other.routes["/middle"] = self._url(self.first, "/end")
        resp = self._get(self._url(self.first, "/start"))
        self.assertEqual(200, resp.status)
        self.assertEqual({}, self._credentials_seen(self.other, "/middle"))
        self.assertEqual(self.CREDENTIALS, self._credentials_seen(self.first, "/end"))

    def test_url_userinfo_not_offered_to_other_origin(self):
        self.first.routes["/start"] = self._url(self.other, "/end")
        self.other.routes["/end"] = "challenge"
        resp = HttpClient().request(
            "GET",
            self._url(self.first, "/start", userinfo="joe:s3cret@"),
            [],
            b"",
            follow_redirects=True,
        )
        self.assertEqual(401, resp.status)
        self.assertEqual(
            [("/end", None)],
            [(p, h.get("Authorization")) for p, h in self.other.seen],
        )

    def test_url_userinfo_offered_to_first_origin(self):
        self.first.routes["/start"] = "/end"
        self.first.routes["/end"] = "challenge"
        resp = HttpClient().request(
            "GET",
            self._url(self.first, "/start", userinfo="joe:s3cret@"),
            [],
            b"",
            follow_redirects=True,
        )
        self.assertEqual(200, resp.status)
        self.assertEqual(
            "Basic am9lOnMzY3JldA==", self.first.seen[-1][1].get("Authorization")
        )


if __name__ == "__main__":
    unittest.main()
