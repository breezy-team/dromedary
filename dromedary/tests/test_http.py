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
import unittest

from dromedary import http
from dromedary.http import ca_bundle


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

    @unittest.skipIf(sys.platform == "win32", "Linux/BSD-specific behaviour")
    def test_result_is_from_known_locations(self):
        # On macOS the default falls back to the first known location; on
        # Linux/BSD the first existing one (or the first known location if
        # none exist) is returned. Either way the result must be in the list.
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
        self._original = http._credential_lookup
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


if __name__ == "__main__":
    unittest.main()
