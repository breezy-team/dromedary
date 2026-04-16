# Copyright (C) 2025 Breezy Developers
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

"""Tests for the GIO transport.

These exercise the `gio+file://` backend, which is the only gio backend
that works without a real gvfs mount. The whole module is skipped when
dromedary was built without the `gio` Cargo feature.
"""

import tempfile
import unittest

from dromedary import urlutils
from dromedary.errors import DependencyNotPresent

try:
    from dromedary.gio_transport import GioTransport
except DependencyNotPresent:
    GioTransport = None


@unittest.skipIf(GioTransport is None, "dromedary built without the gio feature")
class GioTransportTests(unittest.TestCase):
    def setUp(self):
        if GioTransport is None:
            self.skipTest("dromedary built without the gio feature")
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.base = "gio+" + urlutils.local_path_to_url(self._dir.name) + "/"
        self.t = GioTransport(self.base)

    def test_external_url_round_trips(self):
        self.assertEqual(self.base, self.t.external_url())

    def test_put_get_has(self):
        self.assertFalse(self.t.has("hello"))
        self.t.put_bytes("hello", b"world")
        self.assertTrue(self.t.has("hello"))
        self.assertEqual(b"world", self.t.get_bytes("hello"))

    def test_mkdir_stat_list(self):
        self.t.mkdir("d")
        self.t.put_bytes("d/a", b"1")
        self.t.put_bytes("d/b", b"22")
        self.assertEqual(["a", "b"], sorted(self.t.list_dir("d")))
        st = self.t.stat("d/a")
        self.assertEqual(1, st.st_size)

    def test_rename_and_delete(self):
        self.t.put_bytes("a", b"hi")
        self.t.rename("a", "b")
        self.assertFalse(self.t.has("a"))
        self.assertEqual(b"hi", self.t.get_bytes("b"))
        self.t.delete("b")
        self.assertFalse(self.t.has("b"))

    def test_append_extends_file(self):
        self.t.put_bytes("f", b"abc")
        from io import BytesIO

        offset = self.t.append_file("f", BytesIO(b"DEF"))
        self.assertEqual(3, offset)
        self.assertEqual(b"abcDEF", self.t.get_bytes("f"))

    def test_clone_descends(self):
        self.t.mkdir("sub")
        self.t.put_bytes("sub/inside", b"x")
        sub = self.t.clone("sub")
        self.assertEqual(b"x", sub.get_bytes("inside"))

    def test_missing_file_raises(self):
        from dromedary.errors import NoSuchFile

        self.assertRaises(NoSuchFile, self.t.get_bytes, "nope")
