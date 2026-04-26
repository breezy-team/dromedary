# Copyright (C) 2006-2009, 2011, 2012, 2013 Canonical Ltd
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

"""WebDAV transport: thin Python subclass over the Rust HttpDavTransport.

The Rust class (``dromedary._transport_rs.webdav.HttpDavTransport``)
owns the HTTP verbs, the PROPFIND XML parser, the atomic-put dance,
and both append strategies. This module layers the small Python-only
bits:

* the ``__init__`` handshake that resolves ``ssl_ca_certs`` /
  ``ssl_cert_reqs`` from ``dromedary.http`` module hooks and grafts
  the source transport's HttpClient onto clones (same pattern as
  ``dromedary.http.urllib.HttpTransport``)
* Python-flavoured wrappers that adapt the Rust pymethod signatures
  to the Transport-protocol ones dromedary expects (``put_file``
  reading a file-like, ``get`` returning a BytesIO, etc.)
* the ``get_test_permutations`` entry point used by
  ``dromedary/tests/per_transport.py``
"""

from io import BytesIO

from dromedary.http import urllib

from .._transport_rs import webdav as _webdav_rs


class HttpDavTransport(_webdav_rs.HttpDavTransport):
    """HTTP(S) transport with WebDAV write verbs."""

    def __new__(cls, base, _from_transport=None, ca_certs=None):
        """Build the Rust transport.

        Mirrors :class:`dromedary.http.urllib.HttpTransport.__new__`:
        resolves SSL options from the ``dromedary.http`` module hooks
        and, if a ``_from_transport`` is supplied, grafts its
        HttpClient onto the freshly-constructed instance so the
        connection pool and auth cache are shared.
        """
        if ca_certs is None:
            import dromedary.http as _mod_http

            configured = _mod_http.ssl_ca_certs()
            if configured:
                ca_certs = configured

        import ssl as _ssl

        import dromedary.http as _mod_http

        disable_verification = _mod_http.ssl_cert_reqs() == _ssl.CERT_NONE
        if disable_verification:
            ca_certs = None

        self = super().__new__(
            cls,
            base,
            ca_certs=ca_certs,
            disable_verification=disable_verification,
            user_agent=urllib._default_user_agent(),
        )
        if _from_transport is not None:
            # Compute the offset so the grafted state targets the
            # right base URL, then swap in the shared state.
            offset = urllib._offset_from_base(_from_transport.base, base)
            self._rust_replace_inner_from(_from_transport, offset)
        return self

    def __init__(self, base, _from_transport=None, ca_certs=None):
        """Initialize the Python-side state."""
        # Rust __new__ populates the transport state. The only
        # Python-side slot is `_medium`, which breezy's HttpDav
        # subclass fills in on first `get_smart_medium()` call.
        self._medium = None

    def clone(self, offset=None):
        """Return a new transport sharing this transport's HttpClient."""
        new_base = self.base if offset is None else self.abspath(offset)
        return type(self)(new_base, _from_transport=self)

    def _report_activity(self, byte_count, direction):
        """Feed byte-count progress into dromedary's UI hook."""
        from dromedary import ui as _ui

        _ui.report_transport_activity(self, byte_count, direction)

    def is_readonly(self):
        """WebDAV supports writes."""
        return False

    def listable(self):
        """WebDAV exposes directory listings via PROPFIND."""
        return True

    # ------------------------------------------------------------------
    # Transport-protocol adapters. The Rust pyclass exposes bytes-in /
    # bytes-out APIs; the Python Transport contract wants file-likes
    # for get / put_file and int offsets for append_file.

    def get(self, relpath):
        """Return a file-like of ``relpath``'s contents."""
        return BytesIO(self._get_bytes(relpath))

    def get_bytes(self, relpath):
        """Return ``relpath``'s contents as bytes."""
        return self._get_bytes(relpath)

    def put_file(self, relpath, f, mode=None):
        """Store the contents of `f` at `relpath`. Returns the length."""
        data = f.read()
        self.put_bytes(relpath, data)
        return len(data)

    def put_file_non_atomic(
        self,
        relpath,
        f,
        mode=None,
        create_parent_dir=False,
        dir_mode=None,
    ):
        """Non-atomic version of put_file (skips the temp-file dance)."""
        self.put_bytes_non_atomic(relpath, f.read(), create_parent_dir)

    def append_file(self, relpath, f, mode=None):
        """Append `f.read()` to `relpath`. Returns the old length."""
        return self.append_bytes(relpath, f.read())


def get_test_permutations():
    """Return the permutations to be used in testing."""
    from .tests import dav_server

    return [
        (HttpDavTransport, dav_server.DAVServer),
        (HttpDavTransport, dav_server.QuirkyDAVServer),
    ]
