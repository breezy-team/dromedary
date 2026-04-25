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

        Mirrors :meth:`dromedary.http.urllib.HttpTransport.__new__`:
        TLS-related knobs are deferred to ``__init__`` so breezy
        subclasses that add ``ca_certs`` to their own ``__init__``
        and call ``super().__init__(..., ca_certs=...)`` see it
        applied. ``__new__`` only does the bare-minimum base-URL
        setup; ``__init__`` rebuilds the underlying client with the
        right TLS config when it finally arrives.

        When ``_from_transport`` is supplied we construct a fresh
        Rust instance at ``base`` and then graft the source's
        HttpClient / auth cache / range hint onto it via
        ``_rust_replace_inner_from``.
        """
        self = super().__new__(
            cls,
            base,
            ca_certs=None,
            disable_verification=False,
            user_agent=urllib._default_user_agent(),
        )
        if _from_transport is not None:
            # Compute the offset so the grafted state targets the
            # right base URL, then swap in the shared state.
            offset = urllib._offset_from_base(_from_transport.base, base)
            self._rust_replace_inner_from(_from_transport, offset)
        return self

    def __init__(self, base, _from_transport=None, ca_certs=None):
        """Initialise Python-side state and TLS-configured inner client.

        Rust ``__new__`` populated the base-URL state with a minimal
        default client. TLS knobs take effect here so subclasses that
        override ``__init__`` and call ``super().__init__(..., ca_certs=...)``
        pick up correctly — see
        :meth:`dromedary.http.urllib.HttpTransport.__init__`.
        """
        self._medium = None
        if _from_transport is None:
            import ssl as _ssl

            import dromedary.http as _mod_http

            if ca_certs is None:
                configured = _mod_http.ssl_ca_certs()
                if configured:
                    ca_certs = configured
            disable_verification = _mod_http.ssl_cert_reqs() == _ssl.CERT_NONE
            if disable_verification:
                ca_certs = None
            fresh = _webdav_rs.HttpDavTransport(
                base,
                ca_certs=ca_certs,
                disable_verification=disable_verification,
                user_agent=urllib._default_user_agent(),
            )
            # ``offset=None`` lets ``_rust_replace_inner_from`` share
            # ``fresh``'s inner directly, preserving raw_base and
            # segment parameters that ``clone_concrete(None)`` would
            # otherwise strip.
            self._rust_replace_inner_from(fresh, None)
        # Wire an activity callback into the Rust transport so
        # internal get/has/post/readv calls feed breezy's progress
        # UI too, not just the explicit ``.request()`` path. Same
        # pattern as ``HttpTransport.__init__``.
        import weakref

        wself = weakref.ref(self)

        def _forward(byte_count, direction):
            t = wself()
            if t is None:
                return
            t._report_activity(byte_count, direction)

        self._set_activity_callback(_forward)

    def clone(self, offset=None):
        """Return a new transport sharing this transport's HttpClient.

        Uses ``urlutils.URL.clone`` path-combine semantics rather
        than ``abspath`` URL-join semantics — see
        :meth:`dromedary.http.urllib.HttpTransport.clone`.
        """
        if offset is None:
            new_base = self.base
        else:
            from dromedary._transport_rs.urlutils import URL

            new_base = str(URL.from_string(self.base).clone(offset))
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

    def open_write_stream(self, relpath, mode=None):
        """Open a writable stream at ``relpath``.

        WebDAV has no native append/stream verbs, so we back the
        stream with append-based writes: the Transport protocol's
        ``AppendBasedFileStream`` sends one PUT per ``write()``,
        each concatenating the new bytes onto the server-side file.
        Inefficient for large files but correct; bzr only uses
        open_write_stream for small status/lock files.

        We start by PUT'ing an empty body so the file exists when
        ``open_write_stream`` returns (the Transport contract
        requires it — breezy's ``test_opening_a_file_stream_creates_
        file`` exercises exactly that shape). ``FileStream.close``
        looks the stream up in the module-level ``_file_streams``
        registry, so we insert it there too.
        """
        from dromedary import AppendBasedFileStream, _file_streams

        self.put_bytes(relpath, b"")
        handle = AppendBasedFileStream(self, relpath)
        _file_streams[self.abspath(relpath)] = handle
        return handle


def get_test_permutations():
    """Return the permutations to be used in testing."""
    from .tests import dav_server

    return [
        (HttpDavTransport, dav_server.DAVServer),
        (HttpDavTransport, dav_server.QuirkyDAVServer),
    ]
