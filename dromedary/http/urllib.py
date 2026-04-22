# Copyright (C) 2005-2010 Canonical Ltd
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

"""HTTP transport: thin Python subclass over the Rust HttpTransport.

The Rust class (``dromedary._transport_rs.http.HttpTransport``)
implements the whole Transport protocol including ``readv``,
``_post``, ``_head``, ``_options``, the range-hint degradation loop,
and redirect handling. This module subclasses it and layers:

* breezy's ``_medium`` slot (populated by ``get_smart_medium``)
* resolution of ``ssl_ca_certs`` / ``ssl_cert_reqs`` from the
  dromedary module-level hooks before calling the Rust constructor
* ``_redirected_to`` URL surgery for cross-transport redirects
* a ``urlencode``-style ``request`` wrapper that accepts the
  ``fields`` / ``retries`` kwargs the pre-Rust API exposed
* the ``get_test_permutations`` entry point used by
  ``dromedary/tests/per_transport.py``
"""

from urllib.parse import urlencode

import dromedary as _mod_dromedary
from dromedary._transport_rs import http as _http_rs
from dromedary.errors import RedirectRequested, UnusableRedirect

# Re-export for backwards compatibility with code that imports the
# HttpClient pyclass from dromedary.http.urllib.
HttpClient = _http_rs.HttpClient


class HttpTransport(_http_rs.HttpTransport):
    """HTTP(S) transport.

    The ``+impl`` suffix in URLs like ``http+urllib://host/`` is
    accepted and dropped — there is only one implementation now.
    """

    def __new__(cls, base, _from_transport=None, ca_certs=None):
        """Build the Rust transport.

        When ``_from_transport`` is supplied we construct a fresh
        Rust instance at ``base`` and then graft the source's
        HttpClient / auth cache / range hint onto it via
        ``_rust_replace_inner_from`` — so clones share all the
        per-client state without losing the Python subclass identity.
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
            user_agent=_default_user_agent(),
        )
        if _from_transport is not None:
            # Compute the offset so the grafted state targets the
            # right base URL, then swap in the shared state.
            offset = _offset_from_base(_from_transport.base, base)
            self._rust_replace_inner_from(_from_transport, offset)
        return self

    def __init__(self, base, _from_transport=None, ca_certs=None):
        """Initialise Python-side state; Rust ``__new__`` owns transport state."""
        # The only Python-side attribute is the _medium slot filled in
        # by breezy when get_smart_medium() is first called.
        self._medium = None

    def clone(self, offset=None):
        """Return a new transport sharing this transport's HttpClient."""
        new_base = self.base if offset is None else self.abspath(offset)
        return type(self)(new_base, _from_transport=self)

    def _report_activity(self, byte_count, direction):
        """Report byte-count progress to the dromedary UI hook.

        Called back from the Rust client during ``request()``; feeds
        into breezy's transport-activity progress bar.
        """
        from dromedary import ui as _ui

        _ui.report_transport_activity(self, byte_count, direction)

    # ------------------------------------------------------------------
    # Request wrapper — accepts the legacy ``fields`` / ``retries`` args.
    # The Rust ``request`` uses ``follow_redirects`` (bool) and no
    # fields encoding.

    def request(self, method, url, fields=None, headers=None, **urlopen_kw):
        """Issue a single HTTP request.

        ``body`` and ``fields`` are mutually exclusive; ``retries > 0``
        enables redirect following for this call (matching the
        pre-Rust API shape). Any remaining keyword arguments raise
        ``NotImplementedError`` to catch typos early.
        """
        body = urlopen_kw.pop("body", None)
        if fields is not None:
            if body is not None:
                raise ValueError("body and fields are mutually exclusive")
            body = urlencode(fields).encode()
        if headers is None:
            headers = {}
        follow_redirects = urlopen_kw.pop("retries", 0) > 0
        if urlopen_kw:
            raise NotImplementedError(f"unknown arguments: {urlopen_kw.keys()!r}")

        response = super().request(
            method,
            url,
            headers=headers,
            body=body,
            follow_redirects=follow_redirects,
            report_activity=self._report_activity,
        )

        code = response.status
        if not follow_redirects and code in (301, 302, 303, 307, 308):
            raise RedirectRequested(
                url,
                response.redirected_to,
                is_permanent=(code in (301, 308)),
            )
        return response

    # ------------------------------------------------------------------
    # has() / _post() — breezy-shape convenience wrappers.
    # `has` uses HEAD so the Rust Transport::has (which does GET) is
    # overridden to avoid pulling a response body just to check
    # existence.

    def has(self, relpath):
        """Does the target location exist?"""
        response = self._head(relpath)
        return response.status == 200

    def _post(self, body_bytes):
        """POST `body_bytes` to .bzr/smart on this transport.

        Returns ``(response_code, response_body_filelike)``. The Rust
        pyclass returns raw bytes; breezy's smart-HTTP medium calls
        ``.read(count)`` on the result, so we wrap the bytes in a
        BytesIO for that specific caller.
        """
        from io import BytesIO

        code, body = super()._post(".bzr/smart", body_bytes)
        return code, BytesIO(body)

    # ------------------------------------------------------------------
    # Historical breezy-facing helpers. These were public-ish API on
    # the pre-Rust urllib transport; breezy's own tests and a handful
    # of production code paths reach into them, so we keep them as
    # thin shims over the Rust readv / range-header logic.

    def _get(self, relpath, offsets, tail_amount=0):
        """Range-GET ``relpath`` returning ``(code, seekable_bytes)``.

        `offsets` is either `None` (fetch the whole file) or a list of
        `_CoalescedOffset` objects from `_coalesce_offsets`. The second
        element of the returned tuple is a `BytesIO` big enough that
        `.seek(abs_offset, SEEK_SET)` followed by `.read(length)`
        produces the bytes that were originally requested — i.e. a
        sparse file-in-memory.

        The Python urllib transport used to return a live HTTP body
        that handled the sparseness via content-range parsing. With
        the Rust readv machinery doing that work for us, we
        reconstitute the same sparse-file shape by dropping each
        range's data at its absolute offset in a BytesIO.
        """
        from io import BytesIO

        if not offsets and not tail_amount:
            # Whole-file fetch.
            data = self._get_bytes_inner(relpath)
            return 200, BytesIO(data)

        # Expand the coalesced-offset structs into the (start, length)
        # pairs readv wants. _CoalescedOffset carries a `ranges` list
        # of (sub_offset, sub_length) pairs relative to `start`.
        pairs = []
        if offsets:
            for coal in offsets:
                for sub_off, sub_len in coal.ranges:
                    pairs.append((coal.start + sub_off, sub_len))
        if tail_amount:
            # Need the total file length to compute absolute tail
            # offset; use the Rust stat / HEAD helper.
            resp = self._head(relpath)
            length = int(resp.getheader("content-length") or 0)
            pairs.append((max(length - tail_amount, 0), tail_amount))

        # Compute an upper bound so the BytesIO is large enough to
        # seek into for each returned range. We size it to the
        # highest (offset + length) any caller will seek+read.
        highest = max(start + length for start, length in pairs)
        out = BytesIO(b"\0" * highest)
        from dromedary.errors import (
            InvalidHttpRange as _InvalidHttpRange,
            ShortReadvError as _ShortReadvError,
        )

        try:
            for offset, chunk in self.readv(relpath, pairs):
                out.seek(offset)
                out.write(chunk)
        except _ShortReadvError as e:
            # Readv ran past the end of the file. At the `_get` API
            # layer this means the caller asked for an out-of-range
            # byte range — Python urllib raised InvalidHttpRange
            # here, matching what breezy's TestRanges expect.
            # Preserve the original ShortReadv context so callers
            # debugging a live failure still see where it came from.
            raise _InvalidHttpRange(
                self._remote_path(relpath),
                "bytes=%d-%d" % pairs[0] if pairs else "",
                str(e),
            ) from e
        out.seek(0)
        return 206, out

    def _get_bytes_inner(self, relpath):
        """Fetch the entire body of `relpath` as bytes.

        Separate helper so ``_get`` can call it without going through
        the Python ``get()`` wrapper that returns a file-like object.
        """
        f = self.get(relpath)
        try:
            return f.read()
        finally:
            if hasattr(f, "close"):
                f.close()

    @staticmethod
    def _range_header(ranges, tail_amount):
        """Build an HTTP Range header value from coalesced offsets.

        Historical public-ish API — breezy's TestRangeHeader unit
        tests call this directly to verify the byte-range encoding.
        The Rust side does the same formatting internally inside
        `HttpTransport::attempted_range_header`; this Python staticmethod
        reimplements the simple case the tests need without going
        through a full HTTP round-trip.
        """
        strings = [
            "%d-%d" % (offset.start, offset.start + offset.length - 1)
            for offset in ranges
        ]
        if tail_amount:
            strings.append("-%d" % tail_amount)
        return ",".join(strings)

    # ------------------------------------------------------------------
    # Breezy-facing redirect fix-up. The Rust side surfaces a 3xx as
    # RedirectRequested(source, target); breezy then calls this to
    # build a transport to retry the request against.

    def _redirected_to(self, source, target):
        """Return a transport suitable to re-issue a redirected request.

        The redirect is only handled when the relpath involved wasn't
        renamed. Otherwise raises UnusableRedirect and the caller
        decides what to do.
        """
        from dromedary import urlutils

        parsed_source = urlutils.URL.from_string(source)
        parsed_target = urlutils.URL.from_string(target)
        self_url = urlutils.URL.from_string(self.base)
        pl = len(self_url.path)
        excess_tail = parsed_source.path[pl:].strip("/")
        if not parsed_target.path.endswith(excess_tail):
            raise UnusableRedirect(source, target, "final part of the url was renamed")

        target_path = parsed_target.path
        if excess_tail:
            target_path = target_path[: -len(excess_tail)]

        unqualified_scheme = self._unqualified_scheme
        if parsed_target.scheme in ("http", "https"):
            if (
                parsed_target.scheme == unqualified_scheme
                and parsed_target.host == self_url.host
                and parsed_target.port == self_url.port
                and (parsed_target.user is None or parsed_target.user == self_url.user)
            ):
                return self.clone(target_path)
            redir_scheme = parsed_target.scheme
            new_url = _unsplit_url(
                redir_scheme,
                self_url.user,
                self_url.password,
                parsed_target.host,
                parsed_target.port,
                target_path,
            )
        else:
            new_url = _unsplit_url(
                parsed_target.scheme,
                parsed_target.user,
                parsed_target.password,
                parsed_target.host,
                parsed_target.port,
                target_path,
            )
        return _mod_dromedary.get_transport_from_url(new_url)


def _default_user_agent():
    """Return the current User-Agent the client should use."""
    from dromedary.http import default_user_agent

    return default_user_agent()


def _offset_from_base(parent_base, child_base):
    """Compute ``child_base`` relative to ``parent_base`` for clone().

    Used when ``_from_transport`` is supplied — breezy passes the
    absolute ``child_base``, but the Rust ``clone(offset)`` expects an
    offset. Returns ``None`` if the two are identical.
    """
    if parent_base == child_base:
        return None
    if child_base.startswith(parent_base):
        return child_base[len(parent_base) :]
    return child_base


def _unsplit_url(scheme, user, password, host, port, path):
    """Build a URL from its components. Used by ``_redirected_to``."""
    from urllib.parse import quote

    auth = ""
    if user:
        auth = quote(user, safe="")
        if password:
            auth += ":" + quote(password, safe="")
        auth += "@"
    netloc = auth + (host or "")
    if port is not None:
        netloc += f":{port}"
    return f"{scheme}://{netloc}{path}"


def get_test_permutations():
    """Return the permutations used by the per-transport test scenarios."""
    from dromedary.tests import http_server

    permutations = [(HttpTransport, http_server.HttpServer)]
    import importlib.util

    if importlib.util.find_spec("ssl") is not None:
        from dromedary.tests import https_server, ssl_certs

        _ca_path = ssl_certs.build_path("ca.crt")

        class HTTPS_transport(HttpTransport):
            def __new__(cls, base, _from_transport=None):
                return super().__new__(
                    cls,
                    base,
                    _from_transport=_from_transport,
                    ca_certs=_ca_path,
                )

            def __init__(self, base, _from_transport=None):
                super().__init__(
                    base,
                    _from_transport=_from_transport,
                    ca_certs=_ca_path,
                )

        permutations.append((HTTPS_transport, https_server.HTTPSServer))
    return permutations
