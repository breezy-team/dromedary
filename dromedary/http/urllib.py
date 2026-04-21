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

"""HTTP transport backed by the Rust HttpClient in _transport_rs.http.

The Python implementation is a thin wrapper around the Rust client:
request/response flow, TLS, proxy handling, and redirect policy all
live in Rust. This module holds the transport-shaped pieces that
don't benefit from being in Rust: range coalescing, readv retry
logic, remote-path quoting, and the redirection-target fix-up used
when breezy follows a redirect across transports.

This replaces a ~2500-line stack of urllib.request handler
subclasses (ConnectionHandler, ProxyHandler, AbstractHTTPHandler,
four AuthHandlers, HTTPRedirectHandler, Opener, custom Response and
HTTPConnection subclasses) with a single HttpTransport class.
"""

import logging
import os
import re
from urllib.parse import urlencode

import dromedary as _mod_dromedary
from dromedary import ConnectedTransport
from dromedary._transport_rs import http as _http_rs
from dromedary.errors import (
    BadHttpRequest,
    HttpBoundaryMissing,
    InvalidHttpRange,
    InvalidHttpResponse,
    InvalidRange,
    NoSuchFile,
    RedirectRequested,
    ShortReadvError,
    TransportNotPossible,
    UnexpectedHttpStatus,
    UnusableRedirect,
)
from dromedary.http.response import handle_response

logger = logging.getLogger("dromedary.http.urllib")
debug_logger = logging.getLogger("dromedary.http")


class HttpTransport(ConnectedTransport):
    """HTTP(S) transport.

    The protocol can be given as e.g. ``http+urllib://host/`` to pin a
    particular client implementation. We only have one today (the Rust
    ``HttpClient``), so the suffix is accepted but ignored.
    """

    # _unqualified_scheme: "http" or "https"
    # _scheme: may have "+pycurl", etc.  Retained as a breezy-visible
    # attribute.
    _debuglevel = 0

    # Range-coalescing knobs — tuned for Apache's limits and kept at
    # the same values the urllib-handler version used. They're
    # class-level so subclasses (webdav) can tweak individual values
    # without re-deriving everything.
    _bytes_to_read_before_seek = 128
    _max_readv_combine = 0
    _max_get_ranges = 200
    _get_max_size = 0

    def __init__(self, base, _from_transport=None, ca_certs=None):
        """Set the base URL; share a client with ``_from_transport`` if given."""
        proto_match = re.match(r"^(https?)(\+\w+)?://", base)
        if not proto_match:
            raise AssertionError(f"not a http url: {base!r}")
        self._unqualified_scheme = proto_match.group(1)
        super().__init__(base, _from_transport=_from_transport)
        # `_medium` is read by breezy's HttpTransport subclass to
        # cache the bzr-smart medium across requests. Keep the
        # attribute even though dromedary itself never uses it.
        self._medium = None
        # Range hint is a runtime downgrade knob: try multi-range,
        # fall back to single-range, then whole file. Propagated to
        # clones through _from_transport.
        if _from_transport is not None:
            self._range_hint = _from_transport._range_hint
            self._client = _from_transport._client
        else:
            self._range_hint = "multi"
            # ca_certs precedence: explicit kwarg > breezy's
            # `dromedary.http.ssl_ca_certs()` hook (a module-level
            # callable breezy swaps out per ~/.brz config) > the
            # Rust default (native store on mac/windows, known
            # Linux locations otherwise).
            if ca_certs is None:
                import dromedary.http as _mod_http

                configured = _mod_http.ssl_ca_certs()
                if configured:
                    ca_certs = configured
            # cert_reqs=none → skip verification entirely. Breezy
            # exposes this via the ssl.cert_reqs config option.
            disable_verification = False
            import ssl as _ssl

            import dromedary.http as _mod_http

            if _mod_http.ssl_cert_reqs() == _ssl.CERT_NONE:
                disable_verification = True
                ca_certs = None  # redundant with disable_verification
            self._client = _http_rs.HttpClient(
                ca_certs=ca_certs,
                disable_verification=disable_verification,
                user_agent=_default_user_agent(),
            )
        # Seed the shared-connection slot so breezy's clone-detection
        # in _get_connection returns something truthy: whether or not
        # the client has actually talked to a server yet, sharing the
        # client across clones is what matters.
        if self._get_connection() is None:
            self._set_connection(self._client, self._create_auth())

    # ------------------------------------------------------------------
    # Core request machinery

    def request(self, method, url, fields=None, headers=None, **urlopen_kw):
        """Issue a single HTTP request.

        ``body`` and ``fields`` are mutually exclusive; passing
        ``retries>0`` enables redirect following for this call
        (matching the Python-urllib behaviour). Any remaining keyword
        arguments raise ``NotImplementedError`` to catch typos early.
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

        response = self._client.request(
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
        if response.redirected_to is not None:
            logger.debug("redirected from: %s to: %s", url, response.redirected_to)
        return response

    def disconnect(self):
        """Drop the shared client state.

        ureq's connection pool lives inside the agent; replacing the
        client forces a reconnect on the next request. Python-side
        callers that just want to free the socket (not reconfigure)
        don't need this — the Rust agent reuses sockets transparently.
        """
        # No explicit close on HttpClient — dropping the reference is
        # enough for rustls to tear down the TLS sessions lazily.
        pass

    # ------------------------------------------------------------------
    # Transport methods — most are either passthroughs or "HTTP doesn't
    # support this" stubs.

    def has(self, relpath):
        """Does the target location exist?"""
        response = self._head(relpath)
        return response.status == 200

    def get(self, relpath):
        """Get the file at the given relative path."""
        _code, response_file = self._get(relpath, None)
        return response_file

    def _get(self, relpath, offsets, tail_amount=0):
        """Get a file, or part of a file.

        :param relpath: Path relative to transport base URL
        :param offsets: None to get the whole file; or a list of
            _CoalescedOffset to fetch parts of a file.
        :param tail_amount: The amount to get from the end of the file.
        :returns: (http_code, result_file)
        """
        abspath = self._remote_path(relpath)
        range_header = None
        headers = {}
        if offsets or tail_amount:
            range_header = self._attempted_range_header(offsets, tail_amount)
            if range_header is not None:
                headers = {"Range": "bytes=" + range_header}

        response = self.request("GET", abspath, headers=headers)

        if response.status == 404:
            raise NoSuchFile(abspath)
        if response.status == 416:
            raise InvalidHttpRange(
                abspath, range_header, "Server return code %d" % response.status
            )
        if response.status == 400:
            if range_header:
                raise InvalidHttpRange(
                    abspath,
                    range_header,
                    "Server return code %d" % response.status,
                )
            raise BadHttpRequest(abspath, response.reason)
        if response.status not in (200, 206):
            raise UnexpectedHttpStatus(
                abspath, response.status, headers=response.getheaders()
            )

        data = handle_response(abspath, response.status, response.getheader, response)
        return response.status, data

    def _post(self, body_bytes):
        """POST ``body_bytes`` to .bzr/smart on this transport.

        :returns: (response code, response body file-like object).
        """
        abspath = self._remote_path(".bzr/smart")
        response = self.request(
            "POST",
            abspath,
            body=body_bytes,
            headers={"Content-Type": "application/octet-stream"},
        )
        data = handle_response(abspath, response.status, response.getheader, response)
        return response.status, data

    def _head(self, relpath):
        """HEAD ``relpath``, leaving status-code handling to callers."""
        abspath = self._remote_path(relpath)
        response = self.request("HEAD", abspath)
        if response.status not in (200, 404):
            raise UnexpectedHttpStatus(
                abspath, response.status, headers=response.getheaders()
            )
        return response

    def _options(self, relpath):
        """OPTIONS request, returns the headers list."""
        abspath = self._remote_path(relpath)
        resp = self.request("OPTIONS", abspath)
        if resp.status == 404:
            raise NoSuchFile(abspath)
        if resp.status in (403, 405):
            raise InvalidHttpResponse(
                abspath,
                "OPTIONS not supported or forbidden for remote URL",
                headers=resp.getheaders(),
            )
        return resp.getheaders()

    # ------------------------------------------------------------------
    # Read-vector helpers (unchanged from the urllib version)

    def _degrade_range_hint(self, relpath, ranges):
        """Step the range hint down one rung after a server misbehaves."""
        if self._range_hint == "multi":
            self._range_hint = "single"
            logger.debug('Retry "%s" with single range request', relpath)
        elif self._range_hint == "single":
            self._range_hint = None
            logger.debug('Retry "%s" without ranges', relpath)
        else:
            return False
        return True

    def _readv(self, relpath, offsets):
        """Readv implementation over HTTP range requests.

        Handles server range support degradation: tries multi-range,
        falls back to single-range, then to a whole-file download.
        """
        offsets = list(offsets)

        try_again = True
        retried_offset = None
        while try_again:
            try_again = False

            sorted_offsets = sorted(offsets)
            coalesced = self._coalesce_offsets(
                sorted_offsets,
                limit=self._max_readv_combine,
                fudge_factor=self._bytes_to_read_before_seek,
                max_size=self._get_max_size,
            )
            coalesced = list(coalesced)
            if debug_logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    "http readv of %s  offsets => %s collapsed %s",
                    relpath,
                    len(offsets),
                    len(coalesced),
                )

            data_map = {}
            iter_offsets = iter(offsets)
            try:
                cur_offset_and_size = next(iter_offsets)
            except StopIteration:
                return

            try:
                for cur_coal, rfile in self._coalesce_readv(relpath, coalesced):
                    for offset, size in cur_coal.ranges:
                        start = cur_coal.start + offset
                        rfile.seek(start, os.SEEK_SET)
                        data = rfile.read(size)
                        data_len = len(data)
                        if data_len != size:
                            raise ShortReadvError(relpath, start, size, actual=data_len)
                        if (start, size) == cur_offset_and_size:
                            yield cur_offset_and_size[0], data
                            try:
                                cur_offset_and_size = next(iter_offsets)
                            except StopIteration:
                                return
                        else:
                            data_map[(start, size)] = data

                    while cur_offset_and_size in data_map:
                        this_data = data_map.pop(cur_offset_and_size)
                        yield cur_offset_and_size[0], this_data
                        try:
                            cur_offset_and_size = next(iter_offsets)
                        except StopIteration:
                            return

            except (
                ShortReadvError,
                InvalidRange,
                InvalidHttpRange,
                HttpBoundaryMissing,
            ) as e:
                logger.debug("Exception %r: %s during http._readv", e, e)
                if (
                    not isinstance(e, ShortReadvError)
                    or retried_offset == cur_offset_and_size
                ):
                    if not self._degrade_range_hint(relpath, coalesced):
                        raise
                offsets = [cur_offset_and_size] + list(iter_offsets)
                retried_offset = cur_offset_and_size
                try_again = True

    def _coalesce_readv(self, relpath, coalesced):
        """Issue GET requests to satisfy coalesced offsets."""

        def get_and_yield(relpath, coalesced):
            if coalesced:
                _code, rfile = self._get(relpath, coalesced)
                for coal in coalesced:
                    yield coal, rfile

        if self._range_hint is None:
            yield from get_and_yield(relpath, coalesced)
        else:
            total = len(coalesced)
            if self._range_hint == "multi":
                max_ranges = self._max_get_ranges
            elif self._range_hint == "single":
                max_ranges = total
            else:
                raise AssertionError(f"Unknown _range_hint {self._range_hint!r}")
            cumul = 0
            ranges = []
            for coal in coalesced:
                if (
                    self._get_max_size > 0 and cumul + coal.length > self._get_max_size
                ) or len(ranges) >= max_ranges:
                    yield from get_and_yield(relpath, ranges)
                    ranges = [coal]
                    cumul = coal.length
                else:
                    ranges.append(coal)
                    cumul += coal.length
            yield from get_and_yield(relpath, ranges)

    def _attempted_range_header(self, offsets, tail_amount):
        """Build a Range header respecting the current range hint."""
        if self._range_hint == "multi":
            return self._range_header(offsets, tail_amount)
        if self._range_hint == "single":
            if len(offsets) > 0:
                if tail_amount not in (0, None):
                    return None
                start = offsets[0].start
                last = offsets[-1]
                end = last.start + last.length - 1
                whole = self._coalesce_offsets(
                    [(start, end - start + 1)], limit=0, fudge_factor=0
                )
                return self._range_header(list(whole), 0)
            return self._range_header(offsets, tail_amount)
        return None

    @staticmethod
    def _range_header(ranges, tail_amount):
        """Turn coalesced ranges into an HTTP Range header value."""
        strings = [
            "%d-%d" % (offset.start, offset.start + offset.length - 1)
            for offset in ranges
        ]
        if tail_amount:
            strings.append("-%d" % tail_amount)
        return ",".join(strings)

    # ------------------------------------------------------------------
    # Read-only stubs — HTTP can't express most write operations.

    def put_file(self, relpath, f, mode=None):
        """HTTP transport is read-only."""
        raise TransportNotPossible("http PUT not supported")

    def mkdir(self, relpath, mode=None):
        """HTTP transport is read-only."""
        raise TransportNotPossible("http does not support mkdir()")

    def rmdir(self, relpath):
        """HTTP transport is read-only."""
        raise TransportNotPossible("http does not support rmdir()")

    def append_file(self, relpath, f, mode=None):
        """HTTP transport is read-only."""
        raise TransportNotPossible("http does not support append()")

    def copy(self, rel_from, rel_to):
        """HTTP transport is read-only."""
        raise TransportNotPossible("http does not support copy()")

    def copy_to(self, relpaths, other, mode=None, pb=None):
        """Copy into ``other`` — HTTP can't be the destination."""
        if isinstance(other, HttpTransport):
            raise TransportNotPossible("http cannot be the target of copy_to()")
        return super().copy_to(relpaths, other, mode=mode, pb=pb)

    def move(self, rel_from, rel_to):
        """HTTP transport is read-only."""
        raise TransportNotPossible("http does not support move()")

    def delete(self, relpath):
        """HTTP transport is read-only."""
        raise TransportNotPossible("http does not support delete()")

    def stat(self, relpath):
        """HTTP transport doesn't support stat()."""
        raise TransportNotPossible("http does not support stat()")

    def lock_write(self, relpath):
        """HTTP transport doesn't support write locks."""
        raise TransportNotPossible("http does not support lock_write()")

    def lock_read(self, relpath):
        """Return a bogus lock — HTTP doesn't enforce read locks."""

        class BogusLock:
            def __init__(self, path):
                self.path = path

            def unlock(self):
                pass

        return BogusLock(relpath)

    # ------------------------------------------------------------------
    # Metadata

    def recommended_page_size(self):
        """Suggested read page size — larger for HTTP to amortise latency."""
        return 64 * 1024

    def external_url(self):
        """URL suitable for external use (drops any +impl qualifier)."""
        url = self._parsed_url.clone()
        url.scheme = self._unqualified_scheme
        return str(url)

    def is_readonly(self):
        """HTTP doesn't support writes."""
        return True

    def listable(self):
        """HTTP has no directory listing."""
        return False

    # ------------------------------------------------------------------
    # Internal helpers

    def _remote_path(self, relpath):
        """Build a remote URL, stripping any embedded credentials.

        Credentials belong in headers, not in the URL we hand to the
        server. Auth handlers consult ``self._parsed_url`` separately.
        """
        url = self._parsed_url.clone(relpath)
        url.user = url.quoted_user = None
        url.password = url.quoted_password = None
        url.scheme = self._unqualified_scheme
        return str(url)

    def _create_auth(self):
        """Return a dict of credentials collected at build time."""
        return {
            "host": self._parsed_url.host,
            "port": self._parsed_url.port,
            "user": self._parsed_url.user,
            "password": self._parsed_url.password,
            "protocol": self._unqualified_scheme,
            "path": self._parsed_url.path,
        }

    def _redirected_to(self, source, target):
        """Return a transport suitable to re-issue a redirected request.

        The redirect is only handled when the relpath involved wasn't
        renamed. Otherwise raises UnusableRedirect and the caller
        decides what to do.
        """
        parsed_source = self._split_url(source)
        parsed_target = self._split_url(target)
        pl = len(self._parsed_url.path)
        excess_tail = parsed_source.path[pl:].strip("/")
        if not parsed_target.path.endswith(excess_tail):
            raise UnusableRedirect(source, target, "final part of the url was renamed")

        target_path = parsed_target.path
        if excess_tail:
            target_path = target_path[: -len(excess_tail)]

        if parsed_target.scheme in ("http", "https"):
            if (
                parsed_target.scheme == self._unqualified_scheme
                and parsed_target.host == self._parsed_url.host
                and parsed_target.port == self._parsed_url.port
                and (
                    parsed_target.user is None
                    or parsed_target.user == self._parsed_url.user
                )
            ):
                return self.clone(target_path)
            redir_scheme = parsed_target.scheme
            new_url = self._unsplit_url(
                redir_scheme,
                self._parsed_url.user,
                self._parsed_url.password,
                parsed_target.host,
                parsed_target.port,
                target_path,
            )
        else:
            new_url = self._unsplit_url(
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


def get_test_permutations():
    """Return the permutations used by the per-transport test scenarios."""
    from dromedary.tests import http_server

    permutations = [(HttpTransport, http_server.HttpServer)]
    try:
        import ssl  # noqa: F401

        from dromedary.tests import https_server, ssl_certs

        class HTTPS_transport(HttpTransport):
            def __init__(self, base, _from_transport=None):
                super().__init__(
                    base,
                    _from_transport=_from_transport,
                    ca_certs=ssl_certs.build_path("ca.crt"),
                )

        permutations.append((HTTPS_transport, https_server.HTTPSServer))
    except ModuleNotFoundError:
        pass
    return permutations
