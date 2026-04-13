# Copyright (C) 2005-2012, 2016 Canonical Ltd
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

"""Exception classes for dromedary transport layer."""


class TransportError(Exception):
    """Base class for transport-related errors."""

    internal_error = False

    _fmt = "Transport error: %(msg)s %(orig_error)s"

    def __init__(self, msg=None, orig_error=None):
        """Initialize with an optional message and originating error."""
        if msg is None and orig_error is not None:
            msg = str(orig_error)
        if orig_error is None:
            orig_error = ""
        if msg is None:
            msg = ""
        self.msg = msg
        self.orig_error = orig_error
        Exception.__init__(self)

    def _get_format_string(self):
        return self._fmt

    def __str__(self):
        """Return the formatted error message."""
        fmt = self._get_format_string()
        if fmt is not None:
            d = dict(self.__dict__)
            try:
                return fmt % d
            except (KeyError, TypeError):
                pass
        if self.args:
            return str(self.args[0])
        return self.msg or ""

    def __eq__(self, other):
        """Return True if both errors are of the same class and have equal state."""
        if self.__class__ is not other.__class__:
            return NotImplemented
        return self.__dict__ == other.__dict__

    def __hash__(self):
        """Return a hash based on object identity."""
        return id(self)

    def __repr__(self):
        """Return a debug representation including the instance dict."""
        return f"<{self.__class__.__name__}({self.__dict__!r})>"


class PathError(TransportError):
    """Generic path-related error."""

    _fmt = "Generic path error: %(path)r%(extra)s)"

    def __init__(self, path, extra=None):
        """Initialize with the offending path and optional extra detail."""
        TransportError.__init__(self)
        self.path = path
        if extra:
            self.extra = ": " + str(extra)
        else:
            self.extra = ""


class NotADirectory(PathError):
    """Raised when a path is expected to be a directory but is not."""

    _fmt = '"%(path)s" is not a directory %(extra)s'


class DirectoryNotEmpty(PathError):
    """Raised when an operation requires an empty directory."""

    _fmt = 'Directory not empty: "%(path)s"%(extra)s'


class ResourceBusy(PathError):
    """Raised when the target resource is currently busy."""

    _fmt = 'Device or resource busy: "%(path)s"%(extra)s'


class PermissionDenied(PathError):
    """Raised when access to a path is denied."""

    _fmt = 'Permission denied: "%(path)s"%(extra)s'


class NoSuchFile(PathError):
    """Raised when a referenced file or directory does not exist."""

    _fmt = 'No such file or directory: "%(path)s"%(extra)s'


class FileExists(PathError):
    """Raised when a file unexpectedly already exists."""

    _fmt = 'File exists: "%(path)s"%(extra)s'


class UnsupportedProtocol(PathError):
    """Raised when no transport supports the URL's protocol."""

    _fmt = 'Unsupported protocol for url "%(path)s"%(extra)s'


class ReadError(PathError):
    """Raised when reading from a path fails."""

    _fmt = "Error reading from %(path)r%(extra)s."


class ShortReadvError(PathError):
    """Raised when a readv call returned fewer bytes than requested."""

    _fmt = (
        "readv() read %(actual)s bytes rather than %(length)s bytes"
        ' at %(offset)s for "%(path)s"%(extra)s'
    )

    internal_error = True

    def __init__(self, path, offset, length, actual, extra=None):
        """Initialize with the path, requested offset/length and actual bytes read."""
        PathError.__init__(self, path, extra=extra)
        self.offset = offset
        self.length = length
        self.actual = actual


class PathNotChild(PathError, ValueError):
    """Raised when a path is not a descendant of an expected base path."""

    _fmt = 'Path "%(path)s" is not a child of path "%(base)s"%(extra)s'

    internal_error = False

    def __init__(self, path, base, extra=None):
        """Initialize with the path, expected base path and optional extra detail."""
        TransportError.__init__(self)
        self.path = path
        self.base = base
        if extra:
            self.extra = ": " + str(extra)
        else:
            self.extra = ""


class TransportNotPossible(TransportError):
    """Raised when an operation is not supported by the transport."""

    _fmt = "Transport operation not possible: %(msg)s %(orig_error)s"


class NotLocalUrl(TransportError):
    """Raised when a URL was expected to refer to a local path but does not."""

    _fmt = "%(url)s is not a local path."

    def __init__(self, url):
        """Initialize with the offending URL."""
        self.url = url
        TransportError.__init__(self)


class NoSmartMedium(TransportError):
    """Raised when a transport cannot tunnel the smart protocol."""

    _fmt = "The transport '%(transport)s' cannot tunnel the smart protocol."

    internal_error = True

    def __init__(self, transport):
        """Initialize with the transport that lacks smart-protocol support."""
        self.transport = transport
        TransportError.__init__(self)


class DependencyNotPresent(TransportError):
    """A required dependency for a transport is not present."""

    _fmt = 'Unable to import library "%(library)s": %(error)s'

    def __init__(self, library, error):
        """Initialize with the missing library name and import error."""
        self.library = library
        self.error = error
        TransportError.__init__(self)


class RedirectRequested(TransportError):
    """Raised when the server requested a redirect to another URL."""

    _fmt = "%(source)s is%(permanently)s redirected to %(target)s"

    def __init__(self, source, target, is_permanent=False):
        """Initialize with the source URL, target URL and whether permanent."""
        self.source = source
        self.target = target
        if is_permanent:
            self.permanently = " permanently"
        else:
            self.permanently = ""
        TransportError.__init__(self)


class TooManyRedirections(TransportError):
    """Raised when the maximum redirect chain length was exceeded."""

    _fmt = "Too many redirections"


class InProcessTransport(TransportError):
    """Raised when a transport can only be reached from within this process."""

    _fmt = "The transport '%(transport)s' is only accessible within this process."

    def __init__(self, transport):
        """Initialize with the in-process-only transport."""
        self.transport = transport
        TransportError.__init__(self)


class ConnectionError(TransportError):
    """Raised when a transport connection fails."""

    _fmt = "Connection error: %(msg)s"


class UnusableRedirect(TransportError):
    """Raised when a redirect cannot be followed."""

    _fmt = "Unable to follow redirect from %(source)s to %(target)s: %(reason)s."

    def __init__(self, source, target, reason):
        """Initialize with the source URL, target URL and reason."""
        TransportError.__init__(self)
        self.source = source
        self.target = target
        self.reason = reason


# HTTP-specific errors
class InvalidHttpResponse(TransportError):
    """Raised when an HTTP response could not be parsed or was unexpected."""

    _fmt = "Invalid http response for %(path)s: %(msg)s%(orig_error)s"

    def __init__(self, path, msg, orig_error=None, headers=None):
        """Initialize with the path, message, original error and headers."""
        self.path = path
        if orig_error is None:
            orig_error = ""
        else:
            orig_error = f": {orig_error!r}"
        self.headers = headers
        TransportError.__init__(self, msg, orig_error=orig_error)


class UnexpectedHttpStatus(InvalidHttpResponse):
    """Raised when an HTTP response had an unexpected status code."""

    _fmt = "Unexpected HTTP status %(code)d for %(path)s: %(extra)s"

    def __init__(self, path, code, extra=None, headers=None):
        """Initialize with the path, HTTP status code, optional extra and headers."""
        self.path = path
        self.code = code
        self.extra = extra or ""
        full_msg = "status code %d unexpected" % code
        if extra is not None:
            full_msg += ": " + extra
        InvalidHttpResponse.__init__(self, path, full_msg, headers=headers)


class InvalidHttpRange(InvalidHttpResponse):
    """Raised when an HTTP range request returned an invalid range."""

    _fmt = "Invalid http range %(range)r for %(path)s: %(msg)s"

    def __init__(self, path, range, msg):
        """Initialize with the path, requested range and message."""
        self.range = range
        InvalidHttpResponse.__init__(self, path, msg)


class HttpBoundaryMissing(InvalidHttpResponse):
    """Raised when a multipart HTTP response is missing its MIME boundary."""

    _fmt = "HTTP MIME Boundary missing for %(path)s: %(msg)s"

    def __init__(self, path, msg):
        """Initialize with the path and message."""
        InvalidHttpResponse.__init__(self, path, msg)


class BadHttpRequest(UnexpectedHttpStatus):
    """Raised when the server reported a bad HTTP request."""

    _fmt = "Bad http request for %(path)s: %(reason)s"

    def __init__(self, path, reason):
        """Initialize with the path and reason."""
        self.path = path
        self.reason = reason
        TransportError.__init__(self, reason)


class InvalidRange(TransportError):
    """Raised when a range read targets an invalid offset."""

    _fmt = "Invalid range access in %(path)s at %(offset)s: %(msg)s"

    def __init__(self, path, offset, msg=None):
        """Initialize with the path, offset and optional message."""
        TransportError.__init__(self, msg)
        self.path = path
        self.offset = offset


# Smart protocol errors
class SmartProtocolError(TransportError):
    """Generic error in the bzr smart protocol."""

    _fmt = "Generic bzr smart protocol error: %(details)s"

    def __init__(self, details):
        """Initialize with the protocol error details."""
        self.details = details
        TransportError.__init__(self)


class ErrorFromSmartServer(TransportError):
    """An error tuple was received from a smart server."""

    _fmt = "Error received from smart server: %(error_tuple)r"

    internal_error = True

    def __init__(self, error_tuple):
        """Initialize with the raw error tuple from the smart server."""
        self.error_tuple = error_tuple
        try:
            self.error_verb = error_tuple[0]
        except IndexError:
            self.error_verb = None
        self.error_args = error_tuple[1:]
        TransportError.__init__(self)


class UnexpectedSmartServerResponse(TransportError):
    """The smart server returned a response that could not be understood."""

    _fmt = "Could not understand response from smart server: %(response_tuple)r"

    def __init__(self, response_tuple):
        """Initialize with the unexpected response tuple."""
        self.response_tuple = response_tuple
        TransportError.__init__(self)


class UnknownSmartMethod(TransportError):
    """The smart server did not recognise the requested verb."""

    _fmt = "The server does not recognise the '%(verb)s' request."

    internal_error = True

    def __init__(self, verb):
        """Initialize with the unrecognised verb."""
        self.verb = verb
        TransportError.__init__(self)


# File-level locking errors raised by transport implementations.
#
# These class names are imported by the Rust extensions (see
# dromedary/_transport_rs/src/lib.rs), so they must stay at module level.
# Higher-level lock concepts (repository/branch/working-tree locks) belong
# in the consuming application (e.g. breezy.errors), which translates these
# at the boundary if it wants to surface them as its own lock errors.
class LockContention(TransportError):
    """Raised when a lock is held by another process."""

    _fmt = 'Could not acquire lock "%(lock)s": %(msg)s'

    internal_error = False

    def __init__(self, lock, msg=""):
        """Initialize with the contended lock and optional message."""
        self.lock = lock
        self.msg = msg
        TransportError.__init__(self)


class LockFailed(TransportError):
    """Raised when acquiring a lock fails for reasons other than contention."""

    internal_error = False

    _fmt = "Cannot lock %(lock)s: %(why)s"

    def __init__(self, lock, why):
        """Initialize with the lock and the reason it could not be acquired."""
        self.lock = lock
        self.why = why
        TransportError.__init__(self)


class SocketConnectionError(ConnectionError):
    """Socket connection error."""

    _fmt = "%(formatted_msg)s"

    def __init__(self, host, port=None, msg=None, orig_error=None):
        """Initialize with the host, optional port, message and originating error."""
        if msg is None:
            msg = "Failed to connect to"
        orig_error = "" if orig_error is None else "; " + str(orig_error)
        self.host = host
        port = "" if port is None else f":{port}"
        self.port = port
        self.formatted_msg = f"{msg} {host}{port}{orig_error}"
        ConnectionError.__init__(self, self.formatted_msg)


class StrangeHostname(TransportError):
    """Refusing to connect to strange SSH hostname."""

    _fmt = "Refusing to connect to strange SSH hostname %(hostname)s"

    def __init__(self, hostname):
        """Initialize with the rejected hostname."""
        self.hostname = hostname
        TransportError.__init__(self)
