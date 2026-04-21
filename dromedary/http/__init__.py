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

"""Base implementation of Transport over http.

This module is a thin facade over ``_transport_rs.http``. The User-
Agent prefix, the credential-lookup callback, CA bundle resolution
(including native-store materialisation on Windows/macOS), and the
default certificate-verification requirement all live in Rust; the
helpers here just delegate.

Breezy overrides ``ssl_ca_certs`` and ``ssl_cert_reqs`` by
reassigning the module attributes, so those stay as plain callables
at the module level rather than functions that always consult the
Rust state.
"""

DEBUG = 0

from dromedary.version import version_string as dromedary_version

from .._transport_rs import http as _http_rs

# Seed the Rust-held User-Agent prefix with our own default; breezy's
# transport layer calls set_user_agent() later to replace it.
_http_rs.set_user_agent(f"Dromedary/{dromedary_version}")


def set_user_agent(prefix):
    """Set the User-Agent prefix for HTTP requests.

    Args:
        prefix: The User-Agent string to use, e.g. "Breezy/3.4.0".
    """
    _http_rs.set_user_agent(prefix)


def default_user_agent():
    """Get the default User-Agent string for HTTP requests."""
    return _http_rs.default_user_agent()


def set_credential_lookup(func):
    """Set the function used to look up HTTP credentials.

    Args:
        func: A callable(protocol, host, port=None, path=None, realm=None)
            returning (user, password) or (None, None). Pass ``None``
            to clear any previously-registered callback.
    """
    _http_rs.set_credential_lookup(func)


def get_credential_lookup():
    """Return the currently-registered credential-lookup callable, or None."""
    return _http_rs.get_credential_lookup()


def set_negotiate_provider(func):
    """Register a Negotiate / Kerberos initial-token provider.

    The callable is invoked as ``func(host)`` and should return a
    base64-encoded GSSAPI token string to send after ``Negotiate ``
    in the Authorization header, or ``None`` if no token is
    available (no Kerberos ticket, library missing, wrong realm).
    Pass ``None`` to clear any previously-registered callback.
    """
    _http_rs.set_negotiate_provider(func)


def get_negotiate_provider():
    """Return the currently-registered Negotiate provider, or None."""
    return _http_rs.get_negotiate_provider()


def _default_kerberos_provider(host):
    """Default Negotiate provider using the Python `kerberos` module.

    Matches the behaviour of breezy's old NegotiateAuthHandler: if
    the `kerberos` module isn't installed, or the GSSAPI context
    setup fails for any reason, we return None so the auth layer
    falls back to Digest/Basic.
    """
    try:
        import kerberos
    except ModuleNotFoundError:
        return None
    ret, vc = kerberos.authGSSClientInit(f"HTTP@{host}")
    if ret < 1:
        return None
    ret = kerberos.authGSSClientStep(vc, "")
    if ret < 0:
        return None
    return kerberos.authGSSClientResponse(vc)


# Install the default provider at import time. Callers that want to
# disable Kerberos can set_negotiate_provider(None); callers that
# want to swap in an alternative (e.g. NTLM) replace it outright.
_http_rs.set_negotiate_provider(_default_kerberos_provider)


def get_credentials(protocol, host, port=None, path=None, realm=None):
    """Look up stored credentials for an HTTP connection."""
    return _http_rs.get_credentials(protocol, host, port=port, path=path, realm=realm)


# Known CA bundle locations. Exported for compatibility; the
# authoritative list lives in the Rust ``dromedary::http`` module.
_ssl_ca_certs_known_locations = list(_http_rs.SSL_CA_CERTS_KNOWN_LOCATIONS)


def default_ca_certs():
    """Get the default path to CA certificates for SSL verification.

    On Windows and macOS this returns the path to a PEM tempfile
    containing the platform's native root store (written once per
    process). On Linux it returns the first pre-installed bundle
    found in ``_ssl_ca_certs_known_locations``.
    """
    return _http_rs.default_ca_certs()


def default_cert_reqs():
    """Get the default certificate verification requirement.

    Returns an integer matching ``ssl.CERT_NONE`` (0) or
    ``ssl.CERT_REQUIRED`` (2). On Windows and macOS, returns
    ``CERT_NONE`` historically — see
    ``_transport_rs.http.default_cert_reqs`` for the rationale.
    """
    return _http_rs.default_cert_reqs()


ssl_ca_certs = default_ca_certs
ssl_cert_reqs = default_cert_reqs
