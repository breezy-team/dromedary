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

There are separate implementation modules for each http client implementation.
"""

DEBUG = 0

import sys

from dromedary.version import version_string as dromedary_version

from .._transport_rs import http as _http_rs

_user_agent_prefix = f"Dromedary/{dromedary_version}"


def set_user_agent(prefix):
    """Set the User-Agent prefix for HTTP requests.

    Args:
        prefix: The User-Agent string to use, e.g. "Breezy/3.4.0".
    """
    global _user_agent_prefix
    _user_agent_prefix = prefix


def _default_credential_lookup(protocol, host, port=None, path=None, realm=None):
    """Default credential lookup returning no credentials.

    Override via set_credential_lookup() to integrate with a credential store.

    Returns:
        tuple: (user, password) or (None, None) if no credentials found.
    """
    return None, None


_credential_lookup = _default_credential_lookup


def set_credential_lookup(func):
    """Set the function used to look up HTTP credentials.

    Args:
        func: A callable(protocol, host, port=None, path=None, realm=None)
            returning (user, password) or (None, None).
    """
    global _credential_lookup
    _credential_lookup = func


def get_credentials(protocol, host, port=None, path=None, realm=None):
    """Look up stored credentials for an HTTP connection."""
    return _credential_lookup(protocol, host, port=port, path=path, realm=realm)


def default_user_agent():
    """Get the default User-Agent string for HTTP requests."""
    return _user_agent_prefix


# Known CA bundle locations. Exported for compatibility; the authoritative
# list lives in the Rust `dromedary::http` module.
_ssl_ca_certs_known_locations = list(_http_rs.SSL_CA_CERTS_KNOWN_LOCATIONS)


def default_ca_certs():
    """Get the default path to CA certificates for SSL verification."""
    return _http_rs.default_ca_certs()


def default_cert_reqs():
    """Get the default certificate verification requirement for the platform.

    On Windows and macOS, returns ssl.CERT_NONE due to lack of native access
    to root certificates. On other platforms, returns ssl.CERT_REQUIRED.
    """
    import ssl

    if sys.platform in ("win32", "darwin"):
        # FIXME: Once we get a native access to root certificates there, this
        # won't needed anymore. See http://pad.lv/920455 -- vila 2012-02-15
        return ssl.CERT_NONE
    else:
        return ssl.CERT_REQUIRED


ssl_ca_certs = default_ca_certs
ssl_cert_reqs = default_cert_reqs
