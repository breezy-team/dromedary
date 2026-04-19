# Copyright (C) 2007 Canonical Ltd
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

"""Auto-detect of CA bundle for SSL connections.

The lookup logic lives in the Rust `_transport_rs.http` module; this file
re-exports a thin wrapper so that existing callers keep working.
"""

from .._transport_rs import http as _http_rs


def get_ca_path(use_cache=True):
    """Return location of CA bundle.

    Honours the ``CURL_CA_BUNDLE`` environment variable and, on Windows,
    searches the application directory and ``PATH`` for ``curl-ca-bundle.crt``.
    Returns an empty string when no bundle can be located.
    """
    return _http_rs.get_ca_path(use_cache)


def _clear_cache():
    """Clear the cached CA path (for tests)."""
    _http_rs.clear_ca_path_cache()
