# Copyright (C) 2010 Canonical Ltd.
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
#
# Author: Mattias Eriksson

"""Implementation of Transport over gio.

It provides the gio+XXX:// protocols where XXX is any of the protocols
supported by gio (file, sftp, smb, dav, ftp, ssh, obex).

The transport is implemented in Rust against the gtk-rs `gio` crate,
gated behind a non-default `gio` Cargo feature. When dromedary is built
without that feature, importing this module raises DependencyNotPresent
to match the historical behaviour when the legacy Python `gio` module
was missing.
"""

from dromedary import urlutils
from dromedary.errors import DependencyNotPresent
from dromedary.tests.test_server import TestServer

try:
    from dromedary._transport_rs.gio import GioTransport
except ImportError as e:
    raise DependencyNotPresent("gio", e) from e

__all__ = ["GioLocalURLServer", "GioTransport", "get_test_permutations"]


class GioLocalURLServer(TestServer):
    """A pretend server for local transports, using gio+file:// urls.

    Of course no actual server is required to access the local filesystem, so
    this just exists to tell the test code how to get to it.
    """

    def start_server(self):
        """Start the server (no-op for local filesystem access)."""
        pass

    def get_url(self):
        """See Transport.Server.get_url."""
        return "gio+" + urlutils.local_path_to_url("")


def get_test_permutations():
    """Return the permutations to be used in testing."""
    return [(GioTransport, GioLocalURLServer)]
