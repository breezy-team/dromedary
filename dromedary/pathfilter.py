# Copyright (C) 2009, 2010 Canonical Ltd
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

"""A transport decorator that filters all paths that are passed to it."""

from dromedary import Server, register_transport, unregister_transport
from dromedary._transport_rs.pathfilter import PathFilteringTransport

__all__ = [
    "PathFilteringServer",
    "PathFilteringTransport",
    "get_test_permutations",
]


class PathFilteringServer(Server):
    """Transport server for PathFilteringTransport.

    It holds the backing_transport and filter_func for PathFilteringTransports.
    All paths will be passed through filter_func before calling into the
    backing_transport.
    """

    def __init__(self, backing_transport, filter_func):
        """Constructor.

        :param backing_transport: a transport
        :param filter_func: a callable that takes paths, and translates them
            into paths for use with the backing transport.
        """
        self.backing_transport = backing_transport
        self.filter_func = filter_func

    def _factory(self, url):
        return PathFilteringTransport(self, url)

    def get_url(self):
        """Return the URL scheme for this server."""
        return self.scheme

    def start_server(self):
        """Start the path filtering transport server."""
        self.scheme = "filtered-%d:///" % id(self)
        register_transport(self.scheme, self._factory)

    def stop_server(self):
        """Stop the path filtering transport server."""
        unregister_transport(self.scheme, self._factory)


def get_test_permutations():
    """Return the permutations to be used in testing."""
    from dromedary.tests import test_server

    return [(PathFilteringTransport, test_server.TestingPathFilteringServer)]
