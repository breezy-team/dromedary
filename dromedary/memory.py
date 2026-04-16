# Copyright (C) 2005-2011, 2016 Canonical Ltd
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

"""Implementation of Transport that uses memory for its storage.

The contents of the transport will be lost when the object is discarded,
so this is primarily useful for testing.
"""

from dromedary import Server, register_transport, unregister_transport
from dromedary._transport_rs.memory import MemoryStoreHandle
from dromedary._transport_rs.memory import MemoryTransport as _RustMemoryTransport

__all__ = ["MemoryServer", "MemoryTransport", "get_test_permutations"]


class MemoryTransport(_RustMemoryTransport):
    """This is an in memory file system for transient data storage."""


class MemoryServer(Server):
    """Server for the MemoryTransport for testing with."""

    def start_server(self):
        """Start the memory server by initializing storage and registering transport."""
        self._store = MemoryStoreHandle()
        self._scheme = f"memory+{id(self)}:///"

        def memory_factory(url):
            return MemoryTransport(url, _shared_store=self._store)

        self._memory_factory = memory_factory
        register_transport(self._scheme, self._memory_factory)

    def stop_server(self):
        """Stop the server and unregister the transport."""
        unregister_transport(self._scheme, self._memory_factory)

    def get_url(self):
        """See dromedary.Server.get_url."""
        return self._scheme

    def get_bogus_url(self):
        """Get a URL for a non-existent location.

        Raises:
            NotImplementedError: This method is not implemented for memory transport.
        """
        raise NotImplementedError


def get_test_permutations():
    """Return the permutations to be used in testing."""
    return [
        (MemoryTransport, MemoryServer),
    ]
