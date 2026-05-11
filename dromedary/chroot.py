# Copyright (C) 2006-2010 Canonical Ltd
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

"""Implementation of Transport that prevents access to locations above a set
root.
"""

from typing import TYPE_CHECKING

from dromedary import pathfilter, register_transport
from dromedary._transport_rs.pathfilter import ChrootTransport

if TYPE_CHECKING:
    from dromedary import Transport

__all__ = ["ChrootServer", "ChrootTransport", "get_test_permutations"]


class ChrootServer(pathfilter.PathFilteringServer):
    """User space 'chroot' facility.

    PathFilteringServer does all the path sanitation needed to enforce a
    chroot, so this is a simple subclass of PathFilteringServer that ignores
    filter_func.
    """

    def __init__(self, backing_transport: "Transport") -> None:
        """Initialize the ChrootServer."""
        pathfilter.PathFilteringServer.__init__(self, backing_transport, None)

    def _factory(self, url: str) -> ChrootTransport:
        return ChrootTransport(self, url)

    def start_server(self) -> None:
        """Start the chroot server and register its transport."""
        self.scheme = "chroot-%d:///" % id(self)
        register_transport(self.scheme, self._factory)


def get_test_permutations() -> list[tuple[type, type]]:
    """Return the permutations to be used in testing."""
    from dromedary.tests import test_server

    return [(ChrootTransport, test_server.TestingChrootServer)]
