# Copyright (C) 2006, 2007, 2009, 2010, 2011, 2016 Canonical Ltd
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

"""Implementation of Transport that adapts another transport to be readonly."""

from dromedary._transport_rs.readonly import ReadonlyTransportDecorator

__all__ = ["ReadonlyTransportDecorator", "get_test_permutations"]


def get_test_permutations():
    """Return the permutations to be used in testing."""
    from dromedary.tests import test_server

    return [(ReadonlyTransportDecorator, test_server.ReadonlyServer)]
