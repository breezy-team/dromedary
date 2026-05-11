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

"""UI integration points for dromedary.

Embedders should replace these functions to integrate with their UI.
The defaults provide basic functionality using the standard library.
"""

from typing import Literal


def report_transport_activity(transport: object, byte_count: int, direction: Literal["read", "write"]) -> None:
    """Called during transport I/O to report activity. Default: no-op."""
    pass


def get_password(prompt: str = "", **kwargs: object) -> str:
    """Prompt for a password. Default: uses getpass."""
    import getpass

    if kwargs:
        prompt = prompt % kwargs
    return getpass.getpass(prompt)


def get_username(prompt: str, **kwargs: object) -> str:
    """Prompt for a username. Default: uses input()."""
    if kwargs:
        prompt = prompt % kwargs
    return input(prompt)


def show_message(msg: str) -> None:
    """Show a message to the user. Default: print to stderr."""
    import sys

    print(msg, file=sys.stderr)
