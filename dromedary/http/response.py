# Copyright (C) 2006-2011 Canonical Ltd
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

"""Handlers for HTTP Responses.

Thin re-export shim over the Rust implementation in
``_transport_rs.http`` which owns the real ``ResponseFile`` /
``RangeFile`` / ``handle_response`` logic. Keeping this module around
lets ``from dromedary.http.response import ...`` continue to work for
anyone still importing by the old path (urllib.py, breezy tests).
"""

from dromedary._transport_rs.http import (
    RangeFile,
    ResponseFile,
    handle_response,
)

__all__ = ["RangeFile", "ResponseFile", "handle_response"]
