# Copyright (C) 2006-2009, 2011, 2012 Canonical Ltd
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

"""An http transport implementing WebDAV on top of dromedary's HTTP transport.

This package exposes :class:`HttpDavTransport`, a subclass of
:class:`dromedary.http.urllib.HttpTransport` that implements the subset of
WebDAV (RFC 4918) needed to support writes over HTTP. It intentionally does
not register the ``http+webdav://`` / ``https+webdav://`` schemes itself —
callers that want those schemes wired up should do the registration
themselves (e.g. breezy registers them pointing at its own subclass that
adds a smart-server medium).
"""

from dromedary.webdav.webdav import HttpDavTransport

__all__ = ["HttpDavTransport"]
