# Copyright (C) 2026 Jelmer Vernooĳ
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

"""Pure-Rust SSH vendor backed by russh.

Thin Python adapter over `dromedary._transport_rs.ssh.RusshVendor`, so it
plugs into the existing `SSHVendor` registry alongside the paramiko and
subprocess vendors. Once the migration is complete this module is what
`default_key` points at.
"""

from dromedary.ssh import SSHConnection, SSHVendor

from .._transport_rs import ssh as _ssh_rs


class _RusshSSHConnection(SSHConnection):
    """SSHConnection wrapping a `RusshSSHConnection` from the Rust layer."""

    def __init__(self, inner):
        self._inner = inner

    def send(self, data):
        return self._inner.send(data)

    def recv(self, count):
        return self._inner.recv(count)

    def close(self):
        return self._inner.close()


class RusshVendor(SSHVendor):
    """SSH vendor using the pure-Rust russh library."""

    def __init__(self):
        """Construct a russh-backed SSH vendor."""
        self._vendor = _ssh_rs.RusshVendor()

    def connect_sftp(self, username, password, host, port):
        """Open an SFTP session; returns an `_transport_rs.sftp.SFTPClient`."""
        return self._vendor.connect_sftp(username, password, host, port)

    def connect_ssh(self, username, password, host, port, command):
        """Execute `command` on the remote host over SSH."""
        inner = self._vendor.connect_ssh(username, password, host, command, port)
        return _RusshSSHConnection(inner)


russh_vendor = RusshVendor()
