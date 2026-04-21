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

"""Rust-backed subprocess SSH vendors (OpenSSH, LSH, PLink).

Thin Python adapters over `dromedary._transport_rs.ssh.{OpenSSH,LSH,
PLink}SubprocessVendor`, registered alongside the existing pure-Python
subprocess vendors. Selecting any of them is opt-in via `BRZ_SSH=openssh-rs`
(etc.) until step 8 removes the Python implementations.
"""

from dromedary.ssh import SFTPClient, SSHConnection, SSHVendor

from .._transport_rs import ssh as _ssh_rs


class _RustSubprocessSSHConnection(SSHConnection):
    """SSHConnection wrapping a Rust `SSHSubprocessConnection`."""

    def __init__(self, inner):
        self._inner = inner

    def close(self):
        return self._inner.close()


class _RustSubprocessVendor(SSHVendor):
    """Shared adapter logic for the three Rust subprocess vendors."""

    def __init__(self, rust_vendor):
        self._vendor = rust_vendor

    def connect_sftp(self, username, password, host, port):
        fd = self._vendor.spawn_sftp(username, host, port)
        return SFTPClient(fd)

    def connect_ssh(self, username, password, host, port, command):
        inner = self._vendor.connect_ssh(username, host, command, port)
        return _RustSubprocessSSHConnection(inner)


openssh_vendor = _RustSubprocessVendor(_ssh_rs.OpenSSHSubprocessVendor())
lsh_vendor = _RustSubprocessVendor(_ssh_rs.LSHSubprocessVendor())
plink_vendor = _RustSubprocessVendor(_ssh_rs.PLinkSubprocessVendor())
