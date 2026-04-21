# Copyright (C) 2006-2011 Robey Pointer <robey@lag.net>
# Copyright (C) 2005, 2006, 2007 Canonical Ltd
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

"""Foundation SSH support for SFTP and smart server."""

import errno
import logging
import os
import socket
from binascii import hexlify

from catalogus import registry

from dromedary import _bedding as bedding
from dromedary import _config, _ui, errors
from dromedary.errors import SocketConnectionError
from dromedary.osutils import pathjoin

from .._transport_rs import sftp as _sftp_rs
from .._transport_rs import ssh as _ssh_rs

logger = logging.getLogger("dromedary.ssh")

SFTPClient = _sftp_rs.SFTPClient

try:
    import paramiko
except ModuleNotFoundError:
    # If we have an ssh subprocess, we don't strictly need paramiko for all ssh
    # access
    paramiko = None  # type: ignore


class SSHVendorNotFound(errors.TransportError):
    """No SSH implementation available."""

    _fmt = (
        "Don't know how to handle SSH connections."
        " Please set BRZ_SSH environment variable."
    )


class UnknownSSH(errors.TransportError):
    """Unknown SSH implementation specified."""

    _fmt = "Unrecognised value for BRZ_SSH environment variable: %(vendor)s"

    def __init__(self, vendor):
        """Initialize with the unrecognised vendor name."""
        self.vendor = vendor
        errors.TransportError.__init__(self)


class SSHVendorManager(registry.Registry[str, "SSHVendor", None]):
    """Manager for manage SSH vendors."""

    def __init__(self):
        """Initialize the SSH vendor manager.

        Sets up the registry and initializes the vendor cache.
        """
        super().__init__()
        self._cached_ssh_vendor = None

    def clear_cache(self):
        """Clear previously cached lookup result."""
        self._cached_ssh_vendor = None

    def _get_vendor_by_config(self):
        """Get SSH vendor based on configuration.

        Looks up the SSH vendor from the global configuration. If a vendor
        name is specified but not registered, attempts to use it as an
        executable path.

        Returns:
            SSHVendor: The configured SSH vendor, or None if not configured.

        Raises:
            UnknownSSH: If the configured vendor name is not found and cannot
                be used as an executable path.
        """
        vendor_name = _config.get_ssh_vendor_name()
        if vendor_name is not None:
            try:
                vendor = self.get(vendor_name)
            except KeyError as err:
                vendor = self._get_vendor_from_path(vendor_name)
                if vendor is None:
                    raise UnknownSSH(vendor_name) from err
                vendor.executable_path = vendor_name
            return vendor
        return None

    def _get_vendor_by_inspection(self):
        """Return the vendor or None by checking for known SSH implementations.

        Runs 'ssh -V' to determine the SSH implementation in use. Detection
        runs in Rust; this just maps the returned registry key back to a
        vendor instance.

        Returns:
            SSHVendor: The detected vendor, or None if not recognized.
        """
        key = _ssh_rs.detect_ssh_vendor("ssh")
        if key is None:
            return None
        logger.debug("ssh implementation detected as %s", key)
        return self.get(key)

    def _get_vendor_from_path(self, path):
        """Return the vendor or None using the program at the given path.

        Runs the specified executable with '-V' to determine its type.

        Args:
            path: Path to the SSH executable.

        Returns:
            SSHVendor: The detected vendor, or None if not recognized.
        """
        key = _ssh_rs.detect_ssh_vendor(path)
        if key is None:
            return None
        logger.debug("ssh implementation at %s detected as %s", path, key)
        return self.get(key)

    def get_vendor(self):
        """Find out what version of SSH is on the system.

        :raises SSHVendorNotFound: if no any SSH vendor is found
        :raises UnknownSSH: if the BRZ_SSH environment variable contains
                            unknown vendor name
        """
        if self._cached_ssh_vendor is None:
            vendor = self._get_vendor_by_config()
            if vendor is None:
                vendor = self._get_vendor_by_inspection()
                if vendor is None:
                    logger.debug("falling back to default implementation")
                    if self.default_key is None:
                        raise SSHVendorNotFound()
                    vendor = self.get()
            self._cached_ssh_vendor = vendor
        return self._cached_ssh_vendor


_ssh_vendor_manager = SSHVendorManager()
_get_ssh_vendor = _ssh_vendor_manager.get_vendor
register_ssh_vendor = _ssh_vendor_manager.register
register_lazy_ssh_vendor = _ssh_vendor_manager.register_lazy


class SocketAsChannelAdapter:
    """Simple wrapper for a socket that pretends to be a paramiko Channel."""

    def __init__(self, sock):
        """Initialize the adapter with a socket.

        Args:
            sock: A socket object to wrap.
        """
        self.__socket = sock

    def get_name(self):
        """Get the name of this channel adapter.

        Returns:
            str: A descriptive name for this adapter.
        """
        return "bzr SocketAsChannelAdapter"

    def send(self, data):
        """Send data through the socket.

        Args:
            data: Bytes to send.

        Returns:
            int: Number of bytes sent.
        """
        return self.__socket.send(data)

    def recv(self, n):
        """Receive data from the socket.

        Args:
            n: Maximum number of bytes to receive.

        Returns:
            bytes: Data received from the socket, or empty string if the
                connection is closed.

        Note:
            Returns empty string instead of raising an exception when the
            connection is closed, to match paramiko's expected behavior.
        """
        try:
            return self.__socket.recv(n)
        except OSError as e:
            if e.args[0] in (
                errno.EPIPE,
                errno.ECONNRESET,
                errno.ECONNABORTED,
                errno.EBADF,
            ):
                # Connection has closed.  Paramiko expects an empty string in
                # this case, not an exception.
                return ""
            raise

    def recv_ready(self):
        """Check if data is available for reading.

        Returns:
            bool: Always returns True. Should ideally use poll() or select()
                to check for actual data availability.

        Note:
            This is a simplified implementation that always returns True.
            A proper implementation would check if data is actually available.
        """
        # TODO: jam 20051215 this function is necessary to support the
        # pipelined() function. In reality, it probably should use
        # poll() or select() to actually return if there is data
        # available, otherwise we probably don't get any benefit
        return True

    def close(self):
        """Close the underlying socket."""
        self.__socket.close()


class SSHVendor:
    """Abstract base class for SSH vendor implementations."""

    def connect_sftp(self, username, password, host, port):
        """Make an SSH connection, and return an SFTPClient.

        :param username: an ascii string
        :param password: an ascii string
        :param host: a host name as an ascii string
        :param port: a port number
        :type port: int

        :raises: ConnectionError if it cannot connect.

        :rtype: paramiko.sftp_client.SFTPClient
        """
        raise NotImplementedError(self.connect_sftp)

    def connect_ssh(self, username, password, host, port, command):
        """Make an SSH connection.

        :returns: an SSHConnection.
        """
        raise NotImplementedError(self.connect_ssh)

    def _raise_connection_error(
        self, host, port=None, orig_error=None, msg="Unable to connect to SSH host"
    ):
        """Raise a SocketConnectionError with properly formatted host.

        This just unifies all the locations that try to raise ConnectionError,
        so that they format things properly.

        Args:
            host: The hostname that failed to connect.
            port: The port number (optional).
            orig_error: The original exception that caused the connection failure.
            msg: Custom error message.

        Raises:
            SocketConnectionError: Always raises this error with the provided details.
        """
        raise SocketConnectionError(
            host=host, port=port, msg=msg, orig_error=orig_error
        )


class LoopbackVendor(SSHVendor):
    """SSH "vendor" that connects over a plain TCP socket, not SSH."""

    def connect_sftp(self, username, password, host, port):
        """Connect to an SFTP server using a plain TCP socket.

        This is a loopback implementation that bypasses SSH and connects
        directly via TCP. Useful for testing or local connections.

        Args:
            username: SSH username (ignored in loopback).
            password: SSH password (ignored in loopback).
            host: Hostname to connect to.
            port: Port number to connect to.

        Returns:
            SFTPClient: An SFTP client connected via TCP socket.

        Raises:
            SocketConnectionError: If connection fails.
        """
        sock = socket.socket()
        try:
            sock.connect((host, port))
        except OSError as e:
            self._raise_connection_error(host, port=port, orig_error=e)
        return SFTPClient(sock.detach())


register_ssh_vendor("loopback", LoopbackVendor())


# Rust-backed vendors. Registered lazily so the extension module is only
# imported when one of these vendors is actually selected.
register_lazy_ssh_vendor("russh", "dromedary.ssh.russh", "russh_vendor")
register_lazy_ssh_vendor("openssh", "dromedary.ssh.subprocess_rs", "openssh_vendor")
register_lazy_ssh_vendor("lsh", "dromedary.ssh.subprocess_rs", "lsh_vendor")
register_lazy_ssh_vendor("plink", "dromedary.ssh.subprocess_rs", "plink_vendor")
_ssh_vendor_manager.default_key = "russh"

if paramiko is not None:
    register_lazy_ssh_vendor("paramiko", "dromedary.ssh.paramiko", "paramiko_vendor")
    register_lazy_ssh_vendor("none", "dromedary.ssh.paramiko", "paramiko_vendor")


def _paramiko_auth(username, password, host, port, paramiko_transport):
    # paramiko requires a username, but it might be none if nothing was
    # supplied.  If so, use the local username.
    if username is None:
        username = _config.get_auth_user("ssh", host, port=port)
    agent = paramiko.Agent()
    for key in agent.get_keys():
        logger.debug("Trying SSH agent key %s", hexlify(key.get_fingerprint()).upper())
        try:
            paramiko_transport.auth_publickey(username, key)
            return
        except paramiko.SSHException:
            pass

    # okay, try finding id_rsa or id_dss?  (posix only)
    if _try_pkey_auth(paramiko_transport, paramiko.RSAKey, username, "id_rsa"):
        return
    # DSSKey was removed in paramiko 4.0.0 as DSA keys are deprecated
    if hasattr(paramiko, "DSSKey"):
        if _try_pkey_auth(paramiko_transport, paramiko.DSSKey, username, "id_dsa"):
            return

    # If we have gotten this far, we are about to try for passwords, do an
    # auth_none check to see if it is even supported.
    supported_auth_types = []
    try:
        # Note that with paramiko <1.7.5 this logs an INFO message:
        #    Authentication type (none) not permitted.
        # So we explicitly disable the logging level for this action
        old_level = paramiko_transport.logger.level
        paramiko_transport.logger.setLevel(logging.WARNING)
        try:
            paramiko_transport.auth_none(username)
        finally:
            paramiko_transport.logger.setLevel(old_level)
    except paramiko.BadAuthenticationType as e:
        # Supported methods are in the exception
        supported_auth_types = e.allowed_types
    except paramiko.SSHException:
        # Don't know what happened, but just ignore it
        pass
    # We treat 'keyboard-interactive' and 'password' auth methods identically,
    # because Paramiko's auth_password method will automatically try
    # 'keyboard-interactive' auth (using the password as the response) if
    # 'password' auth is not available.  Apparently some Debian and Gentoo
    # OpenSSH servers require this.
    # XXX: It's possible for a server to require keyboard-interactive auth that
    # requires something other than a single password, but we currently don't
    # support that.
    if (
        "password" not in supported_auth_types
        and "keyboard-interactive" not in supported_auth_types
    ):
        raise errors.ConnectionError(
            "Unable to authenticate to SSH host as"
            "\n  {}@{}\nsupported auth types: {}".format(
                username, host, supported_auth_types
            )
        )

    if password:
        try:
            paramiko_transport.auth_password(username, password)
            return
        except paramiko.SSHException:
            pass

    # give up and ask for a password
    password = _config.get_auth_password("ssh", host, username, port=port)
    # get_password can still return None, which means we should not prompt
    if password is not None:
        try:
            paramiko_transport.auth_password(username, password)
        except paramiko.SSHException as e:
            raise errors.ConnectionError(
                "Unable to authenticate to SSH host as\n  {}@{}\n".format(
                    username, host
                ),
                e,
            ) from e
    else:
        raise errors.ConnectionError(
            "Unable to authenticate to SSH host as  {}@{}".format(username, host)
        )


def _try_pkey_auth(paramiko_transport, pkey_class, username, filename):
    filename = os.path.expanduser("~/.ssh/" + filename)
    try:
        key = pkey_class.from_private_key_file(filename)
        paramiko_transport.auth_publickey(username, key)
        return True
    except paramiko.PasswordRequiredException:
        password = _ui.get_password(
            "SSH %(filename)s password", filename=os.fsdecode(filename)
        )
        try:
            key = pkey_class.from_private_key_file(filename, password)
            paramiko_transport.auth_publickey(username, key)
            return True
        except paramiko.SSHException:
            logger.debug(
                "SSH authentication via %s key failed.",
                os.path.basename(filename),
            )
    except paramiko.SSHException:
        logger.debug(
            "SSH authentication via %s key failed.", os.path.basename(filename)
        )
    except OSError:
        pass
    return False


def _ssh_host_keys_config_dir():
    return pathjoin(bedding.config_dir(), "ssh_host_keys")


def load_host_keys():
    """Load system host keys (probably doesn't work on windows) and any
    "discovered" keys from previous sessions.
    """
    global SYSTEM_HOSTKEYS, BRZ_HOSTKEYS
    try:
        SYSTEM_HOSTKEYS = paramiko.util.load_host_keys(
            os.path.expanduser("~/.ssh/known_hosts")
        )
    except OSError as e:
        logger.debug("failed to load system host keys: %s", e)
    brz_hostkey_path = _ssh_host_keys_config_dir()
    try:
        BRZ_HOSTKEYS = paramiko.util.load_host_keys(brz_hostkey_path)
    except OSError as e:
        logger.debug("failed to load brz host keys: %s", e)
        save_host_keys()


def save_host_keys():
    """Save "discovered" host keys in $(config)/ssh_host_keys/."""
    global SYSTEM_HOSTKEYS, BRZ_HOSTKEYS
    bzr_hostkey_path = _ssh_host_keys_config_dir()
    bedding.ensure_config_dir_exists()

    try:
        with open(bzr_hostkey_path, "w") as f:
            f.write("# SSH host keys collected by bzr\n")
            for hostname, keys in BRZ_HOSTKEYS.items():
                for keytype, key in keys.items():
                    f.write("{} {} {}\n".format(hostname, keytype, key.get_base64()))
    except OSError as e:
        logger.debug("failed to save bzr host keys: %s", e)


class SSHConnection:
    """Abstract base class for SSH connections."""

    def get_sock_or_pipes(self):
        """Returns a (kind, io_object) pair.

        If kind == 'socket', then io_object is a socket.

        If kind == 'pipes', then io_object is a pair of file-like objects
        (read_from, write_to).

        Returns:
            tuple: A (kind, io_object) pair where:
                - kind is either 'socket' or 'pipes'
                - io_object is either a socket or (read_file, write_file) tuple
        """
        raise NotImplementedError(self.get_sock_or_pipes)

    def close(self):
        """Close the SSH connection.

        Subclasses must implement this method to properly close their
        connection type.
        """
        raise NotImplementedError(self.close)
