# Copyright (C) 2007 Canonical Ltd
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

"""Implementation of Transport that traces transport operations.

This does not change the transport behaviour at all, merely records every call
and then delegates it.
"""

import os
from collections.abc import Iterator
from typing import IO, TYPE_CHECKING

from dromedary import Transport, decorator

if TYPE_CHECKING:
    from dromedary import FileStream, Lock


class TransportTraceDecorator(decorator.TransportDecorator):
    """A tracing decorator for Transports.

    Calls that potentially perform IO are logged to self._activity. The
    _activity attribute is shared as the transport is cloned, but not if a new
    transport is created without cloning.

    Not all operations are logged at this point, if you need an unlogged
    operation please add a test to the tests of this transport, for the logging
    of the operation you want logged.

    See also TransportLogDecorator, that records a machine-readable log in
    memory for eg testing.
    """

    def __init__(
        self,
        url: str,
        _decorated: Transport | None = None,
        _from_transport: "TransportTraceDecorator | None" = None,
    ) -> None:
        """Set the 'base' path where files will be stored.

        _decorated is a private parameter for cloning.
        """
        super().__init__(url, _decorated)
        if _from_transport is None:
            # newly created
            self._activity: list[tuple] = []
        else:
            # cloned
            self._activity = _from_transport._activity

    def append_file(self, relpath: str, f: IO[bytes], mode: int | None = None) -> int:
        """See Transport.append_file()."""
        return self._decorated.append_file(relpath, f, mode=mode)

    def append_bytes(self, relpath: str, bytes: bytes, mode: int | None = None) -> int:
        """See Transport.append_bytes()."""
        return self._decorated.append_bytes(relpath, bytes, mode=mode)

    def delete(self, relpath: str) -> None:
        """See Transport.delete()."""
        self._activity.append(("delete", relpath))
        return self._decorated.delete(relpath)

    def delete_tree(self, relpath: str) -> None:
        """See Transport.delete_tree()."""
        return self._decorated.delete_tree(relpath)

    @classmethod
    def _get_url_prefix(cls) -> str:
        """Tracing transports are identified by 'trace+'."""
        return "trace+"

    def get(self, relpath: str) -> IO[bytes]:
        """See Transport.get()."""
        self._trace(("get", relpath))
        return self._decorated.get(relpath)

    def has(self, relpath: str) -> bool:
        """See Transport.has()."""
        return self._decorated.has(relpath)

    def is_readonly(self) -> bool:
        """See Transport.is_readonly."""
        return self._decorated.is_readonly()

    def mkdir(self, relpath: str, mode: int | None = None) -> None:
        """See Transport.mkdir()."""
        self._trace(("mkdir", relpath, mode))
        return self._decorated.mkdir(relpath, mode)

    def open_write_stream(self, relpath: str, mode: int | None = None) -> "FileStream":
        """See Transport.open_write_stream."""
        return self._decorated.open_write_stream(relpath, mode=mode)

    def put_file(self, relpath: str, f: IO[bytes], mode: int | None = None) -> int:
        """See Transport.put_file()."""
        return self._decorated.put_file(relpath, f, mode)

    def put_bytes(self, relpath: str, raw_bytes: bytes, mode: int | None = None) -> int:
        """See Transport.put_bytes()."""
        self._trace(("put_bytes", relpath, len(raw_bytes), mode))
        return self._decorated.put_bytes(relpath, raw_bytes, mode)

    def put_bytes_non_atomic(
        self,
        relpath: str,
        raw_bytes: bytes,
        mode: int | None = None,
        create_parent_dir: bool = False,
        dir_mode: int | None = None,
    ) -> None:
        """See Transport.put_bytes_non_atomic."""
        self._trace(
            (
                "put_bytes_non_atomic",
                relpath,
                len(raw_bytes),
                mode,
                create_parent_dir,
                dir_mode,
            )
        )
        return self._decorated.put_bytes_non_atomic(
            relpath,
            raw_bytes,
            mode=mode,
            create_parent_dir=create_parent_dir,
            dir_mode=dir_mode,
        )

    def listable(self) -> bool:
        """See Transport.listable."""
        return self._decorated.listable()

    def iter_files_recursive(self) -> Iterator[str]:
        """See Transport.iter_files_recursive()."""
        return self._decorated.iter_files_recursive()

    def list_dir(self, relpath: str) -> list[str]:
        """See Transport.list_dir()."""
        return self._decorated.list_dir(relpath)

    def readv(
        self,
        relpath: str,
        offsets: list[tuple[int, int]],
        adjust_for_latency: bool = False,
        upper_limit: int | None = None,
    ) -> Iterator[tuple[int, bytes]]:
        """Read multiple ranges from a file."""
        # we override at the readv() level rather than _readv() so that any
        # latency adjustments will be done by the underlying transport
        self._trace(("readv", relpath, offsets, adjust_for_latency, upper_limit))
        return self._decorated.readv(relpath, offsets, adjust_for_latency, upper_limit)

    def recommended_page_size(self) -> int:
        """See Transport.recommended_page_size()."""
        return self._decorated.recommended_page_size()

    def rename(self, rel_from: str, rel_to: str) -> None:
        """See Transport.rename."""
        self._activity.append(("rename", rel_from, rel_to))
        return self._decorated.rename(rel_from, rel_to)

    def rmdir(self, relpath: str) -> None:
        """See Transport.rmdir."""
        self._trace(("rmdir", relpath))
        return self._decorated.rmdir(relpath)

    def stat(self, relpath: str) -> os.stat_result:
        """See Transport.stat()."""
        return self._decorated.stat(relpath)

    def lock_read(self, relpath: str) -> "Lock":
        """See Transport.lock_read."""
        return self._decorated.lock_read(relpath)

    def lock_write(self, relpath: str) -> "Lock":
        """See Transport.lock_write."""
        return self._decorated.lock_write(relpath)

    def _trace(self, operation_tuple: tuple) -> None:
        """Record that a transport operation occurred."""
        self._activity.append(operation_tuple)


def get_test_permutations() -> list[tuple[type, type]]:
    """Return the permutations to be used in testing."""
    from dromedary.tests import test_server

    return [(TransportTraceDecorator, test_server.TraceServer)]
