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

"""Implementation of Transport that decorates another transport.

This does not change the transport behaviour at all, but provides all the
stub functions to allow other decorators to be written easily.
"""

from collections.abc import Iterator
from typing import IO, TYPE_CHECKING

from dromedary import (
    Transport,
    get_transport_from_path,
    get_transport_from_url,
    urlutils,
)

if TYPE_CHECKING:
    import os

    from dromedary import FileStream, Lock


class TransportDecorator(Transport):
    """A no-change decorator for Transports.

    Subclasses of this are new transports that are based on an
    underlying transport and can override or intercept some
    behavior.  For example ReadonlyTransportDecorator prevents
    all write attempts, and FakeNFSTransportDecorator simulates
    some NFS quirks.

    This decorator class is not directly usable as a decorator:
    you must use a subclass which has overridden the _get_url_prefix() class
    method to return the url prefix for the subclass.
    """

    def __init__(
        self,
        url: str,
        _decorated: Transport | None = None,
        _from_transport: "TransportDecorator | None" = None,
    ) -> None:
        """Set the 'base' path of the transport.

        :param _decorated: A private parameter for cloning.
        :param _from_transport: Is available for subclasses that
            need to share state across clones.
        """
        prefix = self._get_url_prefix()
        if not url.startswith(prefix):
            raise ValueError(
                f"url {url!r} doesn't start with decorator prefix {prefix!r}"
            )
        not_decorated_url = url[len(prefix) :]
        if _decorated is None:
            if urlutils.is_url(not_decorated_url):
                self._decorated = get_transport_from_url(not_decorated_url)
            else:
                self._decorated = get_transport_from_path(not_decorated_url)
        else:
            self._decorated = _decorated
        super().__init__(prefix + self._decorated.base)

    def abspath(self, relpath: str) -> str:
        """See Transport.abspath()."""
        return self._get_url_prefix() + self._decorated.abspath(relpath)

    def append_file(self, relpath: str, f: IO[bytes], mode: int | None = None) -> int:
        """See Transport.append_file()."""
        return self._decorated.append_file(relpath, f, mode=mode)

    def append_bytes(self, relpath: str, bytes: bytes, mode: int | None = None) -> int:
        """See Transport.append_bytes()."""
        return self._decorated.append_bytes(relpath, bytes, mode=mode)

    def _can_roundtrip_unix_modebits(self) -> bool:
        """See Transport._can_roundtrip_unix_modebits()."""
        return self._decorated._can_roundtrip_unix_modebits()

    def clone(self, offset: str | None = None) -> "TransportDecorator":
        """See Transport.clone()."""
        decorated_clone = self._decorated.clone(offset)
        return self.__class__(
            self._get_url_prefix() + decorated_clone.base, decorated_clone, self
        )

    def delete(self, relpath: str) -> None:
        """See Transport.delete()."""
        return self._decorated.delete(relpath)

    def delete_tree(self, relpath: str) -> None:
        """See Transport.delete_tree()."""
        return self._decorated.delete_tree(relpath)

    def external_url(self) -> str:
        """See dromedary.Transport.external_url."""
        # while decorators are in-process only, they
        # can be handed back into breezy safely, so
        # its just the base.
        return self.base

    @classmethod
    def _get_url_prefix(cls) -> str:
        """Return the URL prefix of this decorator."""
        raise NotImplementedError(cls._get_url_prefix)

    def get(self, relpath: str) -> IO[bytes]:
        """See Transport.get()."""
        return self._decorated.get(relpath)

    def has(self, relpath: str) -> bool:
        """See Transport.has()."""
        return self._decorated.has(relpath)

    def is_readonly(self) -> bool:
        """See Transport.is_readonly."""
        return self._decorated.is_readonly()

    def mkdir(self, relpath: str, mode: int | None = None) -> None:
        """See Transport.mkdir()."""
        return self._decorated.mkdir(relpath, mode)

    def open_write_stream(self, relpath: str, mode: int | None = None) -> "FileStream":
        """See Transport.open_write_stream."""
        return self._decorated.open_write_stream(relpath, mode=mode)

    def put_file(self, relpath: str, f: IO[bytes], mode: int | None = None) -> int:
        """See Transport.put_file()."""
        return self._decorated.put_file(relpath, f, mode)

    def put_bytes(self, relpath: str, bytes: bytes, mode: int | None = None) -> int:
        """See Transport.put_bytes()."""
        return self._decorated.put_bytes(relpath, bytes, mode)

    def listable(self) -> bool:
        """See Transport.listable."""
        return self._decorated.listable()

    def iter_files_recursive(self) -> Iterator[str]:
        """See Transport.iter_files_recursive()."""
        return self._decorated.iter_files_recursive()

    def list_dir(self, relpath: str) -> list[str]:
        """See Transport.list_dir()."""
        return self._decorated.list_dir(relpath)

    def _readv(
        self, relpath: str, offsets: list[tuple[int, int]]
    ) -> Iterator[tuple[int, bytes]]:
        """See Transport._readv."""
        return self._decorated._readv(relpath, offsets)

    def recommended_page_size(self) -> int:
        """See Transport.recommended_page_size()."""
        return self._decorated.recommended_page_size()

    def rename(self, rel_from: str, rel_to: str) -> None:
        """See Transport.rename."""
        return self._decorated.rename(rel_from, rel_to)

    def rmdir(self, relpath: str) -> None:
        """See Transport.rmdir."""
        return self._decorated.rmdir(relpath)

    def _get_segment_parameters(self) -> dict[str, str]:
        return self._decorated._segment_parameters

    def _set_segment_parameters(self, value: dict[str, str]) -> None:
        self._decorated._segment_parameters = value

    segment_parameters = property(
        _get_segment_parameters,
        _set_segment_parameters,
        doc="See Transport.segment_parameters",
    )

    def stat(self, relpath: str) -> "os.stat_result":
        """See Transport.stat()."""
        return self._decorated.stat(relpath)

    def lock_read(self, relpath: str) -> "Lock":
        """See Transport.lock_read."""
        return self._decorated.lock_read(relpath)

    def lock_write(self, relpath: str) -> "Lock":
        """See Transport.lock_write."""
        return self._decorated.lock_write(relpath)

    def _redirected_to(self, source: str, target: str) -> Transport:
        redirected = self._decorated._redirected_to(source, target)
        if redirected is not None:
            return self.__class__(self._get_url_prefix() + redirected.base, redirected)
        else:
            return None


def get_test_permutations() -> list[tuple[type, type]]:
    """Return the permutations to be used in testing.

    The Decorator class is not directly usable, and testing it would not have
    any benefit - its the concrete classes which need to be tested.
    """
    return []
