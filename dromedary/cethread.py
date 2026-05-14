# Copyright (C) 2011 Canonical Ltd
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

"""Thread implementation that captures and re-raises exceptions.

This module provides a thread class that catches exceptions occurring during
thread execution and re-raises them when the thread is joined, allowing for
better error handling in multi-threaded applications.
"""

import sys
import threading
import types
from collections.abc import Callable, Iterable, Mapping


class CatchingExceptionThread(threading.Thread):
    """A thread that keeps track of exceptions.

    If an exception occurs during the thread execution, it's caught and
    re-raised when the thread is joined().
    """

    ignored_exceptions: Callable[[BaseException], bool] | None
    exception: (
        tuple[type[BaseException], BaseException, types.TracebackType]
        | tuple[None, None, None]
        | None
    )

    def __init__(
        self,
        group: None = None,
        target: Callable[..., object] | None = None,
        name: str | None = None,
        args: Iterable[object] = (),
        kwargs: Mapping[str, object] | None = None,
        *,
        daemon: bool | None = None,
        sync_event: threading.Event | None = None,
    ) -> None:
        """Initialize a CatchingExceptionThread instance.

        Args:
            sync_event: An optional threading.Event used for synchronization. If not
                provided, a new Event will be created. This event is used to coordinate
                exception handling between threads.
        """
        # There are cases where the calling thread must wait, yet, if an
        # exception occurs, the event should be set so the caller is not
        # blocked. The main example is a calling thread that want to wait for
        # the called thread to be in a given state before continuing.
        if sync_event is None:
            sync_event = threading.Event()
        super().__init__(
            group=group,
            target=target,
            name=name,
            args=args,
            kwargs=kwargs,
            daemon=daemon,
        )
        self.set_sync_event(sync_event)
        self.exception = None
        self.ignored_exceptions = None  # see set_ignored_exceptions
        self.lock = threading.Lock()

    def set_sync_event(self, event: threading.Event) -> None:
        """Set the ``sync_event`` event used to synchronize exception catching.

        When the thread uses an event to synchronize itself with another thread
        (setting it when the other thread can wake up from a ``wait`` call),
        the event must be set after catching an exception or the other thread
        will hang.

        Some threads require multiple events and should set the relevant one
        when appropriate.

        Note that the event should be initially cleared so the caller can
        wait() on him and be released when the thread set the event.

        Also note that the thread can use multiple events, setting them as it
        progress, while the caller can chose to wait on any of them. What
        matters is that there is always one event set so that the caller is
        always released when an exception is caught. Re-using the same event is
        therefore risky as the thread itself has no idea about which event the
        caller is waiting on. If the caller has already been released then a
        cleared event won't guarantee that the caller is still waiting on it.
        """
        self.sync_event = event

    def switch_and_set(self, new: threading.Event) -> None:
        """Switch to a new ``sync_event`` and set the current one.

        Using this method protects against race conditions while setting a new
        ``sync_event``.

        Note that this allows a caller to wait either on the old or the new
        event depending on whether it wants a fine control on what is happening
        inside a thread.

        :param new: The event that will become ``sync_event``
        """
        cur = self.sync_event
        self.lock.acquire()
        try:  # Always release the lock
            try:
                self.set_sync_event(new)
                # From now on, any exception will be synced with the new event
            except BaseException:
                # Unlucky, we couldn't set the new sync event, try restoring a
                # safe state
                self.set_sync_event(cur)
                raise
            # Setting the current ``sync_event`` will release callers waiting
            # on it, note that it will also be set in run() if an exception is
            # raised
            cur.set()
        finally:
            self.lock.release()

    def set_ignored_exceptions(
        self,
        ignored: Callable[[BaseException], bool]
        | None
        | list[type[Exception]]
        | type[Exception],
    ) -> None:
        """Declare which exceptions will be ignored.

        :param ignored: Can be either:

           - None: all exceptions will be raised,
           - an exception class: the instances of this class will be ignored,
           - a tuple of exception classes: the instances of any class of the
             list will be ignored,
           - a callable: that will be passed the exception object
             and should return True if the exception should be ignored
        """
        if ignored is None:
            self.ignored_exceptions = None
        elif isinstance(ignored, (Exception, tuple)):
            self.ignored_exceptions = lambda e: isinstance(e, ignored)
        elif isinstance(ignored, list):
            self.ignored_exceptions = lambda e: isinstance(e, tuple(ignored))  # type: ignore
        else:
            self.ignored_exceptions = ignored  # type: ignore

    def run(self) -> None:
        """Overrides Thread.run to capture any exception."""
        self.sync_event.clear()
        try:
            try:
                super().run()
            except BaseException:
                self.exception = sys.exc_info()
        finally:
            # Make sure the calling thread is released
            self.sync_event.set()

    def join(self, timeout: float | None = None) -> None:
        """Overrides Thread.join to raise any exception caught.

        Calling join(timeout=0) will raise the caught exception or return None
        if the thread is still alive.
        """
        super().join(timeout)
        if self.exception is not None:
            _exc_class, exc_value, _exc_tb = self.exception
            self.exception = None  # The exception should be raised only once
            if exc_value is not None and (
                self.ignored_exceptions is None
                or not self.ignored_exceptions(exc_value)
            ):
                # Raise non ignored exceptions
                raise exc_value

    def pending_exception(self) -> None:
        """Raise the caught exception.

        This does nothing if no exception occurred.
        """
        self.join(timeout=0)
