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

"""Re-entry point for the WebDAV tests under the global test-discovery path.

The Makefile runs ``unittest discover`` against ``dromedary/tests`` only, so
this module uses the ``load_tests`` protocol to pull in the webdav test
suite that lives in ``dromedary/webdav/tests/``.
"""

import unittest


def load_tests(loader, basic_tests, pattern):
    """Delegate to the webdav test package's ``load_tests``."""
    from dromedary.webdav import tests as webdav_tests

    suite = unittest.TestSuite()
    return webdav_tests.load_tests(loader, suite, pattern)
