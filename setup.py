#! /usr/bin/env python3

"""Installation script for dromedary."""

import sys

try:
    import setuptools  # noqa: F401
except ModuleNotFoundError as e:
    sys.stderr.write(f"[ERROR] Please install setuptools ({e})\n")
    sys.exit(1)

try:
    from setuptools_rust import Binding, RustExtension
except ModuleNotFoundError as e:
    sys.stderr.write(f"[ERROR] Please install setuptools_rust ({e})\n")
    sys.exit(1)

from setuptools import setup

rust_extensions = [
    RustExtension(
        "dromedary._transport_rs",
        "dromedary/_transport_rs/Cargo.toml",
        binding=Binding.PyO3,
    ),
    RustExtension(
        "dromedary._urlutils_rs",
        "dromedary/_urlutils_rs/Cargo.toml",
        binding=Binding.PyO3,
    ),
]

setup(
    rust_extensions=rust_extensions,
)
