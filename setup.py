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

import os

from setuptools import setup

rust_features = []
if os.environ.get("DROMEDARY_GIO"):
    rust_features.append("gio")

rust_extensions = [
    RustExtension(
        "dromedary._transport_rs",
        "dromedary/_transport_rs/Cargo.toml",
        binding=Binding.PyO3,
        features=rust_features,
    ),
]

setup(
    rust_extensions=rust_extensions,
)
