PYTHON ?= python3
CARGO ?= cargo

.PHONY: all build test test-python test-rust check fmt clippy clean install

all: build

build:
	$(PYTHON) -m pip install -e . --no-build-isolation

install:
	$(PYTHON) -m pip install .

test: test-python test-rust

test-python:
	$(PYTHON) -m unittest discover -t . -s dromedary/tests -p 'test_*.py'

test-rust:
	$(CARGO) test --workspace

check: fmt clippy test

fmt:
	$(CARGO) fmt --all
	ruff format dromedary

clippy:
	$(CARGO) clippy --workspace --all-targets

clean:
	$(CARGO) clean
	rm -rf build dist *.egg-info
