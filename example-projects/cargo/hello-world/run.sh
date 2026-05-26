#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
# Use a project-local CARGO_HOME so the registry cache is isolated and cleared each
# run, ensuring packages are always downloaded fresh through the proxy.
export CARGO_HOME="$(pwd)/.cargo-home"
rm -rf "$CARGO_HOME"
cargo run
