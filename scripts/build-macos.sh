#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ "$(uname -s)" != Darwin ]; then
    echo 'Build the macOS package on a macOS runner with Xcode Command Line Tools.' >&2
    exit 1
fi
export MACOSX_DEPLOYMENT_TARGET=26.0
python3 scripts/fetch-core.py
python3 scripts/fetch-xray.py
cargo build --locked --release --bin eivro --bin eivro-tun
python3 scripts/package-macos.py
