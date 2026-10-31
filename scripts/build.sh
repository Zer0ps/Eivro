#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
. ./scripts/env.sh
if ! python3 scripts/fetch-core.py --check; then python3 scripts/fetch-core.py; fi
if ! python3 scripts/fetch-xray.py --check; then python3 scripts/fetch-xray.py; fi
if command -v cargo-zigbuild >/dev/null 2>&1; then
    XDG_CACHE_HOME="$PWD/.tools/cache" cargo zigbuild --locked --release --target x86_64-unknown-linux-gnu.2.31
    export EIVRO_BIN_DIR="$PWD/target/x86_64-unknown-linux-gnu/release"
else
    cargo build --locked --release
    export EIVRO_BIN_DIR="$PWD/target/release"
fi
python3 scripts/package.py "$@"
