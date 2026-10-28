#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ -x target/x86_64-unknown-linux-gnu/release/velum ]; then
    exec target/x86_64-unknown-linux-gnu/release/velum
fi
if [ -x target/release/velum ]; then
    exec target/release/velum
fi
. ./scripts/env.sh
cargo build --locked --release
exec target/release/velum
