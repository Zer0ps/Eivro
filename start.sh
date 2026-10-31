#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ -x target/x86_64-unknown-linux-gnu/release/eivro ]; then
    exec target/x86_64-unknown-linux-gnu/release/eivro
fi
if [ -x target/release/eivro ]; then
    exec target/release/eivro
fi
. ./scripts/env.sh
cargo build --locked --release
exec target/release/eivro
