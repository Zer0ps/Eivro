#!/bin/sh
# Source this file from the repository root; never install a toolchain globally.
if [ -x "$PWD/.tools/cargo/bin/cargo" ]; then
    export CARGO_HOME="$PWD/.tools/cargo"
    export RUSTUP_HOME="$PWD/.tools/rustup"
    export PATH="$CARGO_HOME/bin:$PATH"
fi
export PATH="$PWD/.tools/zig-x86_64-linux-0.15.2:$PWD/.tools/cargo-zigbuild-x86_64-unknown-linux-musl:$PATH"
export ZIG_GLOBAL_CACHE_DIR="$PWD/.tools/zig-cache"
