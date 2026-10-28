#!/usr/bin/env python3
"""Pinned local build tools for the glibc 2.31 ABI baseline (no system install)."""
import hashlib
from pathlib import Path
import tarfile
import urllib.request

root = Path(__file__).resolve().parent.parent / ".tools"
root.mkdir(exist_ok=True)
for name, url, digest in [
    ("zig.tar.xz", "https://ziglang.org/download/0.15.2/zig-x86_64-linux-0.15.2.tar.xz", "02aa270f183da276e5b5920b1dac44a63f1a49e55050ebde3aecc9eb82f93239"),
    ("zigbuild.tar.xz", "https://github.com/rust-cross/cargo-zigbuild/releases/download/v0.22.2/cargo-zigbuild-x86_64-unknown-linux-musl.tar.xz", "c42788ed655c4a51509356ba082c84296d82669b261c9e1cfd91eb8a13d4efb5"),
]:
    path = root / name
    data = path.read_bytes() if path.exists() else urllib.request.urlopen(url, timeout=90).read()
    if hashlib.sha256(data).hexdigest() != digest:
        raise SystemExit(f"Checksum mismatch for {name}")
    path.write_bytes(data)
    with tarfile.open(path) as archive:
        archive.extractall(root, filter="data")
print("Verified Zig 0.15.2 and cargo-zigbuild 0.22.2")
