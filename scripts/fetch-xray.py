#!/usr/bin/env python3
"""Fetch a pinned upstream Xray binary, verify it, then extract only named files."""
import argparse
import hashlib
import io
from pathlib import Path
import platform
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parent.parent
VERSION = "26.10.21"
ARCHES = {
    "x86_64": ("64", "0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978"),
    "aarch64": ("arm64-v8a", "d1304946c486d98e6b886e9b931eaaaebb23835b30e217638037b7f2721d4e9c"),
}


def check_version():
    try:
        result = subprocess.run(
            [str(ROOT / "vendor/xray"), "version"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise SystemExit(f"Missing or unusable Xray; run python3 scripts/fetch-xray.py for {VERSION}")
    if result.returncode or not result.stdout.startswith(f"Xray {VERSION} ".encode()):
        raise SystemExit(f"Expected Xray {VERSION}; run python3 scripts/fetch-xray.py")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Check the bundled version without downloading")
    if parser.parse_args().check:
        check_version()
        return
    arch, digest = ARCHES[platform.machine()]
    url = f"https://github.com/XTLS/Xray-core/releases/download/v{VERSION}/Xray-linux-{arch}.zip"
    result = subprocess.run(["curl", "--noproxy", "*", "-fL", "--silent", "--show-error", "--connect-timeout", "15", "--max-time", "120", "--max-filesize", "134217728", "--proto", "=https", "--proto-redir", "=https", url], stdout=subprocess.PIPE, check=True)
    if hashlib.sha256(result.stdout).hexdigest() != digest:
        raise SystemExit("Xray checksum mismatch; nothing installed")
    dest = ROOT / "vendor"
    dest.mkdir(exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(result.stdout)) as archive:
        for name, target in [("xray", "xray"), ("LICENSE", "xray.LICENSE")]:
            entry = archive.getinfo(name)
            if entry.is_dir() or entry.file_size > 128 * 1024 * 1024:
                raise SystemExit("Unexpected Xray archive entry")
            (dest / target).write_bytes(archive.read(entry))
    (dest / "xray").chmod(0o755)
    check_version()
    print(f"Verified Xray {VERSION} ({arch})")


if __name__ == "__main__":
    main()
