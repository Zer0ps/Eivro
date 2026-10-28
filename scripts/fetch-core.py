#!/usr/bin/env python3
"""Fetch only pinned, SHA-256 verified upstream release artifacts."""
import hashlib
import io
import argparse
from pathlib import Path
import platform
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
VERSION = "1.14.4"
ARCHES = {
    "x86_64": ("amd64", "699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968"),
    "aarch64": ("arm64", "436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26"),
}

def check_version():
    try:
        result = subprocess.run(
            [str(ROOT / "vendor/sing-box"), "version"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise SystemExit(f"Missing or unusable sing-box; run python3 scripts/fetch-core.py for {VERSION}")
    if result.returncode or result.stdout.splitlines()[:1] != [f"sing-box version {VERSION}".encode()]:
        raise SystemExit(f"Expected sing-box {VERSION}; run python3 scripts/fetch-core.py")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Check the bundled version without downloading")
    if parser.parse_args().check:
        check_version()
        return
    arch, digest = ARCHES[platform.machine()]
    name = f"sing-box-{VERSION}-linux-{arch}"
    url = f"https://github.com/SagerNet/sing-box/releases/download/v{VERSION}/{name}.tar.gz"
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(128 * 1024 * 1024)
    if hashlib.sha256(data).hexdigest() != digest:
        raise SystemExit("Core checksum mismatch; nothing installed")
    dest = ROOT / "vendor"
    dest.mkdir(exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for filename in ("sing-box", "LICENSE"):
            member = archive.getmember(f"{name}/{filename}")
            if not member.isfile():
                raise SystemExit("Unexpected archive entry")
            (dest / filename).write_bytes(archive.extractfile(member).read())
    (dest / "sing-box").chmod(0o755)
    check_version()
    print(f"Verified sing-box {VERSION} ({arch})")

if __name__ == "__main__":
    main()
