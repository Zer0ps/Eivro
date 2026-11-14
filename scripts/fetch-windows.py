#!/usr/bin/env python3
"""Fetch the pinned official Windows x64 cores; never extract arbitrary ZIP paths."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / "vendor/windows"
LIMIT = 128 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    manifest = json.loads((ROOT / "scripts/windows-cores.json").read_text(encoding="utf-8"))
    for name, source in [("sing-box", "src/lib.rs"), ("xray", "src/xray.rs")]:
        field = "UPSTREAM_CORE_VERSION" if name == "sing-box" else "VERSION"
        match = re.search(rf'pub const {field}: &str = "([^"]+)"', (ROOT / source).read_text(encoding="utf-8"))
        if not match or match[1] != manifest[name]["version"]:
            raise SystemExit(f"Windows {name} pin differs from Rust")
    DEST.mkdir(parents=True, exist_ok=True)
    for name, info in manifest.items():
        if all((DEST / entry["target"]).is_file() and
               digest((DEST / entry["target"]).read_bytes()) == entry["sha256"]
               for entry in info["files"].values()):
            print(f"Verified {name} {info['version']} (Windows x64)")
            continue
        if args.check:
            raise SystemExit(f"Missing or modified {name}; run scripts/fetch-windows.py")
        response = subprocess.run([
            "curl", "--fail", "--location", "--silent", "--show-error",
            "--connect-timeout", "15", "--max-time", "600", "--max-filesize", str(LIMIT),
            "--proto", "=https", "--proto-redir", "=https", info["url"],
        ], check=True, stdout=subprocess.PIPE)
        if len(response.stdout) > LIMIT or digest(response.stdout) != info["sha256"]:
            raise SystemExit(f"{name} archive checksum mismatch; nothing installed")
        with zipfile.ZipFile(io.BytesIO(response.stdout)) as archive:
            payload = {}
            for member, entry in info["files"].items():
                meta = archive.getinfo(member)
                if meta.is_dir() or meta.file_size > LIMIT:
                    raise SystemExit("Invalid core archive entry")
                data = archive.read(meta)
                if digest(data) != entry["sha256"] or Path(entry["target"]).name != entry["target"]:
                    raise SystemExit("Invalid core file checksum or name")
                payload[entry["target"]] = data
        for filename, data in payload.items():
            temp = DEST / (filename + ".tmp")
            temp.write_bytes(data)
            temp.replace(DEST / filename)
        print(f"Verified {name} {info['version']} (Windows x64)")


if __name__ == "__main__":
    main()
