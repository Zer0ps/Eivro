#!/usr/bin/env python3
import hashlib
from pathlib import Path
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / ".tools"
FILES = [
    ("https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage", "appimagetool.AppImage", "a6d71e2b6cd66f8e8d16c37ad164658985e0cf5fcaa950c90a482890cb9d13e0"),
    ("https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-x86_64", "runtime-x86_64", "1cc49bcf1e2ccd593c379adb17c9f85a36d619088296504de95b1d06215aebbf"),
]
TOOLS.mkdir(exist_ok=True)
for url, name, digest in FILES:
    target = TOOLS / name
    data = target.read_bytes() if target.exists() else urllib.request.urlopen(url, timeout=60).read()
    if hashlib.sha256(data).hexdigest() != digest:
        raise SystemExit(f"Checksum mismatch for {name}; review upstream version before updating the pin")
    target.write_bytes(data)
    target.chmod(0o755)
if not (TOOLS / "appimagetool/AppRun").exists():
    subprocess.run([str(TOOLS / "appimagetool.AppImage"), "--appimage-extract"], cwd=TOOLS, stdout=subprocess.DEVNULL, check=True)
    (TOOLS / "squashfs-root").rename(TOOLS / "appimagetool")
print("Verified AppImage build tools")
