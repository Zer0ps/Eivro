#!/usr/bin/env python3
"""Offline installed payload smoke test; never starts TUN or changes DNS/proxy."""
import json
from pathlib import Path
import stat
import subprocess
import xml.etree.ElementTree as ET

directory = Path("/usr/libexec/eivro")
version = subprocess.check_output(["eivro", "--version"], text=True).strip().removeprefix("Eivro ")
assert subprocess.check_output([str(directory / "eivro-tun"), "--version"], text=True).strip() == f"Eivro TUN {version}"
for launcher in ("/usr/bin/velum", "/usr/libexec/velum/velum"):
    assert subprocess.check_output([launcher, "--version"], text=True).strip() == f"Eivro {version}"
for removed in ("/usr/libexec/velum/velum-tun", "/usr/share/applications/io.velum.Client.desktop", "/usr/share/polkit-1/actions/io.velum.tun.policy"):
    assert not Path(removed).exists(), removed
for name in ("eivro", "eivro-tun", "sing-box", "xray"):
    path = directory / name
    info = path.stat()
    assert info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o755, name
    result = subprocess.run(["ldd", str(path)], capture_output=True, text=True)
    assert "not found" not in result.stdout + result.stderr, name
for name in ("sing-box", "xray"):
    subprocess.run([str(directory / name), "version"], check=True)
subprocess.run(["desktop-file-validate", "/usr/share/applications/io.eivro.Client.desktop"], check=True)
ET.parse("/usr/share/polkit-1/actions/io.eivro.tun.policy")
result = subprocess.run(["eivro", "--resolve-system"], input=b'["localhost",443]', capture_output=True, check=True, timeout=5)
addresses = json.loads(result.stdout)
assert addresses and not result.stderr
assert all(a in ("127.0.0.1:443", "[::1]:443") for a in addresses)
print(f"Installed Eivro {version}: dependencies, permissions, CLI, system resolver and desktop metadata OK")
