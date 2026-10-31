#!/usr/bin/env python3
"""Reject mismatched release tags before any build or publication."""
import os
from pathlib import Path
import re
import tomllib

root = Path(__file__).resolve().parent.parent
version = tomllib.loads((root / "Cargo.toml").read_text())["package"]["version"]
if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
    raise SystemExit("Stable packages require a numeric Cargo version")
ref = os.environ.get("GITHUB_REF", "")
if ref.startswith("refs/tags/") and ref != f"refs/tags/v{version}":
    raise SystemExit("Release tag must match v<Cargo package version>")
print(f"Release metadata: Eivro {version}")
