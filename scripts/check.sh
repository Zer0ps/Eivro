#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
. ./scripts/env.sh
python3 - <<'PY'
from pathlib import Path
for directory in ("scripts", "tests"):
    for path in Path(directory).glob("*.py"):
        compile(path.read_text(), str(path), "exec")
PY
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_diagnose_link.py' -v
