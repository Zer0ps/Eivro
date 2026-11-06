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
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_lab_isolation.py' -v
python3 scripts/update-ru-presets.py --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked --example network-lab-config
python3 tests/network_lab.py
python3 tests/fakeip_core.py --core vendor/sing-box
python3 tests/domain_dns_lab.py
cargo build --locked --bins
python3 tests/domain_dns_helper_lab.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_diagnose_link.py' -v
