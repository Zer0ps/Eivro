#!/usr/bin/env python3
"""Verify release payloads and metadata; never connect or install anything."""
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import xml.etree.ElementTree as ET
import os
import tempfile
import tomllib
import platform

ROOT = Path(__file__).resolve().parent.parent
temporary = tempfile.TemporaryDirectory(prefix='velum-package-check-')
WORK = Path(temporary.name)
DIST = ROOT / 'dist'
VERSION = tomllib.loads((ROOT/'Cargo.toml').read_text())['package']['version']
PKGVERSION = VERSION.replace('-', '~')
assert platform.machine() == 'x86_64', 'This release verifier covers x86_64'
BIN_DIR = Path(os.environ.get('VELUM_BIN_DIR', ROOT/'target/x86_64-unknown-linux-gnu/release'))

def run(args):
    return subprocess.check_output([str(a) for a in args], stderr=subprocess.STDOUT)

def sha(data):
    return hashlib.sha256(data).hexdigest()

sources = {
    name: ((BIN_DIR if name.startswith('velum') else ROOT/'vendor') / name)
    for name in ('velum', 'velum-tun', 'sing-box', 'xray')
}
hashes = {name: sha(path.read_bytes()) for name, path in sources.items()}
checks = {'binary_sha256': hashes}

with tarfile.open(DIST / f'velum-{VERSION}-linux-amd64.tar.gz') as archive:
    prefix = f'velum-{VERSION}-linux-amd64/'
    for name in ('velum', 'sing-box', 'xray'):
        member = archive.getmember(prefix + name)
        assert member.mode == 0o755 and member.uid == member.gid == 0
        assert sha(archive.extractfile(member).read()) == hashes[name]
    assert archive.getmember(prefix + 'NotoEmoji.LICENSE').isfile()
checks['portable'] = 'PASS: release GUI/cores SHA256, root/0755, font license'

deb = DIST / f'velum_{PKGVERSION}_amd64.deb'
with tarfile.open(fileobj=io.BytesIO(run(['ar', 'p', deb, 'data.tar.gz']))) as archive:
    for parent in ['usr', 'usr/libexec', 'usr/libexec/velum', 'usr/share/licenses/velum']:
        directory = archive.getmember(parent)
        assert directory.isdir() and directory.mode == 0o755 and directory.uid == directory.gid == 0
    for name in sources:
        member = archive.getmember('usr/libexec/velum/' + name)
        assert member.mode == 0o755 and member.uid == member.gid == 0
        assert sha(archive.extractfile(member).read()) == hashes[name]
    ET.fromstring(archive.extractfile('usr/share/polkit-1/actions/io.velum.tun.policy').read())
    assert archive.getmember('usr/share/licenses/velum/NotoEmoji.LICENSE').isfile()
with tarfile.open(fileobj=io.BytesIO(run(['ar', 'p', deb, 'control.tar.gz']))) as archive:
    control = archive.extractfile('control').read().decode()
    assert 'Version: ' + PKGVERSION + '\n' in control
    assert ', nftables,' in control
    assert 'polkitd | policykit-1, pkexec | policykit-1' in control
checks['deb'] = 'PASS: four executables SHA256, root/0755, policy XML, version, nftables dependency, font license'

rpm = DIST / f'velum-{PKGVERSION}-1.x86_64.rpm'
assert run(['rpm', '-qp', '--qf', '%{VERSION}', rpm]).decode() == PKGVERSION
assert run(['rpm', '-qp', '--qf', '%{FILEDIGESTALGO}', rpm]).decode() == '8'
metadata = run(['rpm', '-qp', '--qf', '[%{FILENAMES}\t%{FILEMODES:perms}\t%{FILEUSERNAME}\t%{FILEGROUPNAME}\t%{FILEDIGESTS}\n]', rpm]).decode()
entries = {line.split('\t')[0]: line.split('\t')[1:] for line in metadata.splitlines()}
for name in sources:
    mode, user, group, digest = entries['/usr/libexec/velum/' + name]
    assert (mode, user, group, digest) == ('-rwxr-xr-x', 'root', 'root', hashes[name])
assert '/usr/share/licenses/velum/NotoEmoji.LICENSE' in entries
assert 'nftables' in run(['rpm', '-qp', '--requires', rpm]).decode().splitlines()
checks['rpm_digests'] = run(['rpm', '--checksig', rpm]).decode().strip().split(': ', 1)[1]
checks['rpm'] = 'PASS: version, SHA256, root/0755, nftables dependency, font license; unsigned local package'

appimage = DIST / f'Velum-{VERSION}-x86_64.AppImage'
if appimage.exists():
    appdir = WORK / 'squashfs-root'
    subprocess.run([str(appimage), '--appimage-extract'], cwd=WORK, check=True, stdout=subprocess.DEVNULL)
    for name in ('velum', 'sing-box', 'xray'):
        path = appdir / name
        assert stat.S_IMODE(path.stat().st_mode) == 0o755
        assert sha(path.read_bytes()) == hashes[name]
    checks['appimage'] = 'PASS: extracted binary hashes and executable modes'
checks['app_version'] = run([sources['velum'], '--version']).decode().strip()
assert checks['app_version'] == 'Velum ' + VERSION
checks['helper_version'] = run([sources['velum-tun'], '--version']).decode().strip()
assert checks['helper_version'] == 'Velum TUN ' + VERSION
versions = re.findall(r'GLIBC_(\d+\.\d+)', run(['readelf', '--version-info', sources['velum']]).decode())
checks['maximum_required_glibc'] = max(versions, key=lambda v: tuple(map(int, v.split('.'))))

checks['xray_version'] = run([sources['xray'], 'version']).decode().splitlines()[0]
assert checks['xray_version'].startswith('Xray 26.10.21 ')
checks['sing_box_version'] = run([sources['sing-box'], 'version']).decode().splitlines()[0]
assert checks['sing_box_version'] == 'sing-box version 1.14.4'
with tarfile.open(DIST / f'velum-{VERSION}-source.tar.gz') as archive:
    names = archive.getnames()
    assert all(name.startswith(f'velum-{VERSION}-source/') for name in names)
    assert not any(part in {'.ssh', '.config', '.tools', 'target', 'work', 'dist', '__pycache__'} for name in names for part in Path(name).parts)
    assert archive.extractfile(f'velum-{VERSION}-source/Cargo.toml').read() == (ROOT / 'Cargo.toml').read_bytes()
    assert archive.extractfile(f'velum-{VERSION}-source/src/process.rs').read() == (ROOT / 'src/process.rs').read_bytes()
    assert archive.extractfile(f'velum-{VERSION}-source/tests/connection.rs').read() == (ROOT / 'tests/connection.rs').read_bytes()
    assert archive.extractfile(f'velum-{VERSION}-source/docs/VERIFICATION.md').read() == (ROOT / 'docs/VERIFICATION.md').read_bytes()
    for name in ['.github/workflows/release.yml', 'scripts/verify-packages.py', 'src/resolver.rs', 'tests/resolver.rs']:
        assert archive.extractfile(f'velum-{VERSION}-source/{name}').read() == (ROOT/name).read_bytes()
checks['source'] = 'PASS: current version, supervisor/tests/docs match; no home/config/build directories'
subprocess.run(['sha256sum', '--check', 'SHA256SUMS'], cwd=DIST, check=True)
(DIST / f'Velum-{VERSION}-package-checks.json').write_text(json.dumps(checks, ensure_ascii=False, indent=2) + '\n')
print(json.dumps(checks, ensure_ascii=False, indent=2))
temporary.cleanup()
