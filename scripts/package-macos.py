#!/usr/bin/env python3
"""Build an installer without installing it or changing the host's networking."""
import hashlib
import sys
import tempfile
import time
import os
from pathlib import Path
import platform
import plistlib
import shutil
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parent.parent
VERSION = tomllib.loads((ROOT / 'Cargo.toml').read_text())['package']['version']

def run(*args):
    subprocess.run([str(a) for a in args], check=True)

def copy(source, destination, mode=0o644):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    destination.chmod(mode)

def verify_macho(binary, architecture):
    architectures = subprocess.check_output(['lipo', '-archs', str(binary)], text=True).split()
    if architecture not in architectures:
        raise SystemExit(f'Wrong architecture in {binary.name}: {architectures}')
    commands = subprocess.check_output(['otool', '-l', str(binary)], text=True).splitlines()
    command = None
    minimums = []
    for line in commands:
        fields = line.split()
        if fields[:1] == ['cmd']:
            command = fields[1]
        elif len(fields) == 2 and ((command == 'LC_BUILD_VERSION' and fields[0] == 'minos')
                or (command == 'LC_VERSION_MIN_MACOSX' and fields[0] == 'version')):
            minimums.append(tuple(map(int, fields[1].split('.'))))
    if not minimums or any((version + (0, 0))[:2] > (26, 0) for version in minimums):
        raise SystemExit(f'{binary.name} does not declare compatibility with macOS 26')


def create_dmg(source, destination, size_mib):
    # DiskImages may briefly retain its backing device after a failed attach.
    # Give each attempt its own source and output on the destination filesystem.
    for attempt in range(3):
        with tempfile.TemporaryDirectory(prefix='.eivro-dmg-', dir=destination.parent) as tmp:
            stage = Path(tmp)
            payload = stage / 'payload'
            shutil.copytree(source, payload)
            image = stage / 'Eivro.dmg'
            result = subprocess.run([
                'hdiutil', 'create', '-format', 'UDZO', '-fs', 'HFS+',
                '-size', f'{size_mib}m', '-volname', 'Eivro', '-srcfolder',
                str(payload), str(image),
            ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                env={**os.environ, 'LC_ALL': 'C'})
            print(result.stdout, end='', file=sys.stderr, flush=True)
            if result.returncode == 0:
                image.replace(destination)
                return
            if attempt == 2 or 'hdiutil: create failed - Resource busy' not in result.stdout.splitlines():
                result.check_returncode()
        delay = 2 ** (attempt + 1)
        print(f'DiskImages is busy. Retrying in {delay} seconds.', file=sys.stderr, flush=True)
        time.sleep(delay)


def main():
    if platform.system() != 'Darwin':
        raise SystemExit('Package macOS on a macOS runner, not on Linux')
    machine = platform.machine()
    if machine not in ('arm64', 'x86_64'):
        raise SystemExit('Unsupported macOS architecture')
    for name in ('eivro', 'eivro-tun'):
        version = subprocess.check_output([str(ROOT / 'target/release' / name), '--version'], text=True).strip()
        expected = f'Eivro {"TUN " if name == "eivro-tun" else ""}{VERSION}'
        if version != expected:
            raise SystemExit(f'Stale {name}: rebuild the current release')
    import fcntl
    dist = ROOT / 'dist'
    dist.mkdir(exist_ok=True)
    # Serialize flat-name publication for a shared checkout. Each invocation
    # builds privately on dist's filesystem, including all pkgbuild outputs.
    with (dist / '.package-macos.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with tempfile.TemporaryDirectory(prefix='.eivro-macos-', dir=dist) as tmp:
            build(Path(tmp), dist, machine)


def build(work, dist, machine):
    stage = work / 'root'
    app = stage / 'Applications/Eivro.app/Contents'
    helper = stage / 'Library/PrivilegedHelperTools/io.eivro'
    for name in ('eivro', 'sing-box', 'xray'):
        copy(ROOT / ('target/release' if name == 'eivro' else 'vendor') / name, app / 'MacOS' / name, 0o755)
    for name in ('eivro-tun', 'sing-box', 'xray'):
        copy(ROOT / ('target/release' if name == 'eivro-tun' else 'vendor') / name, helper / name, 0o755)
    for binary in list((app / 'MacOS').iterdir()) + list(helper.iterdir()):
        verify_macho(binary, machine)
    info = {
        'CFBundleExecutable': 'eivro', 'CFBundleIdentifier': 'io.eivro.Client',
        'CFBundleName': 'Eivro', 'CFBundleDisplayName': 'Eivro', 'CFBundlePackageType': 'APPL',
        'CFBundleShortVersionString': VERSION, 'CFBundleVersion': VERSION,
        'LSMinimumSystemVersion': '26.0', 'NSHighResolutionCapable': True,
        'NSPrincipalClass': 'NSApplication', 'CFBundleIconFile': 'Eivro',
    }
    (app / 'Info.plist').write_bytes(plistlib.dumps(info))
    copy(ROOT / 'assets/io.eivro.Client.png', app / 'Resources/AppIcon.png')
    icons = work / 'Eivro.iconset'
    icons.mkdir(parents=True)
    for size in (16, 32, 128, 256, 512):
        for scale in (1, 2):
            name = f'icon_{size}x{size}{"@2x" if scale == 2 else ""}.png'
            run('sips', '-z', size * scale, size * scale, app / 'Resources/AppIcon.png', '--out', icons / name)
    run('iconutil', '-c', 'icns', icons, '-o', app / 'Resources/Eivro.icns')
    copy(ROOT / 'packaging/macos/uninstall.sh', app / 'Resources/uninstall.sh', 0o755)
    for name in ('README.md', 'PRIVACY.md', 'LICENSE', 'THIRD_PARTY.md'):
        copy(ROOT / name, app / 'Resources' / name)
    for document in (ROOT / 'docs').glob('*.md'):
        copy(document, app / 'Resources/docs' / document.name)
    copy(ROOT / 'assets/rules/ru-direct/LICENSE', app / 'Resources/ru-direct.LICENSE')
    copy(ROOT / 'assets/rules/ru-direct/source.json', app / 'Resources/ru-direct-source.json')
    for source, name in [('vendor/LICENSE', 'sing-box.LICENSE'), ('vendor/xray.LICENSE', 'xray.LICENSE'), ('assets/Inter.LICENSE', 'Inter.LICENSE'), ('assets/NotoEmoji.LICENSE', 'NotoEmoji.LICENSE')]:
        copy(ROOT / source, app / 'Resources' / name)
    copy(ROOT / 'packaging/macos/io.eivro.tun.plist', stage / 'Library/LaunchDaemons/io.eivro.tun.plist')
    # Ad-hoc signing supplies bundle integrity for local testing. It is not
    # Developer ID signing or notarization and must never be advertised as such.
    # Sign nested executables before the enclosing app. Signing the main
    # executable first makes codesign validate the still-unsigned siblings.
    for binary in [app / 'MacOS/sing-box', app / 'MacOS/xray'] + sorted(helper.iterdir()):
        run('codesign', '--force', '--sign', '-', '--options', 'runtime', binary)
    run('codesign', '--force', '--sign', '-', '--options', 'runtime', app.parent)
    run('codesign', '--verify', '--deep', '--strict', app.parent)
    image_root = work / 'image'
    image_root.mkdir()
    package = image_root / f'Eivro-{VERSION}-macos-{machine}.pkg'
    components = work / 'components.plist'
    run('pkgbuild', '--analyze', '--root', stage, components)
    descriptions = plistlib.loads(components.read_bytes())
    if len(descriptions) != 1 or descriptions[0]['RootRelativeBundlePath'] != 'Applications/Eivro.app':
        raise SystemExit('Unexpected installer component layout')
    descriptions[0]['BundleIsRelocatable'] = False
    descriptions[0]['BundleHasStrictIdentifier'] = True
    descriptions[0]['BundleOverwriteAction'] = 'upgrade'
    components.write_bytes(plistlib.dumps(descriptions))
    run('pkgbuild', '--root', stage, '--component-plist', components,
        '--identifier', 'io.eivro.pkg', '--version', VERSION,
        '--install-location', '/', '--ownership', 'recommended', '--scripts', ROOT / 'packaging/macos/scripts', package)
    (image_root / 'Read me.txt').write_text('Eivro for macOS 26 or later.\nOpen the .pkg installer, then launch Eivro from Applications.\nThis preview is ad-hoc signed, not notarized by Apple.\nVPN, DNS recovery and energy use require validation on a Mac before a stable macOS release.\n')
    dmg = work / f'Eivro-{VERSION}-macos-{machine}.dmg'
    # hdiutil's automatic source-folder sizing can leave too little room for a
    # large PKG on the temporary filesystem. Empty space compresses away in UDZO.
    payload = sum(p.stat().st_size for p in image_root.iterdir() if p.is_file())
    image_mib = (payload + 1024 * 1024 - 1) // (1024 * 1024) + 64
    print(f'DMG volume: {image_mib} MiB; host free: {shutil.disk_usage(work).free // (1024 * 1024)} MiB', flush=True)
    create_dmg(image_root, dmg, image_mib)
    publish(dist, machine, package, dmg)


def publish(dist, machine, package, dmg):
    manifest = dmg.parent / f'SHA256SUMS-macos-{machine}'
    artifacts = (package, dmg)
    digests = []
    for item in artifacts:
        with item.open('rb') as stream:
            digests.append(f'{hashlib.file_digest(stream, "sha256").hexdigest()}  {item.name}\n')
    manifest.write_text(''.join(digests), encoding='ascii')
    # A checksum manifest is the commit record for these fixed filenames.
    # A build failure above preserves the previous complete set. If the
    # process dies during the renames, an incomplete set has no manifest.
    (dist / manifest.name).unlink(missing_ok=True)
    for item in (*artifacts, manifest):
        item.replace(dist / item.name)
    print(dist / package.name)
    print(dist / dmg.name)


if __name__ == '__main__':
    main()
