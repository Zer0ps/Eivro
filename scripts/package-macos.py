#!/usr/bin/env python3
"""Build an installer without installing it or changing the host's networking."""
import hashlib
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
    work = ROOT / 'work/package-macos'
    if work.exists():
        shutil.rmtree(work)
    stage = work / 'root'
    app = stage / 'Applications/Eivro.app/Contents'
    helper = stage / 'Library/PrivilegedHelperTools/io.eivro'
    for name in ('eivro', 'sing-box', 'xray'):
        copy(ROOT / ('target/release' if name == 'eivro' else 'vendor') / name, app / 'MacOS' / name, 0o755)
    for name in ('eivro-tun', 'sing-box', 'xray'):
        copy(ROOT / ('target/release' if name == 'eivro-tun' else 'vendor') / name, helper / name, 0o755)
    info = {
        'CFBundleExecutable': 'eivro', 'CFBundleIdentifier': 'io.eivro.Client',
        'CFBundleName': 'Eivro', 'CFBundleDisplayName': 'Eivro', 'CFBundlePackageType': 'APPL',
        'CFBundleShortVersionString': VERSION, 'CFBundleVersion': VERSION,
        'LSMinimumSystemVersion': '13.0', 'NSHighResolutionCapable': True,
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
    dist = ROOT / 'dist'
    dist.mkdir(exist_ok=True)
    package = dist / f'Eivro-{VERSION}-macos-{machine}.pkg'
    run('pkgbuild', '--root', stage, '--identifier', 'io.eivro.pkg', '--version', VERSION,
        '--install-location', '/', '--ownership', 'recommended', '--scripts', ROOT / 'packaging/macos/scripts', package)
    image_root = work / 'image'
    image_root.mkdir()
    copy(package, image_root / package.name)
    (image_root / 'Read me.txt').write_text('Eivro for macOS 13 or later.\nOpen the .pkg installer, then launch Eivro from Applications.\nThis preview is ad-hoc signed, not notarized by Apple.\nVPN, DNS recovery and energy use require validation on a Mac before a stable macOS release.\n')
    dmg = dist / f'Eivro-{VERSION}-macos-{machine}.dmg'
    # hdiutil's automatic source-folder sizing can leave too little room for a
    # large PKG on the temporary filesystem. Empty space compresses away in UDZO.
    payload = sum(p.stat().st_size for p in image_root.iterdir() if p.is_file())
    image_mib = (payload + 1024 * 1024 - 1) // (1024 * 1024) + 64
    print(f'DMG volume: {image_mib} MiB; host free: {shutil.disk_usage(work).free // (1024 * 1024)} MiB', flush=True)
    run('hdiutil', 'create', '-ov', '-format', 'UDZO', '-fs', 'HFS+',
        '-size', f'{image_mib}m', '-volname', 'Eivro', '-srcfolder', image_root, dmg)
    checksums = dist / f'SHA256SUMS-macos-{machine}'
    checksums.write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in (package, dmg)))
    print(package)
    print(dmg)

if __name__ == '__main__':
    main()
