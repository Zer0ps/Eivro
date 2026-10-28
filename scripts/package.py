#!/usr/bin/env python3
"""Build local Linux packages without root, installation, Git changes or publishing."""
import argparse
import hashlib
import io
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
WORK = ROOT / "work/package"
VERSION = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
PACKAGE_VERSION = VERSION.replace("-", "~")
MACHINE = platform.machine()
ARCH = {"x86_64": "amd64", "aarch64": "arm64"}[MACHINE]
BASE = f"velum-{VERSION}-linux-{ARCH}"
BIN_DIR = Path(os.environ.get("VELUM_BIN_DIR", str(ROOT / "target/release")))

def copy(src, dst, mode=None):
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    if mode is not None:
        dst.chmod(mode)

def archive_tree(source, output, prefix=""):
    with tarfile.open(output, "w:gz", compresslevel=9) as archive:
        for path in sorted(source.rglob("*")):
            if not path.is_file() and not path.is_dir():
                continue
            name = str(Path(prefix) / path.relative_to(source))
            info = archive.gettarinfo(path, arcname=name)
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mtime = 0
            # dpkg needs explicit parent directories on a clean installation.
            if path.is_dir():
                archive.addfile(info)
            else:
                with path.open("rb") as f:
                    archive.addfile(info, f)

def create_deb(stage):
    control_dir = WORK / "deb-control"
    control_dir.mkdir(parents=True, exist_ok=True)
    symbols = subprocess.check_output(["readelf", "--version-info", str(BIN_DIR / "velum")], text=True)
    import re
    versions = re.findall(r"GLIBC_(\d+\.\d+)", symbols)
    minimum = max(versions, key=lambda v: tuple(map(int, v.split("."))))
    size = sum(p.stat().st_size for p in stage.rglob("*") if p.is_file()) // 1024
    (control_dir / "control").write_text(f"""Package: velum
Version: {PACKAGE_VERSION}
Section: net
Priority: optional
Architecture: {ARCH}
Maintainer: Velum project <maintainers@velum.invalid>
Installed-Size: {size}
Depends: libc6 (>= {minimum}), libgcc-s1, libgl1, libegl1, libxkbcommon0, libwayland-client0, libx11-6, libxcursor1, libxrandr2, libxi6, polkitd | policykit-1, pkexec | policykit-1, nftables, ca-certificates, iproute2, libglib2.0-bin, gsettings-desktop-schemas, dconf-gsettings-backend
Recommends: xwayland
Description: Native Linux proxy client with local routing policies
 Rust desktop interface with sing-box and Xray, light and dark themes,
 local configuration and no application logging or telemetry.
""")
    sums = []
    for p in sorted(stage.rglob("*")):
        if p.is_file():
            sums.append(f"{hashlib.md5(p.read_bytes()).hexdigest()}  {p.relative_to(stage)}")
    (control_dir / "md5sums").write_text("\n".join(sums) + "\n")
    archive_tree(control_dir, WORK / "control.tar.gz")
    archive_tree(stage, WORK / "data.tar.gz")
    (WORK / "debian-binary").write_text("2.0\n")
    output = DIST / f"velum_{PACKAGE_VERSION}_{ARCH}.deb"
    output.unlink(missing_ok=True)
    subprocess.run(["ar", "rc", str(output), "debian-binary", "control.tar.gz", "data.tar.gz"], cwd=WORK, check=True)

def create_rpm(stage):
    if not shutil.which("rpmbuild"):
        raise SystemExit("RPM requires rpm-build; no complete release was produced")
    top = WORK / "rpmbuild"
    for d in ("BUILD", "BUILDROOT", "RPMS", "SOURCES", "SPECS", "SRPMS", "tmp"):
        (top / d).mkdir(parents=True, exist_ok=True)
    spec = top / "SPECS/velum.spec"
    spec.write_text(f"""Name: velum
Version: {PACKAGE_VERSION}
Release: 1
Summary: Native Linux proxy client with no application logs
License: GPL-3.0-or-later
BuildArch: {MACHINE}
Requires: polkit, nftables, ca-certificates, iproute, glib2, gsettings-desktop-schemas, dconf, libGL, libEGL, libxkbcommon, libwayland-client, libX11, libXcursor, libXrandr, libXi
Recommends: xorg-x11-server-Xwayland
%global debug_package %{{nil}}
%global __os_install_post %{{nil}}
%description
Rust desktop client with sing-box, Xray and editable direct-routing policies.
%prep
%build
%install
mkdir -p "%{{buildroot}}"
cp -a "{stage}/." "%{{buildroot}}/"
%files
%attr(0755,root,root) /usr/bin/velum
%dir %attr(0755,root,root) /usr/libexec/velum
%attr(0755,root,root) /usr/libexec/velum/velum
%attr(0755,root,root) /usr/libexec/velum/velum-tun
%attr(0755,root,root) /usr/libexec/velum/sing-box
%attr(0755,root,root) /usr/libexec/velum/xray
/usr/share/applications/io.velum.Client.desktop
/usr/share/icons/hicolor/scalable/apps/io.velum.Client.svg
/usr/share/polkit-1/actions/io.velum.tun.policy
/usr/share/doc/velum
/usr/share/licenses/velum
""")
    subprocess.run(["rpmbuild", "-bb", "--define", f"_topdir {top}", "--define", f"_tmppath {top / 'tmp'}", "--define", "source_date_epoch_from_changelog 0", str(spec)], check=True)
    for p in (top / "RPMS").rglob("*.rpm"):
        copy(p, DIST / p.name)

def create_appimage(portable):
    if MACHINE != "x86_64":
        print("AppImage skipped: build tool is pinned for x86_64")
        return
    tool = ROOT / ".tools/appimagetool/AppRun"
    runtime = ROOT / ".tools/runtime-x86_64"
    if not tool.exists() or not runtime.exists():
        raise SystemExit("Run python3 scripts/fetch-appimage-tools.py for the AppImage build")
    appdir = WORK / "Velum.AppDir"
    appdir.mkdir(exist_ok=True)
    for p in portable.iterdir():
        if p.is_file():
            copy(p, appdir / p.name)
        elif p.is_dir():
            shutil.copytree(p, appdir / p.name, dirs_exist_ok=True)
    copy(ROOT / "assets/io.velum.Client.svg", appdir / "io.velum.Client.svg")
    copy(ROOT / "packaging/io.velum.Client.desktop", appdir / "io.velum.Client.desktop")
    (appdir / "AppRun").write_text('#!/bin/sh\nset -eu\nAPPDIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"\nexec "$APPDIR/velum" "$@"\n')
    (appdir / "AppRun").chmod(0o755)
    subprocess.run([str(tool), "--no-appstream", "--runtime-file", str(runtime), str(appdir), str(DIST / f"Velum-{VERSION}-{MACHINE}.AppImage")], env={**os.environ, "ARCH": MACHINE}, check=True)

def create_source():
    # Explicit whitelist: never ship work/, local tools, credentials or profiles.
    names = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".gitignore",
             ".github", "src", "tests", "scripts", "docs", "assets", "packaging",
             "examples", "README.md", "PRIVACY.md", "LICENSE", "THIRD_PARTY.md",
             "start.sh", "Velum.desktop", "vendor/LICENSE", "vendor/xray.LICENSE"]
    with tarfile.open(DIST / f"velum-{VERSION}-source.tar.gz", "w:gz", compresslevel=9) as archive:
        for name in names:
            item = ROOT / name
            for path in sorted(item.rglob("*")) if item.is_dir() else [item]:
                if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
                    continue
                info = archive.gettarinfo(path, arcname=f"velum-{VERSION}-source/{path.relative_to(ROOT)}")
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = 0
                with path.open("rb") as stream:
                    archive.addfile(info, stream)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-appimage", action="store_true")
    args = parser.parse_args()
    # Direct packaging must reject an old cached core just like the build script.
    subprocess.run([sys.executable, str(ROOT / "scripts/fetch-core.py"), "--check"], check=True)
    subprocess.run([sys.executable, str(ROOT / "scripts/fetch-xray.py"), "--check"], check=True)
    try:
        helper_version = subprocess.run(
            [str(BIN_DIR / "velum-tun"), "--version"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise SystemExit("Missing or unusable Velum helper; run scripts/build.sh first")
    if helper_version.returncode or helper_version.stdout != f"Velum TUN {VERSION}\n".encode():
        raise SystemExit(f"Expected Velum {VERSION} binaries; run scripts/build.sh first")
    app_version = subprocess.check_output([str(BIN_DIR / "velum"), "--version"], timeout=10)
    if app_version != f"Velum {VERSION}\n".encode():
        raise SystemExit("Application and helper versions differ")
    DIST.mkdir(exist_ok=True)
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    portable = WORK / BASE
    stage = WORK / "stage"
    for name in ("velum", "velum-tun"):
        copy(BIN_DIR / name, stage / f"usr/libexec/velum/{name}", 0o755)
    for name in ("sing-box", "xray"):
        copy(ROOT / f"vendor/{name}", stage / f"usr/libexec/velum/{name}", 0o755)
    for name in ("velum", "sing-box", "xray"):
        copy(stage / f"usr/libexec/velum/{name}", portable / name, 0o755)
    for name in ("README.md", "PRIVACY.md", "LICENSE", "THIRD_PARTY.md"):
        copy(ROOT / name, portable / name, 0o644)
    copy(ROOT / "docs/VERIFICATION.md", portable / "docs/VERIFICATION.md", 0o644)
    copy(ROOT / "vendor/LICENSE", portable / "sing-box.LICENSE", 0o644)
    copy(ROOT / "vendor/xray.LICENSE", portable / "xray.LICENSE", 0o644)
    copy(ROOT / "assets/NotoEmoji.LICENSE", portable / "NotoEmoji.LICENSE", 0o644)
    copy(ROOT / "packaging/io.velum.Client.desktop", stage / "usr/share/applications/io.velum.Client.desktop", 0o644)
    copy(ROOT / "assets/io.velum.Client.svg", stage / "usr/share/icons/hicolor/scalable/apps/io.velum.Client.svg", 0o644)
    copy(ROOT / "packaging/io.velum.tun.policy", stage / "usr/share/polkit-1/actions/io.velum.tun.policy", 0o644)
    for name in ("README.md", "PRIVACY.md", "THIRD_PARTY.md"):
        copy(ROOT / name, stage / f"usr/share/doc/velum/{name}", 0o644)
    copy(ROOT / "docs/VERIFICATION.md", stage / "usr/share/doc/velum/docs/VERIFICATION.md", 0o644)
    copy(ROOT / "LICENSE", stage / "usr/share/licenses/velum/LICENSE", 0o644)
    copy(ROOT / "vendor/LICENSE", stage / "usr/share/licenses/velum/sing-box.LICENSE", 0o644)
    copy(ROOT / "vendor/xray.LICENSE", stage / "usr/share/licenses/velum/xray.LICENSE", 0o644)
    copy(ROOT / "assets/NotoEmoji.LICENSE", stage / "usr/share/licenses/velum/NotoEmoji.LICENSE", 0o644)
    launcher = stage / "usr/bin/velum"
    launcher.parent.mkdir(parents=True)
    launcher.write_text('#!/bin/sh\nexec /usr/libexec/velum/velum "$@"\n')
    launcher.chmod(0o755)
    archive_tree(portable, DIST / f"{BASE}.tar.gz", BASE)
    create_deb(stage)
    create_rpm(stage)
    if not args.skip_appimage:
        create_appimage(portable)
    create_source()
    outputs = [DIST / f"velum_{PACKAGE_VERSION}_{ARCH}.deb",
               DIST / f"velum-{PACKAGE_VERSION}-1.{MACHINE}.rpm",
               DIST / f"{BASE}.tar.gz", DIST / f"velum-{VERSION}-source.tar.gz"]
    if not args.skip_appimage and MACHINE == "x86_64":
        outputs.append(DIST / f"Velum-{VERSION}-{MACHINE}.AppImage")
    (DIST / "SHA256SUMS").write_text("".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in outputs))
    for p in outputs:
        print(f"{p.name}: {p.stat().st_size / 1024 / 1024:.1f} MiB")

if __name__ == "__main__":
    main()
