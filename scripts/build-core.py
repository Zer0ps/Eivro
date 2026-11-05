#!/usr/bin/env python3
"""Build the pinned Linux core and its reviewed FakeIP patch; no system installs."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
PIN = json.loads((ROOT / "patches/sing-box/source.json").read_text())


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def fetch(url, path, checksum):
    if path.is_file() and digest(path) == checksum:
        return
    temporary = path.with_suffix(".download")
    try:
        with urllib.request.urlopen(url, timeout=60) as response, temporary.open(
            "wb"
        ) as output:
            total = 0
            while block := response.read(1024 * 1024):
                total += len(block)
                if total > 256 * 1024 * 1024:
                    raise RuntimeError("Unexpected archive size")
                output.write(block)
        if digest(temporary) != checksum:
            raise RuntimeError("Archive checksum mismatch")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".tools/patched-core")
    parser.add_argument(
        "--output", type=Path, default=ROOT / "work/fakeip-core/sing-box"
    )
    args = parser.parse_args()
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if platform.system() != "Linux" or arch is None:
        raise SystemExit("Build natively on Linux x86_64 or arm64")
    patch = ROOT / "patches/sing-box/fakeip-allocation.patch"
    if digest(patch) != PIN["patch_sha256"]:
        raise SystemExit("Patch checksum mismatch")
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    sdk = f"go{PIN['go_version']}.linux-{arch}.tar.gz"
    fetch(
        "https://go.dev/dl/" + sdk, work / "go.tar.gz", PIN[f"go_linux_{arch}_sha256"]
    )
    fetch(PIN["source_url"], work / "source.tar.gz", PIN["source_sha256"])
    # Re-extract source into a fresh directory: patches must never accumulate.
    import tempfile

    with tempfile.TemporaryDirectory(prefix="source-", dir=work) as directory:
        source_root = Path(directory)
        with tarfile.open(work / "source.tar.gz") as archive:
            archive.extractall(source_root, filter="data")
        source = source_root / ("sing-box-" + PIN["commit"])
        if not (work / "go/bin/go").is_file():
            with tarfile.open(work / "go.tar.gz") as archive:
                archive.extractall(work, filter="data")
        env = os.environ.copy()
        env.update(
            {
                "GOROOT": str(work / "go"),
                "GOTOOLCHAIN": "local",
                "GOENV": "off",
                "GOPATH": str(work / "go-work"),
                "GOMODCACHE": str(work / "go-mod"),
                "GOCACHE": str(work / "go-cache"),
                "CGO_ENABLED": "0",
                "GOPROXY": "https://proxy.golang.org",
                "GOSUMDB": "sum.golang.org",
            }
        )
        go = str(work / "go/bin/go")
        expected_go = f"go version go{PIN['go_version']} linux/{arch}"
        if (
            subprocess.check_output([go, "version"], env=env, text=True).strip()
            != expected_go
        ):
            raise RuntimeError("Cached Go toolchain does not match the pinned version")
        env.update(
            {
                "GOPRIVATE": "",
                "GONOPROXY": "",
                "GONOSUMDB": "",
                "GOFLAGS": "",
                "GOOS": "linux",
                "GOARCH": arch,
                "GOAMD64": "v1",
                "GOARM64": "v8.0",
                "GOEXPERIMENT": "",
            }
        )
        subprocess.run(
            ["patch", "--batch", "--forward", "-p1", "-i", str(patch)],
            cwd=source,
            check=True,
        )
        subprocess.run(
            [
                go,
                "test",
                "-p",
                "4",
                "-mod=readonly",
                "./dns/transport/fakeip",
                "./experimental/cachefile",
            ],
            cwd=source,
            env=env,
            check=True,
        )
        candidate = work / "sing-box.candidate"
        subprocess.run(
            [
                go,
                "build",
                "-p",
                "4",
                "-mod=readonly",
                "-buildvcs=false",
                "-trimpath",
                "-tags",
                PIN["tags"],
                "-ldflags",
                "-s -w -X github.com/sagernet/sing-box/constant.Version="
                + PIN["version"],
                "-o",
                str(candidate),
                "./cmd/sing-box",
            ],
            cwd=source,
            env=env,
            check=True,
        )
        version = subprocess.check_output(
            [str(candidate), "version", "-n"], text=True
        ).strip()
        if version != PIN["version"]:
            raise RuntimeError("Unexpected built version")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        import shutil

        staged = args.output.with_suffix(".candidate")
        shutil.copyfile(candidate, staged)
        staged.chmod(0o755)
        staged.replace(args.output)
        if args.output.resolve().parent == (ROOT / "vendor").resolve():
            shutil.copyfile(source / "LICENSE", ROOT / "vendor/LICENSE")
        print(f"Verified {version}: {digest(args.output)}")


if __name__ == "__main__":
    main()
