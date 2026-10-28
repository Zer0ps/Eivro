#!/bin/sh
# Rootless Podman locally, Docker on an ephemeral GitHub runner. No host install.
set -eu
cd "$(dirname "$0")/.."
engine=${CONTAINER_ENGINE:-docker}
version=$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["package"]["version"].replace("-", "~"))')
case "${1:-}" in
    debian) image=debian:13-slim; package="velum_${version}_amd64.deb" ;;
    fedora) image=registry.fedoraproject.org/fedora:44; package="velum-${version}-1.x86_64.rpm" ;;
    *) echo 'Usage: smoke-container.sh debian|fedora' >&2; exit 1 ;;
esac
"$engine" run --rm --security-opt=no-new-privileges --security-opt=label=disable \
    -e "VELUM_PACKAGE=$package" \
    -v "$PWD/dist:/packages:ro" \
    -v "$PWD/scripts/smoke-installed.py:/smoke-installed.py:ro" \
    "$image" sh -eu -c '
      if command -v apt-get >/dev/null; then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "/packages/$VELUM_PACKAGE" python3 desktop-file-utils
      else
        dnf install -y "/packages/$VELUM_PACKAGE" python3 desktop-file-utils
      fi
      python3 /smoke-installed.py
    '
