#!/bin/sh
# Rootless Podman locally, Docker on an ephemeral GitHub runner. No host install.
set -eu
cd "$(dirname "$0")/.."
engine=${CONTAINER_ENGINE:-docker}
version=$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["package"]["version"].replace("-", "~"))')
case "${1:-}" in
    debian) image=debian:13-slim; package="eivro_${version}_amd64.deb" ;;
    fedora) image=registry.fedoraproject.org/fedora:44; package="eivro-${version}-1.x86_64.rpm" ;;
    *) echo 'Usage: smoke-container.sh debian|fedora' >&2; exit 1 ;;
esac
# Optional local upgrade fixture, mounted read-only alongside the new package.
upgrade=${EIVRO_UPGRADE_FROM:-}
if [ -n "$upgrade" ]; then
    [ "$upgrade" = "$(basename -- "$upgrade")" ] && [ -f "dist/$upgrade" ]
fi
"$engine" run --rm --security-opt=no-new-privileges --security-opt=label=disable \
    -e "EIVRO_PACKAGE=$package" \
    -e "EIVRO_UPGRADE_FROM=$upgrade" \
    -v "$PWD/dist:/packages:ro" \
    -v "$PWD/scripts/smoke-installed.py:/smoke-installed.py:ro" \
    "$image" sh -eu -c '
      if command -v apt-get >/dev/null; then
        apt-get update
        if [ -n "$EIVRO_UPGRADE_FROM" ]; then
          DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "/packages/$EIVRO_UPGRADE_FROM"
        fi
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "/packages/$EIVRO_PACKAGE" python3 desktop-file-utils
        test "$(dpkg-query -W -f="\${Status}" velum 2>/dev/null || true)" != "install ok installed"
      else
        if [ -n "$EIVRO_UPGRADE_FROM" ]; then
          dnf install -y "/packages/$EIVRO_UPGRADE_FROM"
        fi
        dnf install -y "/packages/$EIVRO_PACKAGE" python3 desktop-file-utils
        ! rpm -q velum
      fi
      python3 /smoke-installed.py
    '
