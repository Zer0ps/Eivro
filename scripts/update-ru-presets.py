#!/usr/bin/env python3
"""Reproduce bundled RU lists from reviewed, pinned data; never runs upstream code."""

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "assets/rules/ru-direct"
RELEASE = "2669fc240bd64bf9692a17d7b828fe9b771112fb"
SOURCE = "0b3f000a30fc753630b0c12a26353b9b6e72a8c7"
LICENSE_SHA256 = "1126322e2cc8d165adc4c792eeb195717de2bcc7b39be1ce77959d78e87ef685"
PINS = {
    "ru-standard.singbox.json": "c5dbccfcb01b62298b35736f86e23ecd1fbac5a491da26c7d5ef99a9a48719b8",
    "ru-full.singbox.json": "02ec2943dca8e3a46d48af7f540d84c789a3dc4d529a1b9bca5e15ecb60e77f4",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def download(ref, name):
    url = f"https://raw.githubusercontent.com/kyoresuas/ru-direct/{ref}/{name}"
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError("Oversized source")
    return data


def parse(data):
    value = json.loads(data)
    if (
        set(value) != {"version", "rules"}
        or value["version"] != 1
        or len(value["rules"]) != 2
    ):
        raise ValueError("Unsupported upstream format")
    networks, domains = value["rules"]
    if set(networks) != {"ip_cidr"} or set(domains) != {"domain_suffix"}:
        raise ValueError("Unexpected upstream rule fields")
    networks = networks["ip_cidr"]
    domains = domains["domain_suffix"]
    if not 1 <= len(networks) <= 16000 or not 1 <= len(domains) <= 4000:
        raise ValueError("Unexpected list size")
    for value in networks:
        network = ipaddress.ip_network(value)
        if not network.is_global or str(network) != value:
            raise ValueError("Non-public or noncanonical network")
    for value in domains:
        if (
            len(value) > 253
            or "." not in value
            or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                for part in value.split(".")
            )
        ):
            raise ValueError("Invalid domain suffix")
    return sorted(set(networks)), sorted(set(domains))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        manifest = json.loads((DEST / "source.json").read_text())
        if (
            manifest["release_commit"] != RELEASE
            or manifest["source_commit"] != SOURCE
            or manifest["upstream_sha256"] != PINS
            or set(manifest["files"])
            != {"domains.txt", "services-ip.txt", "all-ip.txt", "LICENSE"}
        ):
            raise SystemExit("Bundled RU provenance mismatch")
        for name, expected in manifest["files"].items():
            if (
                name not in {"domains.txt", "services-ip.txt", "all-ip.txt", "LICENSE"}
                or sha((DEST / name).read_bytes()) != expected
            ):
                raise SystemExit("Bundled RU data checksum mismatch")
        print("Pinned RU preset assets verified")
        return
    raw = {}
    for name, checksum in PINS.items():
        data = download(RELEASE, name)
        if sha(data) != checksum:
            raise SystemExit("Upstream checksum mismatch")
        raw[name] = data
    service_nets, domains = parse(raw["ru-standard.singbox.json"])
    all_nets, full_domains = parse(raw["ru-full.singbox.json"])
    if domains != full_domains:
        raise SystemExit("Tier domain lists differ; review required")
    license_data = download(SOURCE, "LICENSE")
    if sha(license_data) != LICENSE_SHA256:
        raise SystemExit("Review changed upstream license")
    files = {
        "domains.txt": ("\n".join(domains) + "\n").encode(),
        "services-ip.txt": ("\n".join(service_nets) + "\n").encode(),
        "all-ip.txt": ("\n".join(all_nets) + "\n").encode(),
        "LICENSE": license_data,
    }
    manifest = {
        "repository": "https://github.com/kyoresuas/ru-direct",
        "release_commit": RELEASE,
        "source_commit": SOURCE,
        "snapshot": "2026-11-03",
        "upstream_sha256": PINS,
        "domains": len(domains),
        "services_networks": len(service_nets),
        "all_networks": len(all_nets),
        "files": {name: sha(data) for name, data in files.items()},
    }
    DEST.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (DEST / name).write_bytes(data)
    (DEST / "source.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(
        json.dumps(
            {k: v for k, v in manifest.items() if k not in ("files", "upstream_sha256")}
        )
    )


if __name__ == "__main__":
    main()
