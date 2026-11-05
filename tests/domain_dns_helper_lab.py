#!/usr/bin/env python3
"""Installed-path helper test in disposable user/mount/PID/network namespaces."""

import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import domain_dns_lab as lab

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("EIVRO_TEST_BIN_DIR", ROOT / "target/debug"))


def copy_binary(source, destination, root):
    target = root / destination.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(0o755)
    info = subprocess.run(["ldd", str(source)], capture_output=True, text=True)
    for path in re.findall(r"(/[^\s()]+)", info.stdout):
        if Path(path).is_file():
            dest = root / path.lstrip("/")
            dest.parent.mkdir(parents=True, exist_ok=True)
            if not dest.exists():
                shutil.copy2(path, dest)


def reply(child):
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ)
        if not selector.select(8):
            raise RuntimeError("Helper reply timed out")
        value = child.stdout.readline().decode().strip()
    return value


def send(child, value, expected):
    child.stdin.write(json.dumps(value).encode() + b"\n")
    child.stdin.flush()
    actual = reply(child)
    if not actual:
        child.wait(timeout=2)
        raise RuntimeError(child.stderr.read(4096).decode())
    assert actual == expected, (expected, actual)


def dns(domain):
    query = (
        struct.pack("!HHHHHH", 1234, 256, 1, 0, 0, 0)
        + lab.name(domain)
        + struct.pack("!HH", 1, 1)
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(4)
        s.sendto(query, ("192.0.2.53", 53))
        answer = s.recv(4096)
    assert answer[3] & 15 == 0 and struct.unpack("!H", answer[6:8])[0] > 0
    return socket.inet_ntoa(answer[-4:])


def tcp(address, expected=b"DIRECT"):
    with socket.create_connection((address, 18080), timeout=4) as s:
        s.sendall(b"opaque-helper-probe")
        assert s.recv(64) == expected


def wait_gone():
    deadline = time.monotonic() + 8
    while (
        subprocess.run(["ip", "link", "show", "eivro0"], capture_output=True).returncode
        == 0
    ):
        if time.monotonic() > deadline:
            raise RuntimeError("TUN not removed")
        time.sleep(0.05)


def test(original_net, original_mount):
    assert os.readlink("/proc/self/ns/net") != original_net
    assert os.readlink("/proc/self/ns/mnt") != original_mount
    assert os.geteuid() == 0
    lab.run("ip", "link", "set", "lo", "up")
    server = subprocess.Popen(
        ["unshare", "--net", sys.executable, __file__, "server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    helper = None
    mounts = []
    with tempfile.TemporaryDirectory(prefix="eivro-helper-root-") as directory:
        root = Path(directory)
        root.chmod(0o755)
        try:
            deadline = time.monotonic() + 3
            while os.readlink(f"/proc/{server.pid}/ns/net") == os.readlink(
                "/proc/self/ns/net"
            ):
                assert time.monotonic() < deadline
                time.sleep(0.01)
            lab.run(
                "ip",
                "link",
                "add",
                "work0",
                "type",
                "veth",
                "peer",
                "name",
                "work-peer",
            )
            lab.run("ip", "link", "set", "work-peer", "netns", str(server.pid))
            lab.run("ip", "addr", "add", "10.50.0.1/24", "dev", "work0")
            lab.run("ip", "link", "set", "work0", "up")
            lab.run(
                "ip", "route", "add", "default", "via", "10.50.0.53", "dev", "work0"
            )
            server.stdin.write("start\n")
            server.stdin.flush()
            assert server.stdout.readline().strip() == "ready"
            for binary in ("eivro", "eivro-tun"):
                copy_binary(BIN / binary, "/usr/libexec/eivro/" + binary, root)
            copy_binary(ROOT / "vendor/sing-box", "/usr/libexec/eivro/sing-box", root)
            copy_binary(Path(shutil.which("ip")), "/usr/bin/ip", root)
            copy_binary(Path(shutil.which("sh")), "/bin/sh", root)
            (root / "etc").mkdir()
            (root / "etc/hosts").write_text("10.50.0.53 vpn-endpoint.test\n")
            (root / "etc/nsswitch.conf").write_text("hosts: files\n")
            for path in ["run", "proc", "sys", "dev/net"]:
                (root / path).mkdir(parents=True, exist_ok=True)
            lab.run(
                "mount",
                "-t",
                "tmpfs",
                "-o",
                "mode=755,size=64m",
                "tmpfs",
                str(root / "run"),
            )
            mounts.append(root / "run")
            (root / "run/systemd/resolve").mkdir(parents=True)
            (root / "run/systemd/resolve/io.systemd.Resolve").touch()
            resolver = root / "usr/bin/resolvectl"
            resolver.write_text(
                '#!/bin/sh\nif [ "$1" = flush-caches ]; then printf \'%s\\n\' "$PPID" >> /run/flush-count; else printf "[]"; fi\n'
            )
            resolver.chmod(0o755)

            def flushes():
                path = root / "run/flush-count"
                return (
                    path.read_text().splitlines().count(str(helper.pid))
                    if path.exists()
                    else 0
                )

            lab.run("mount", "--bind", "/proc", str(root / "proc"))
            mounts.append(root / "proc")
            lab.run(
                "mount",
                "-t",
                "sysfs",
                "-o",
                "ro,nosuid,nodev,noexec",
                "sysfs",
                str(root / "sys"),
            )
            mounts.append(root / "sys")
            for device in ["null", "net/tun"]:
                target = root / "dev" / device
                target.touch()
                lab.run("mount", "--bind", "/dev/" + device, str(target))
                mounts.append(target)
            (root / "dev/stdin").symlink_to("/proc/self/fd/0")
            request = {
                "uri": "ss://chacha20-ietf-poly1305:synthetic@vpn-endpoint.test:19999",
                "bypass": [],
                "port": 12080,
                "bridge_port": None,
                "probe_port": None,
                "kill_switch": False,
                "connections": [
                    {
                        "id": 1,
                        "name": "Lab",
                        "interface": "work0",
                        "dns": {"source": "manual", "servers": ["10.50.0.53"]},
                    }
                ],
                "policies": [
                    {
                        "enabled": True,
                        "target": {"kind": "address", "value": "*.company.test"},
                        "action": {"connection": 1},
                    }
                ],
            }

            def start_helper():
                return subprocess.Popen(
                    ["chroot", str(root), "/usr/libexec/eivro/eivro-tun"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "PKEXEC_UID": "0"},
                )

            helper = start_helper()
            send(helper, {"command": "start", "request": request}, "READY")
            assert flushes() == 1, ("startup flush count", flushes())
            original = dns("plain.company.test")
            tcp(original)
            send(
                helper,
                {"command": "stop", "preserve_protection": False, "preserve_dns": True},
                "STOPPED",
            )
            assert flushes() == 1, "Reconnect cleared DNS while the tunnel was down"
            wait_gone()
            server.stdin.write("rotate\n")
            server.stdin.flush()
            assert server.stdout.readline().strip() == "rotated"
            send(helper, {"command": "start", "request": request}, "READY")
            assert dns("plain.company.test") == original
            tcp(original, b"UPDATED")
            print("Helper reconnect: same FakeIP, new real DNS destination", flush=True)
            assert flushes() == 2
            children = (
                Path(f"/proc/{helper.pid}/task/{helper.pid}/children")
                .read_text()
                .split()
            )
            assert len(children) == 1, children
            core_pid = int(children[0])
            assert os.readlink(f"/proc/{core_pid}/ns/net") == os.readlink(
                "/proc/self/ns/net"
            )
            os.kill(core_pid, signal.SIGKILL)
            assert reply(helper) == "FAILED"
            wait_gone()
            send(helper, {"command": "start", "request": request}, "READY")
            assert dns("plain.company.test") == original
            tcp(original, b"UPDATED")
            assert dns("new.company.test") != original
            print("Core crash: no FakeIP reassignment", flush=True)
            helper.kill()
            helper.wait(timeout=3)
            helper = None
            wait_gone()
            helper = start_helper()
            send(helper, {"command": "start", "request": request}, "READY")
            tcp(original, b"UPDATED")
            assert dns("plain.company.test") == original
            print("Helper crash: RAM state survives and old IP still works", flush=True)
            before = flushes()
            send(helper, {"command": "retire"}, "RETIRED")
            wait_gone()
            assert flushes() == before + 1
            cache_files = list((root / "run/eivro-dns").glob("0.cache*"))
            assert len(cache_files) == 1, cache_files
            contents = cache_files[0].read_bytes()
            assert (
                b"plain.company.test" not in contents
                and b"new.company.test" not in contents
            )
            helper.stdin.close()
            assert helper.wait(timeout=4) == 0
            helper = start_helper()
            send(helper, {"command": "start", "request": request}, "READY")
            try:
                with socket.create_connection((original, 18080), timeout=2) as s:
                    s.sendall(b"retired-address-must-not-route")
                    assert not s.recv(64), "Retired FakeIP reached an outbound"
            except OSError:
                pass
            fresh = dns("plain.company.test")
            assert fresh != original, "Retirement reassigned an old address"
            tcp(fresh, b"UPDATED")
            print(
                "Explicit exit: names erased, old IP rejected, new helper retains cursor",
                flush=True,
            )
            before = flushes()
            send(helper, {"command": "stop", "preserve_protection": False}, "STOPPED")
            wait_gone()
            assert flushes() == before + 1, "Disconnect did not invalidate system DNS"
            before = flushes()
            lab.run(
                "ip",
                "route",
                "add",
                "198.18.0.0/15",
                "via",
                "10.50.0.53",
                "dev",
                "work0",
            )
            helper.stdin.write(
                json.dumps({"command": "start", "request": request}).encode() + b"\n"
            )
            helper.stdin.flush()
            failure = reply(helper)
            assert failure.startswith("START_ERROR ") and "DNS" in failure, failure
            assert flushes() == before
            lab.run(
                "ip",
                "route",
                "del",
                "198.18.0.0/15",
                "via",
                "10.50.0.53",
                "dev",
                "work0",
            )
            print(
                "Conflicting range rejected without changing DNS settings", flush=True
            )
            cache_files = list((root / "run/eivro-dns").glob("0.cache*"))
            assert len(cache_files) == 1
            cache = cache_files[0]
            print("Private tmpfs state bytes:", cache.stat().st_size, flush=True)
            assert cache.stat().st_mode & 0o777 == 0o600
            cache.write_bytes(b"")
            helper.stdin.write(
                json.dumps({"command": "start", "request": request}).encode() + b"\n"
            )
            helper.stdin.flush()
            failure = reply(helper)
            assert failure.startswith("START_ERROR ") and "DNS" in failure, failure
            assert (
                subprocess.run(
                    ["ip", "link", "show", "eivro0"], capture_output=True
                ).returncode
                != 0
            )
            print(
                "Live helper rejects externally truncated initialized state", flush=True
            )
            helper.stdin.close()
            assert helper.wait(timeout=4) == 0
            helper = None
        finally:
            if helper is not None:
                lab.stop(helper)
            lab.stop(server)
            for mount in reversed(mounts):
                subprocess.run(["umount", "-l", str(mount)], check=True)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "server":
        lab.server()
    elif len(sys.argv) > 1 and sys.argv[1] == "lab":
        test(sys.argv[2], sys.argv[3])
    else:
        subprocess.run(
            [
                "unshare",
                "--user",
                "--map-root-user",
                "--net",
                "--mount",
                "--pid",
                "--fork",
                "--mount-proc",
                sys.executable,
                __file__,
                "lab",
                os.readlink("/proc/self/ns/net"),
                os.readlink("/proc/self/ns/mnt"),
            ],
            check=True,
        )
