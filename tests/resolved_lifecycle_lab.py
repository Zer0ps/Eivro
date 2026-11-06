#!/usr/bin/env python3
"""Opt-in real resolved/D-Bus test, ONLY inside a disposable container.

Requires /qa/sing-box and /qa/tun.json (from network-lab-config tun).
The deliberately unsafe legacy probe only targets this container's private bus.
No host mounts, host networking, or host D-Bus socket may be passed to it.
"""

import itertools
import json
import os
import pwd
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

import isolated_linux


def run(*args, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=8)
    if check and result.returncode:
        raise RuntimeError(f"{args}: {result.stderr}")
    return result


def wait_for(check):
    deadline = time.monotonic() + 6
    while not check():
        assert time.monotonic() < deadline, "DNS service did not reach expected state"
        time.sleep(0.05)


def servers(link):
    result = run("resolvectl", "--json=short", "dns", check=False)
    if result.returncode:
        return None
    return next(
        (
            row.get("servers") or []
            for row in json.loads(result.stdout)
            if row.get("ifname") == link
        ),
        [],
    )


def dns_fixture(address):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((address, 53))
    while True:
        packet, peer = sock.recvfrom(4096)
        end = 12
        while packet[end]:
            end += packet[end] + 1
        end += 5
        kind = struct.unpack("!H", packet[end - 4 : end - 2])[0]
        answer = b""
        if kind == 1:
            answer = (
                b"\xc0\x0c"
                + struct.pack("!HHIH", 1, 1, 0, 4)
                + socket.inet_aton("203.0.113.42")
            )
        sock.sendto(
            packet[:2]
            + struct.pack("!HHHHH", 0x8180, 1, int(bool(answer)), 0, 0)
            + packet[12:end]
            + answer,
            peer,
        )


def query():
    data = run(
        "resolvectl",
        "--cache=no",
        "--type=A",
        "--json=short",
        "query",
        "health.lab.test",
    ).stdout
    return json.loads(data.splitlines()[-1])["address"]


def collision(index, blocked):
    if blocked:
        isolated_linux.require_runtime_isolation()
    assert (
        Path("/run/.containerenv").exists() or blocked
    ), "Legacy probe is container-only"
    assert index < 32
    while True:
        name = "probe" + str(len(json.loads(run("ip", "-j", "link").stdout)))
        run("ip", "link", "add", name, "type", "dummy")
        actual = json.loads(run("ip", "-j", "link", "show", name).stdout)[0]["ifindex"]
        if actual == index:
            break
        assert actual < index
    result = run("resolvectl", "revert", name, check=False)
    assert (result.returncode != 0) == blocked, result.stderr


def main():
    assert Path("/run/.containerenv").exists(), "Do not run on the host"
    assert {link["ifname"] for link in json.loads(run("ip", "-j", "link").stdout)} == {
        "lo"
    }, "Use a fresh container with --network=none"
    assert not Path(
        "/run/dbus/system_bus_socket"
    ).exists(), "Use a fresh private test bus"
    Path("/run/dbus").mkdir(exist_ok=True)
    machine_id = Path("/etc/machine-id")
    if not machine_id.exists() or not machine_id.read_text().strip():
        machine_id.write_text(os.urandom(16).hex() + "\n")
    Path("/run/systemd/resolve").mkdir(parents=True, exist_ok=True)
    user = pwd.getpwnam("systemd-resolve")
    os.chown("/run/systemd/resolve", user.pw_uid, user.pw_gid)
    Path("/etc/systemd").mkdir(exist_ok=True)
    Path("/etc/systemd/resolved.conf").write_text(
        "[Resolve]\nFallbackDNS=\nDNSSEC=no\nLLMNR=no\nMulticastDNS=no\n"
    )
    Path("/qa/bus.conf").write_text("""<busconfig><type>system</type>
<listen>unix:path=/run/dbus/system_bus_socket</listen><auth>EXTERNAL</auth>
<policy context="default"><allow user="root"/><allow user="systemd-resolve"/><allow own="*"/><allow send_destination="*"/>
<allow receive_sender="*"/></policy></busconfig>""")
    os.environ["DBUS_SYSTEM_BUS_ADDRESS"] = "unix:path=/run/dbus/system_bus_socket"
    children = []
    core = None
    with tempfile.TemporaryFile() as log:
        try:
            bus = subprocess.Popen(
                [
                    "dbus-daemon",
                    "--nofork",
                    "--nopidfile",
                    "--config-file=/qa/bus.conf",
                ],
                stdout=log,
                stderr=log,
            )
            children.append(bus)
            wait_for(lambda: Path("/run/dbus/system_bus_socket").exists())
            resolved = subprocess.Popen(
                ["/usr/lib/systemd/systemd-resolved"],
                stdout=log,
                stderr=log,
                env={
                    **os.environ,
                    "SYSTEMD_LOG_TARGET": "console",
                    "SYSTEMD_LOG_LEVEL": "notice",
                },
            )
            children.append(resolved)
            wait_for(lambda: servers("lab-up") is not None)
            for link, addr in [("lab-up", "192.0.2.1/24"), ("work0", "10.50.0.1/24")]:
                run("ip", "link", "add", link, "type", "dummy")
                run("ip", "addr", "add", addr, "dev", link)
                run("ip", "link", "set", link, "up")
            run("ip", "route", "add", "default", "via", "192.0.2.254", "dev", "lab-up")
            for link, addr in [("lab-up", "192.0.2.53"), ("work0", "10.50.0.53")]:
                run("ip", "addr", "add", addr + "/32", "dev", link)
                threading.Thread(target=dns_fixture, args=(addr,), daemon=True).start()
            wait_for(
                lambda: run(
                    "resolvectl", "dns", "lab-up", "192.0.2.53", check=False
                ).returncode
                == 0
            )
            run("resolvectl", "default-route", "lab-up", "true")
            baseline = servers("lab-up")
            assert baseline
            index = json.loads(run("ip", "-j", "link", "show", "lab-up").stdout)[0][
                "ifindex"
            ]
            run(
                "unshare",
                "--net",
                sys.executable,
                __file__,
                "collision",
                str(index),
                "legacy",
            )
            assert not servers(
                "lab-up"
            ), "Legacy shared D-Bus failure did not reproduce"
            print(
                "Confirmed: legacy netns-only probe erased parent-link DNS through shared D-Bus",
                flush=True,
            )
            run("resolvectl", "dns", "lab-up", "192.0.2.53")
            # The outer container already supplies private user/PID namespaces.
            # Its masked /proc cannot be remounted in a nested user namespace.
            run(
                "unshare",
                "--net",
                "--mount",
                sys.executable,
                isolated_linux.__file__,
                os.readlink("/proc/self/ns/net"),
                os.readlink("/proc/self/ns/mnt"),
                __file__,
                "collision",
                str(index),
                "blocked",
            )
            assert servers("lab-up") == baseline
            print(
                "Private /run blocks the same ifindex collision; parent DNS survives",
                flush=True,
            )
            config = Path("/qa/tun.json").read_bytes()

            def start(name):
                nonlocal core
                if name == "eivro":
                    core = subprocess.Popen(
                        ["/qa/sing-box", "run", "-c", "/dev/stdin"],
                        stdin=subprocess.PIPE,
                        stdout=log,
                        stderr=log,
                    )
                    core.stdin.write(config)
                    core.stdin.close()

                    def ready():
                        assert core.poll() is None, f"Core exited: {core.returncode}"
                        return bool(servers("eivro0"))

                    wait_for(ready)
                else:
                    # Same link-scoped calls as vpnc-script's resolved backend.
                    run("resolvectl", "dns", "work0", "10.50.0.53")
                    run("resolvectl", "domain", "work0", "partner.test")

            def stop(name):
                nonlocal core
                if name == "eivro":
                    core.terminate()
                    core.wait(timeout=5)
                    core = None
                    wait_for(lambda: not servers("eivro0"))
                else:
                    run("resolvectl", "revert", "work0")

            for starting, stopping in itertools.product(
                itertools.permutations(["eivro", "work"]), repeat=2
            ):
                assert query() == [203, 0, 113, 42]
                for name in starting:
                    start(name)
                    assert servers("lab-up") == baseline
                assert query()[:2] == [198, 18]
                for name in stopping:
                    stop(name)
                    assert servers("lab-up") == baseline
                assert query() == [203, 0, 113, 42]
                print(
                    f"Start {starting}, stop {stopping}: underlay DNS unchanged, resolution restored",
                    flush=True,
                )
            start("eivro")
            core.kill()
            core.wait(timeout=5)
            core = None
            wait_for(lambda: not servers("eivro0"))
            assert servers("lab-up") == baseline and query() == [203, 0, 113, 42]
            print(
                "Core crash: physical-link DNS and ordinary resolution survive",
                flush=True,
            )
        except Exception:
            log.seek(0)
            print(log.read().decode(errors="replace")[-6000:])
            raise
        finally:
            if core is not None:
                core.kill()
                core.wait(timeout=5)
            for child in reversed(children):
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            for link in ("lab-up", "work0"):
                run("ip", "link", "del", link, check=False)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "collision":
        collision(int(sys.argv[2]), sys.argv[3] == "blocked")
    else:
        main()
