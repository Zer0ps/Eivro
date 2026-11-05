#!/usr/bin/env python3
"""Synthetic DNS-to-IP review. Every interface/route exists only inside unshare -Urn."""

import json, os, socket, struct, subprocess, sys, threading, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    r = subprocess.run(args, capture_output=True)
    if r.returncode:
        raise RuntimeError(str(args) + ": " + r.stderr.decode())
    return r


def name(s):
    return b"".join(bytes([len(x)]) + x.encode() for x in s.split(".")) + b"\0"


def exact(s, n):
    data = b""
    while len(data) < n:
        part = s.recv(n - len(data))
        if not part:
            raise RuntimeError("unexpected EOF")
        data += part
    return data


def stop(p):
    p.terminate()
    try:
        p.wait(timeout=3)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait(timeout=3)


def server():
    input()
    run("ip", "link", "set", "lo", "up")
    for ip in (
        "10.50.0.53",
        "198.51.100.99",
        "198.51.100.98",
        "198.51.100.97",
        "198.51.100.96",
        "5.45.192.1",
        "5.45.193.1",
        "2.56.24.1",
    ):
        run(
            "ip",
            "addr",
            "add",
            ip + ("/24" if ip == "10.50.0.53" else "/32"),
            "dev",
            "work-peer" if ip == "10.50.0.53" else "lo",
        )
    run("ip", "link", "set", "work-peer", "up")
    queries = []
    rotated = False

    def dns(port, label):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("10.50.0.53", port))
        while True:
            b, peer = s.recvfrom(4096)
            pos = 12
            labels = []
            while b[pos]:
                size = b[pos]
                labels.append(b[pos + 1 : pos + size + 1].decode())
                pos += size + 1
            end = pos + 5
            q = ".".join(labels)
            kind = struct.unpack("!H", b[pos + 1 : pos + 3])[0]
            queries.append([label, q])
            answer = b""
            count = 0
            if kind == 1:
                ip = (
                    "198.51.100.98"
                    if q.startswith("alias.")
                    else (
                        "198.51.100.97"
                        if q
                        in ("shared.company.test", "shared.2gis.com", "other.cdn.test")
                        else "198.51.100.99"
                    )
                )
                if rotated and q == "plain.company.test":
                    ip = "198.51.100.96"
                if q == "foreign-with-ru-ip.test":
                    ip = "5.45.193.1"
                if q == "foreign-with-full-ru-ip.test":
                    ip = "2.56.24.1"
                owner = b"\xc0\x0c"
                if q.startswith("alias."):
                    canonical = name("canonical.cdn.test")
                    answer = (
                        owner
                        + struct.pack("!HHIH", 5, 1, 60, len(canonical))
                        + canonical
                    )
                    owner = canonical
                    count += 1
                answer += (
                    owner + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
                )
                count += 1
            s.sendto(
                b[:2]
                + struct.pack("!HHHHH", 0x8180, 1, count, 0, 0)
                + b[12:end]
                + answer,
                peer,
            )

    def handle(s, proxy):
        try:
            s.settimeout(5)
            if proxy:
                h = exact(s, 2)
                exact(s, h[1])
                s.sendall(b"\5\0")
                h = exact(s, 4)
                exact(s, 4 if h[3] == 1 else 16 if h[3] == 4 else exact(s, 1)[0])
                exact(s, 2)
                if h[1] == 3:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay:
                        relay.bind(("10.50.0.53", 0))
                        relay.settimeout(4)
                        s.sendall(
                            b"\5\0\0\1"
                            + socket.inet_aton("10.50.0.53")
                            + struct.pack("!H", relay.getsockname()[1])
                        )
                        try:
                            while True:
                                packet, peer = relay.recvfrom(4096)
                                size = (
                                    4
                                    if packet[3] == 1
                                    else 16 if packet[3] == 4 else packet[4] + 1
                                )
                                relay.sendto(packet[: 6 + size] + b"PROXY", peer)
                        except TimeoutError:
                            pass
                    return
                s.sendall(b"\5\0\0\1\0\0\0\0\0\0")
            s.recv(4096)
            s.sendall(
                b"PROXY"
                if proxy
                else b"UPDATED" if s.getsockname()[0] == "198.51.100.96" else b"DIRECT"
            )
        finally:
            s.close()

    def udp():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", 18082))
        while True:
            _, peer = s.recvfrom(4096)
            s.sendto(b"DIRECT", peer)

    threading.Thread(target=udp, daemon=True).start()

    def tcp(addr, port, proxy):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((addr, port))
        s.listen()
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle, args=(c, proxy), daemon=True).start()

    for port, label in ((53, "exception-dns"), (5353, "default-dns")):
        threading.Thread(target=dns, args=(port, label), daemon=True).start()
    for addr, port, proxy in (("0.0.0.0", 18080, False), ("10.50.0.53", 19081, True)):
        threading.Thread(target=tcp, args=(addr, port, proxy), daemon=True).start()
    print("ready", flush=True)
    for line in sys.stdin:
        if line.strip() == "stats":
            print(json.dumps(queries), flush=True)
        elif line.strip() == "rotate":
            rotated = True
            print("rotated", flush=True)
        else:
            break


def lab(original, policy):
    proxy_mode = policy.endswith("-proxy")
    base_policy = policy.removesuffix("-proxy")
    assert os.readlink("/proc/self/ns/net") != original
    run("ip", "link", "set", "lo", "up")
    child = subprocess.Popen(
        ["unshare", "--net", sys.executable, __file__, "server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    core = None
    try:
        deadline = time.monotonic() + 3
        while os.readlink(f"/proc/{child.pid}/ns/net") == os.readlink(
            "/proc/self/ns/net"
        ):
            assert time.monotonic() < deadline
            time.sleep(0.01)
        run("ip", "link", "add", "work0", "type", "veth", "peer", "name", "work-peer")
        run("ip", "link", "set", "work-peer", "netns", str(child.pid))
        run("ip", "addr", "add", "10.50.0.1/24", "dev", "work0")
        run("ip", "link", "set", "work0", "up")
        run("ip", "route", "add", "default", "via", "10.50.0.53", "dev", "work0")
        child.stdin.write("start\n")
        child.stdin.flush()
        assert child.stdout.readline().strip() == "ready"
        base = json.loads(
            run(
                str(ROOT / "target/debug/examples/network-lab-config"),
                *([] if proxy_mode else ["tun"]),
                *([base_policy] if policy.startswith("preset-") else []),
                *(
                    ["direct"]
                    if policy == "direct"
                    else (
                        ["cidr"]
                        if policy == "cidr"
                        else (
                            [
                                "cidr",
                                "application=" + str(Path(sys.executable).resolve()),
                            ]
                            if policy == "application"
                            else ["unavailable"] if policy == "unavailable" else []
                        )
                    )
                ),
            ).stdout
        )
        # Same generated policy, sniff/reverse-mapping logic. Only upstreams are local fixtures.
        base["outbounds"][0] = {
            "type": "socks",
            "tag": "proxy",
            "server": "10.50.0.53",
            "server_port": 19081,
            "version": "5",
        }
        base["dns"]["servers"][1] = {
            "type": "udp",
            "tag": "direct-dns",
            "server": "10.50.0.53",
            "bind_interface": "work0",
        }
        base["dns"]["servers"][2] = {
            "type": "udp",
            "tag": "proxy-dns",
            "server": "10.50.0.53",
            "server_port": 5353,
            "bind_interface": "work0",
        }

        def start(config):
            p = subprocess.Popen(
                [str(ROOT / "vendor/sing-box"), "run", "-c", "/dev/stdin"],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            p.stdin.write(json.dumps(config).encode())
            p.stdin.close()
            deadline = time.monotonic() + 4
            while True:
                if p.poll() is not None:
                    raise RuntimeError(p.stderr.read().decode())
                if proxy_mode:
                    try:
                        with socket.create_connection(
                            ("127.0.0.1", 12080), timeout=0.1
                        ):
                            break
                    except OSError:
                        assert time.monotonic() < deadline
                        time.sleep(0.02)
                    continue
                if (
                    subprocess.run(
                        ["ip", "link", "show", "eivro0"], capture_output=True
                    ).returncode
                    == 0
                ):
                    break
                assert time.monotonic() < deadline
                time.sleep(0.02)
            time.sleep(0.15)
            return p

        def query(domain, kind=1):
            packet = (
                struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
                + name(domain)
                + struct.pack("!HH", kind, 1)
            )
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(3)
                s.sendto(packet, ("192.0.2.53", 53))
                reply = s.recv(4096)
            assert reply[:2] == b"\x12\x34" and reply[3] & 15 == 0
            return (
                socket.inet_ntoa(reply[-4:])
                if kind == 1
                else socket.inet_ntop(socket.AF_INET6, reply[-16:])
            )

        def connect(ip, payload=b"opaque-lab-payload\n"):
            with socket.create_connection(
                ("127.0.0.1", 12080) if proxy_mode else (ip, 18080), timeout=4
            ) as s:
                if proxy_mode:
                    s.sendall(b"\5\1\0")
                    assert exact(s, 2) == b"\5\0"
                    try:
                        destination = b"\1" + socket.inet_aton(ip)
                    except OSError:
                        destination = b"\3" + bytes([len(ip)]) + ip.encode()
                    s.sendall(b"\5\1\0" + destination + struct.pack("!H", 18080))
                    header = exact(s, 4)
                    assert header[1] == 0, header
                    exact(
                        s,
                        (
                            4
                            if header[3] == 1
                            else 16 if header[3] == 4 else exact(s, 1)[0]
                        ),
                    )
                    exact(s, 2)
                s.sendall(payload)
                return s.recv(128).decode()

        def packet(ip):
            with socket.socket(
                socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_DGRAM
            ) as s:
                s.settimeout(4)
                s.sendto(b"eivro-opaque-udp", (ip, 18082))
                return s.recv(128).decode()

        def observe(label, actual, expected):
            print(label + ": " + actual, flush=True)
            assert actual == expected, (label, actual, expected)

        for mode in (policy,):
            cfg = json.loads(json.dumps(base))
            core = start(cfg)
            print("GENERATED TUN POLICY " + mode, flush=True)
            first_route = "PROXY" if mode in ("cidr", "application") else "DIRECT"
            domain_route = "PROXY" if mode == "application" else "DIRECT"
            observe("No observed DNS, IP only", connect("198.51.100.99"), "PROXY")
            if mode.startswith("preset-"):
                for host, expected in [
                    ("2gis.com", "DIRECT"),
                    ("alias.2gis.com", "DIRECT"),
                    ("shared.2gis.com", "DIRECT"),
                    ("other.cdn.test", "PROXY"),
                    ("override.2gis.com", "PROXY"),
                    ("0rub.beeline.ru", "PROXY"),
                    ("beeline.ru", "DIRECT"),
                    ("foreign-with-ru-ip.test", "DIRECT"),
                    (
                        "foreign-with-full-ru-ip.test",
                        "DIRECT" if base_policy == "preset-all" else "PROXY",
                    ),
                ]:
                    observe(
                        host, connect(host if proxy_mode else query(host)), expected
                    )
                observe(
                    "Disabled CIDR inside a broader prefix",
                    connect("5.45.192.1"),
                    "PROXY",
                )
                observe("Active neighboring RU prefix", connect("5.45.193.1"), "DIRECT")
                if not proxy_mode:
                    ip = query("2gis.com")
                    observe("Preset opaque UDP", packet(ip), "DIRECT")
                    observe(
                        "Preset IPv6 FakeIP", connect(query("2gis.com", 28)), "DIRECT"
                    )
                stop(core)
                core = None
                continue
            if mode == "unavailable":
                child.stdin.write("stats\n")
                child.stdin.flush()
                before = json.loads(child.stdout.readline())
                ip = query("plain.company.test")
                try:
                    assert not connect(
                        ip
                    ), "Missing exit silently used another outbound"
                except (OSError, RuntimeError):
                    pass
                child.stdin.write("stats\n")
                child.stdin.flush()
                assert (
                    json.loads(child.stdout.readline()) == before
                ), "Missing exit leaked a DNS query"
                print(
                    "Unavailable exit: raw FakeIP TCP rejected, no real DNS fallback",
                    flush=True,
                )
                stop(core)
                core = None
                continue
            ip = query("plain.company.test")
            observe("A response then raw TCP to returned IP", connect(ip), first_route)
            observe("A FakeIP then raw UDP", packet(ip), first_route)
            v6 = query("plain.company.test", 28)
            observe(
                "AAAA FakeIP then TCP via IPv4-only destination",
                connect(v6),
                first_route,
            )
            observe("AAAA FakeIP then opaque UDP", packet(v6), first_route)
            try:
                assert not connect(
                    "198.18.255.254"
                ), "Unknown FakeIP reached an outbound"
            except (OSError, RuntimeError):
                pass
            ip = query("alias.company.test")
            observe(
                "CNAME response then raw TCP to returned IP", connect(ip), domain_route
            )
            observe(
                "Same CNAME IP with original HTTP Host",
                connect(ip, b"GET / HTTP/1.1\r\nHost: alias.company.test\r\n\r\n"),
                domain_route,
            )
            ip = query("shared.company.test")
            observe(
                "Excluded name before shared IP collision", connect(ip), domain_route
            )
            other_ip = query("other.cdn.test")
            assert other_ip != ip
            observe(
                "Excluded name IP after different name uses same real IP",
                connect(ip),
                domain_route,
            )
            query("shared.company.test")
            observe(
                "Default name IP after excluded name uses same real IP",
                connect(other_ip),
                "PROXY",
            )
            observe("Default domain FakeIP then raw UDP", packet(other_ip), "PROXY")
            observe(
                "HTTP Host cannot overwrite an established FakeIP identity",
                connect(
                    other_ip, b"GET / HTTP/1.1\r\nHost: shared.company.test\r\n\r\n"
                ),
                "PROXY",
            )
            stop(core)
            core = None
        child.stdin.write("stats\n")
        child.stdin.flush()
        print(
            "Synthetic DNS requests: " + str(len(json.loads(child.stdout.readline()))),
            flush=True,
        )
    finally:
        if core is not None:
            stop(core)
        stop(child)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "server":
        server()
    elif len(sys.argv) > 1 and sys.argv[1] == "lab":
        lab(sys.argv[2], sys.argv[3])
    else:
        for mode in (
            "named-exit",
            "direct",
            "cidr",
            "application",
            "unavailable",
            "preset-services",
            "preset-all",
            "preset-services-proxy",
            "preset-all-proxy",
        ):
            subprocess.run(
                [
                    "unshare",
                    "--user",
                    "--map-root-user",
                    "--net",
                    sys.executable,
                    __file__,
                    "lab",
                    os.readlink("/proc/self/ns/net"),
                    mode,
                ],
                check=True,
            )
