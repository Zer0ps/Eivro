#!/usr/bin/env python3
"""Manual IPv4 TCP/Reality checks; no profile, traffic, or core logs are saved."""
import base64
import ctypes
import getpass
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import resource
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import parse_qsl, unquote, urlsplit
import uuid

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/nonexistent", "XDG_CACHE_HOME": "/nonexistent"}
PROBES = (
    ("HTTP, domain", "http://example.com/"),
    ("HTTP, IPv4", "http://1.1.1.1/"),
    ("HTTPS, IPv4", "https://1.1.1.1/cdn-cgi/trace"),
    ("HTTPS, domain", "https://example.com/"),
)


class DiagnosticError(Exception):
    pass


def parse_link(text):
    if len(text) > 65536 or any(ord(c) < 32 for c in text):
        raise DiagnosticError("Invalid link.")
    u = urlsplit(text)
    if u.scheme != "vless" or not u.hostname or u.password or u.path not in ("", "/"):
        raise DiagnosticError("This diagnostic requires a VLESS TCP/Reality link.")
    user = str(uuid.UUID(unquote(u.username or "")))
    q = {}
    allowed = {"security", "sni", "peer", "fp", "pbk", "sid", "spx", "flow", "encryption", "type", "headerType", "alpn", "mux", "concurrency", "x-durev-block", "x-durev-prio"}
    for k, v in parse_qsl(u.query, keep_blank_values=True):
        if k in q or k not in allowed:
            raise DiagnosticError("Unsupported or duplicate link parameters.")
        q[k] = v
    if q.get("security") != "reality" or q.get("type", "tcp") != "tcp":
        raise DiagnosticError("This diagnostic requires TCP and Reality.")
    if q.get("encryption", "none") != "none" or q.get("flow", "") not in ("", "xtls-rprx-vision"):
        raise DiagnosticError("Unsupported VLESS encryption or flow.")
    if q.get("headerType", "none") != "none" or q.get("mux", "false") not in ("false", "0"):
        raise DiagnosticError("TCP headers and enabled mux are unsupported.")
    if "concurrency" in q and not -(2**31) <= int(q["concurrency"]) < 2**31:
        raise DiagnosticError("Invalid concurrency.")
    if q.get("spx", "/") not in ("", "/"):
        raise DiagnosticError("Custom spiderX is unsupported by Eivro.")
    pbk = q.get("pbk", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", pbk) or len(base64.urlsafe_b64decode(pbk + "=")) != 32:
        raise DiagnosticError("Invalid Reality public key.")
    sid = q.get("sid", "")
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,8}", sid):
        raise DiagnosticError("Invalid Reality short ID.")
    if "sni" in q and "peer" in q and q["sni"] != q["peer"]:
        raise DiagnosticError("Conflicting Reality server names.")
    port = 443 if u.port is None else u.port
    if port == 0:
        raise DiagnosticError("Invalid server port.")
    return u.hostname, port, user, q


def ipv4(host, port):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        if address.version != 4:
            raise DiagnosticError("This diagnostic does not test IPv6.")
        return str(address)
    result = queue.Queue(maxsize=1)

    def lookup():
        try:
            result.put(socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0])
        except OSError:
            result.put(None)

    threading.Thread(target=lookup, daemon=True).start()
    try:
        value = result.get(timeout=5)
    except queue.Empty:
        raise DiagnosticError("Server IPv4 lookup timed out.") from None
    if not value:
        raise DiagnosticError("Server IPv4 lookup failed.")
    return value


def main_uplink():
    result = subprocess.run(["ip", "-j", "-4", "route", "show", "table", "main", "default"], env=ENV, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3, check=True)
    routes = json.loads(result.stdout)
    candidates = [r for r in routes if isinstance(r.get("dev"), str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", r["dev"]) and r["dev"] not in ("lo", "eivro0") and not (Path("/sys/class/net") / r["dev"] / "tun_flags").exists()]
    if not candidates:
        raise DiagnosticError("No non-TUN IPv4 default route was found.")
    interface = min(candidates, key=lambda r: r.get("metric", 0))["dev"]
    socket.if_nametoindex(interface)
    return interface


def connect(address, port, interface=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(4)
        if interface:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")
        s.connect((address, port))
        return s
    except BaseException:
        s.close()
        raise


def configuration(address, remote_port, user, q, local_port, original_host, interface=None):
    reality = {
        "serverName": q.get("sni", q.get("peer", original_host)),
        "fingerprint": q.get("fp", "chrome"),
        "publicKey": q["pbk"],
        "shortId": q.get("sid", ""),
        "spiderX": q.get("spx", "/"),
        "show": False,
    }
    if "alpn" in q:
        reality["alpn"] = [v for v in q["alpn"].split(",") if v]
    cfg = {
        "log": {"access": "none", "error": "none", "loglevel": "none", "dnsLog": False},
        "inbounds": [{"listen": "127.0.0.1", "port": local_port, "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{"address": address, "port": remote_port, "users": [{"id": user, "encryption": "none", "flow": q.get("flow", "")}]}]},
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": reality},
        }],
    }
    if interface:
        cfg["outbounds"][0]["streamSettings"]["sockopt"] = {"interface": interface}
    return cfg


def probe(port, url):
    # curl's output is restricted to status and timing. Response bodies and
    # potentially sensitive error text are never printed or retained.
    r = subprocess.run(
        ["curl", "--disable", "-4", "--silent", "--connect-timeout", "4", "--max-time", "8", "--noproxy", "", "--proxy", f"socks5h://127.0.0.1:{port}", "--proto", "=http,https", "--output", "/dev/null", "--write-out", "%{http_code} %{time_total}", url],
        env=ENV, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10,
    )
    fields = r.stdout.decode("ascii", errors="ignore").split()
    status = fields[0] if fields and re.fullmatch(r"[0-5][0-9]{2}", fields[0]) else "000"
    elapsed = float(fields[1]) if len(fields) == 2 else 0.0
    return r.returncode, status, elapsed


def stop(child):
    if child.poll() is None:
        child.terminate()
    try:
        child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    args = sys.argv[1:]
    if len(args) != len(set(args)) or any(a not in ("--without-vision", "--uplink") for a in args):
        raise DiagnosticError("Only --without-vision and --uplink are accepted; paste the link at the hidden prompt.")
    if not sys.stdin.isatty():
        raise DiagnosticError("Use a terminal for hidden link input.")
    source = getpass.getpass("VLESS URI (hidden): ").strip()
    host, remote_port, user, q = parse_link(source)
    if "--without-vision" in args:
        q["flow"] = ""
        print("Diagnostic override: Vision disabled; Reality protection remains enabled.", flush=True)
    address = ipv4(host, remote_port)
    interface = main_uplink() if "--uplink" in args else None
    if interface:
        print(f"Diagnostic sockets bound to main uplink: {interface}", flush=True)
    else:
        route = subprocess.run(["ip", "-j", "-4", "route", "get", address], env=ENV, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3, check=True)
        device = json.loads(route.stdout)[0].get("dev", "")
        if device == "eivro0" or (Path("/sys/class/net") / device / "tun_flags").exists():
            print("WARNING: server route uses an existing TUN. This tests a VPN chain; use --uplink to test the main uplink.", flush=True)
    core = Path("/usr/libexec/eivro/xray")
    if not core.is_file():
        core = Path(__file__).resolve().parents[1] / "vendor/xray"
    version = subprocess.run([str(core), "version"], env=ENV, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
    match = re.search(rb"^Xray ([0-9]+\.[0-9]+\.[0-9]+) ", version.stdout)
    if version.returncode or match is None:
        raise DiagnosticError("Cannot identify Xray.")
    print("Xray:", match[1].decode(), flush=True)
    with connect(address, remote_port, interface):
        print("Server TCP/IPv4: reachable", flush=True)
    try:
        with connect(address, remote_port, interface) as raw:
            with ssl.create_default_context().wrap_socket(raw, server_hostname=q.get("sni", q.get("peer", host))):
                print("TLS without Reality authentication: certificate verified", flush=True)
    except (OSError, ValueError):
        print("TLS without Reality authentication: failed (not an authentication test)", flush=True)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    cfg = json.dumps(configuration(address, remote_port, user, q, port, host, interface)).encode()
    validation = subprocess.run([str(core), "run", "-test", "-config", "stdin:"], input=cfg, env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    if validation.returncode:
        raise DiagnosticError("Xray rejected the configuration. No settings or credentials were printed.")
    parent = os.getpid()
    libc = ctypes.CDLL(None, use_errno=True)

    def supervise():
        if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0 or os.getppid() != parent:
            os._exit(125)

    child = subprocess.Popen([str(core), "run", "-config", "stdin:"], env=ENV, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=supervise)
    try:
        child.stdin.write(cfg)
        child.stdin.close()
        until = time.monotonic() + 5
        while True:
            if child.poll() is not None:
                raise DiagnosticError("Xray exited during startup.")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.15) as s:
                    s.settimeout(0.2)
                    s.sendall(bytes([5, 1, 0]))
                    if s.recv(2) == bytes([5, 0]):
                        break
            except OSError:
                pass
            if time.monotonic() >= until:
                raise DiagnosticError("Local SOCKS startup timed out.")
            time.sleep(0.03)
        successes = set()
        for label, url in PROBES:
            code, status, elapsed = probe(port, url)
            print(f"{label}: curl={code}, HTTP={status}, time={elapsed:.2f}s", flush=True)
            if code == 0 and status != "000":
                successes.add(label)
        if not successes:
            print("No upstream HTTP response. TCP availability does not prove Reality/VLESS authentication.")
        elif "HTTPS, IPv4" in successes and "HTTPS, domain" not in successes:
            print("HTTPS by IPv4 works; check server DNS and domain routing.")
        elif not any(label.startswith("HTTPS") for label in successes):
            print("HTTP data passes through VLESS; HTTPS fails. Check Vision and server egress.")
        else:
            print("HTTPS passed through Xray. Compare Eivro's selected core and settings.")
        return 0 if {"HTTPS, IPv4", "HTTPS, domain"} <= successes else 1
    finally:
        stop(child)
        print("Isolated Xray stopped; system routes and DNS were not changed.", flush=True)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except DiagnosticError as error:
        print(str(error))
        sys.exit(1)
    except (ValueError, OSError, EOFError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        print("Diagnostic failed or timed out. Link, credentials, and response bodies were not printed.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("Cancelled.")
        sys.exit(130)
