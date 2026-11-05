"""Opt-in, loopback-only FakeIP runtime checks. Synthetic names; anonymous RAM state."""

import argparse, contextlib, json, os, socket, statistics, struct, subprocess, time


class DnsError(Exception):
    pass


def read(sock, count):
    data = b""
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise DnsError("DNS channel closed")
        data += part
    return data


def skip_name(data, pos):
    for _ in range(128):
        size = data[pos]
        pos += 1
        if size == 0:
            return pos
        if size & 0xC0 == 0xC0:
            return pos + 1
        if size & 0xC0:
            raise DnsError("bad DNS label")
        pos += size
    raise DnsError("bad DNS name")


class Core:
    def __init__(self, binary, fd, pool="198.18.0.0/15"):
        self.binary = binary
        self.fd = fd
        self.process = None
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        self.config = {
            "log": {"disabled": True},
            "inbounds": [
                {
                    "type": "mixed",
                    "tag": "lab",
                    "listen": "127.0.0.1",
                    "listen_port": self.port,
                }
            ],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {
                "default_domain_resolver": "real",
                "rules": [
                    {"action": "sniff"},
                    {"protocol": "dns", "action": "hijack-dns"},
                ],
            },
            "dns": {
                "servers": [
                    {
                        "type": "fakeip",
                        "tag": "fake",
                        "inet4_range": pool,
                        "inet6_range": "2001:2::/125",
                    },
                    {
                        "type": "hosts",
                        "tag": "real",
                        "predefined": {"site.test": "127.0.0.1"},
                    },
                ],
                "rules": [
                    {
                        "inbound": ["lab"],
                        "query_type": ["A", "AAAA"],
                        "action": "route",
                        "server": "fake",
                    }
                ],
                "final": "real",
            },
            "experimental": {
                "cache_file": {
                    "enabled": True,
                    "path": f"/proc/self/fd/{fd}",
                    "store_fakeip": True,
                    "store_dns": False,
                }
            },
        }

    def start(self):
        self.process = subprocess.Popen(
            [self.binary, "run", "-c", "/dev/stdin"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            pass_fds=[self.fd],
            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
        )
        self.process.stdin.write(json.dumps(self.config).encode())
        self.process.stdin.close()
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(self.process.stderr.read().decode())
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.1):
                    return self
            except OSError:
                time.sleep(0.01)
        raise RuntimeError("core not ready")

    def stop(self, kill=False):
        if self.process is None:
            return
        p = self.process
        if kill:
            p.kill()
        else:
            p.terminate()
        try:
            p.wait(timeout=4)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=2)
            raise RuntimeError("core did not stop gracefully")
        finally:
            p.stderr.close()
            self.process = None

    def query(self, domain, kind=1):
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as s:
            s.sendall(b"\5\1\0")
            assert read(s, 2) == b"\5\0"
            s.sendall(
                b"\5\1\0\1" + socket.inet_aton("192.0.2.53") + struct.pack("!H", 53)
            )
            assert read(s, 10)[1] == 0
            q = (
                struct.pack("!HHHHHH", 1234, 256, 1, 0, 0, 0)
                + b"".join(bytes([len(x)]) + x.encode() for x in domain.split("."))
                + b"\0"
                + struct.pack("!HH", kind, 1)
            )
            s.sendall(struct.pack("!H", len(q)) + q)
            r = read(s, struct.unpack("!H", read(s, 2))[0])
            _, flags, questions, answers, _, _ = struct.unpack("!HHHHHH", r[:12])
            if flags & 15:
                raise DnsError("DNS error " + str(flags & 15))
            pos = 12
            for _ in range(questions):
                pos = skip_name(r, pos) + 4
            for _ in range(answers):
                pos = skip_name(r, pos)
                record, _, ttl, size = struct.unpack("!HHIH", r[pos : pos + 10])
                pos += 10
                if record == kind and size == (4 if kind == 1 else 16):
                    return socket.inet_ntop(
                        socket.AF_INET if kind == 1 else socket.AF_INET6,
                        r[pos : pos + size],
                    )
                pos += size
            raise DnsError("no address answer")

    def stats(self):
        p = self.process.pid
        stat = open(f"/proc/{p}/stat").read().rsplit(")", 1)[1].split()
        ticks = sum(int(stat[i]) for i in (11, 12)) / os.sysconf("SC_CLK_TCK")
        smaps = {
            line.split(":")[0]: int(line.split()[1])
            for line in open(f"/proc/{p}/smaps_rollup")
            if ":" in line and line.split()[1].isdigit()
        }
        return {
            "cpu_seconds": ticks,
            "rss_kib": smaps["Rss"],
            "private_kib": smaps["Private_Clean"] + smaps["Private_Dirty"],
            "ram_store_bytes": os.fstat(self.fd).st_size,
        }


@contextlib.contextmanager
def runtime(binary, pool="198.18.0.0/15"):
    fd = os.memfd_create("eivro-fakeip-test", os.MFD_CLOEXEC)
    core = Core(binary, fd, pool)
    try:
        yield core.start()
    finally:
        core.stop()
        os.close(fd)


def run(binary, expect_bugs, bench):
    with runtime(binary) as core:
        old = core.query("first.test")
        core.stop()
        core.start()
        assert core.query("first.test") == old
        second = core.query("second.test")
        core.stop(kill=True)
        core.start()
        new = core.query("third.test")
        old_after = core.query("first.test")
        crash_ok = new not in (old, second) and old_after == old
        print(
            json.dumps(
                {
                    "crash_preserved_identity": crash_ok,
                    "before": [old, second],
                    "after": [new, old_after],
                }
            ),
            flush=True,
        )
        assert crash_ok != expect_bugs
        core.stop()
        core.start()
        core.stop(kill=True)
        core.start()
        stable = core.query("first.test") == old_after
        print(
            json.dumps({"crash_without_new_query_preserved_identity": stable}),
            flush=True,
        )
        if not expect_bugs:
            assert stable
    for kind in (1, 28):
        with runtime(binary, "198.18.0.0/29") as core:
            issued = [core.query(f"pool-{i}.test", kind) for i in range(5)]
            try:
                extra = core.query("exhausted.test", kind)
                safe = extra not in issued
            except DnsError:
                safe = True
            print(
                json.dumps({"type": kind, "exhaustion_rejected_reassignment": safe}),
                flush=True,
            )
            assert safe != expect_bugs
            if not expect_bugs:
                assert core.query("pool-0.test", kind) == issued[0]
                core.stop()
                fd = os.memfd_create("retired-exhausted-pool", os.MFD_CLOEXEC)
                retired = Core(binary, fd, "198.18.0.0/29")
                try:
                    subprocess.run(
                        [binary, "eivro-retire-fakeip", str(core.fd), str(fd)],
                        pass_fds=[core.fd, fd],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE,
                        timeout=5,
                        check=True,
                    )
                    retired.start()
                    try:
                        retired.query("pool-0.test", kind)
                    except DnsError:
                        pass
                    else:
                        raise AssertionError("Retirement recycled an exhausted pool")
                    print(
                        json.dumps(
                            {"type": kind, "retirement_does_not_reset_exhaustion": True}
                        ),
                        flush=True,
                    )
                finally:
                    retired.stop()
                    os.close(fd)
    if not expect_bugs:
        with runtime(binary) as core:
            core.stop(kill=True)
            fd = os.memfd_create("retired-unused-pool", os.MFD_CLOEXEC)
            retired = Core(binary, fd)
            try:
                subprocess.run(
                    [binary, "eivro-retire-fakeip", str(core.fd), str(fd)],
                    pass_fds=[core.fd, fd],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    timeout=5,
                    check=True,
                )
                retired.start()
                assert (
                    retired.query("first-after-empty-retirement.test") == "198.18.0.2"
                )
                print(
                    json.dumps({"pre_first_query_crash_can_retire_safely": True}),
                    flush=True,
                )
            finally:
                retired.stop()
                os.close(fd)
        with runtime(binary) as core:
            first4 = core.query("retirement-private.test")
            first6 = core.query("retirement-private.test", 28)
            core.stop()
            before = os.pread(core.fd, os.fstat(core.fd).st_size, 0)
            target = os.memfd_create("eivro-retired-state", os.MFD_CLOEXEC)
            fresh = Core(binary, target)
            try:
                subprocess.run(
                    [binary, "eivro-retire-fakeip", str(core.fd), str(target)],
                    pass_fds=[core.fd, target],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    timeout=5,
                    check=True,
                )
                assert os.pread(core.fd, len(before), 0) == before
                assert b"retirement-private.test" not in os.pread(
                    target, os.fstat(target).st_size, 0
                )
                fresh.start()
                assert fresh.query("new-after-exit.test") != first4
                assert fresh.query("new-after-exit.test", 28) != first6
                assert fresh.query("retirement-private.test") != first4
                print(
                    json.dumps(
                        {"retirement_erased_names_preserved_both_cursors": True}
                    ),
                    flush=True,
                )
            finally:
                fresh.stop()
                os.close(target)
        with runtime(binary) as core:
            core.query("retained.test")
            core.stop()
            core.config["dns"]["servers"][0]["inet4_range"] = "198.19.0.0/16"
            try:
                core.start()
            except RuntimeError:
                assert (
                    core.process.poll() is not None
                ), "Core did not reject changed ranges"
            else:
                raise AssertionError(
                    "Retained identities silently reset after a range change"
                )
            print(json.dumps({"changed_ranges_rejected": True}), flush=True)
    if bench:
        with runtime(binary) as core:
            fresh = []
            cached = []
            for i in range(bench):
                t = time.perf_counter()
                core.query(f"bench-{i}.test")
                fresh.append((time.perf_counter() - t) * 1000)
            for i in range(min(bench, 100)):
                t = time.perf_counter()
                core.query(f"bench-{i}.test")
                cached.append((time.perf_counter() - t) * 1000)
            initial = core.stats()
            time.sleep(5)
            final = core.stats()
            print(
                json.dumps(
                    {
                        "samples": bench,
                        "new_ms_p50": statistics.median(fresh),
                        "new_ms_p95": sorted(fresh)[int(len(fresh) * 0.95)],
                        "cached_ms_p50": statistics.median(cached),
                        "idle_cpu_seconds_5s": final["cpu_seconds"]
                        - initial["cpu_seconds"],
                        **final,
                    }
                ),
                flush=True,
            )


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--core", required=True)
    p.add_argument("--expect-bugs", action="store_true")
    p.add_argument("--bench", type=int, default=0)
    a = p.parse_args()
    run(os.path.abspath(a.core), a.expect_bugs, a.bench)
