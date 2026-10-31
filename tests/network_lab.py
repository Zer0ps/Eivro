#!/usr/bin/env python3
"""Opt-in real-core lab. Automatically runs inside a fresh unshare -Urn namespace.
Creates veth devices exclusively in disposable namespaces; never edits the host.
No real credentials or external network access. Requires ip, openssl, curl.
"""
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
ROOT = Path(__file__).resolve().parents[1]

def run(*args, **kw):
    return subprocess.run(args, check=True, capture_output=True, **kw)

def server(cert, key):
    input()
    run('ip', 'link', 'set', 'lo', 'up')
    run('ip', 'address', 'add', '10.50.0.53/24', 'dev', 'work-peer')
    run('ip', 'link', 'set', 'work-peer', 'up')
    queries = []
    packets = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    packets.bind(('10.50.0.53', 53))

    def dns():
        while True:
            data, peer = packets.recvfrom(4096)
            end = 12
            labels = []
            while data[end]:
                n = data[end]
                labels.append(data[end + 1:end + 1 + n].decode())
                end += n + 1
            end += 5
            name = '.'.join(labels)
            queries.append(name)
            kind = struct.unpack('!H', data[end - 4:end - 2])[0]
            answer = b''
            if kind == 1:
                answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 10, 4) + socket.inet_aton('10.50.0.53')
            reply = data[:2] + struct.pack('!HHHHH', 33152, 1, bool(answer), 0, 0) + data[12:end] + answer
            packets.sendto(reply, peer)

    class Handler(http.server.BaseHTTPRequestHandler):

        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Length', '13')
            self.end_headers()
            self.wfile.write(b'work-route-ok')

        def log_message(self, *_):
            pass
    https_server = http.server.ThreadingHTTPServer(('10.50.0.53', 443), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    https_server.socket = tls.wrap_socket(https_server.socket, server_side=True)
    threading.Thread(target=dns, daemon=True).start()
    threading.Thread(target=https_server.serve_forever, daemon=True).start()
    print('ready', flush=True)
    for command in sys.stdin:
        if command.strip() == 'stats':
            print(json.dumps(queries), flush=True)
        else:
            break

def lab(original_namespace):
    if os.readlink('/proc/self/ns/net') == original_namespace:
        raise SystemExit('Use unshare --user --map-root-user --net python3 tests/network_lab.py')
    run('ip', 'link', 'set', 'lo', 'up')
    with tempfile.TemporaryDirectory(prefix='eivro-network-lab-') as tmp:
        cert, key = (str(Path(tmp) / 'cert.pem'), str(Path(tmp) / 'key.pem'))
        run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=git.company.test', '-addext', 'subjectAltName=DNS:git.company.test', '-keyout', key, '-out', cert)
        child = subprocess.Popen(['unshare', '--net', sys.executable, __file__, 'server', cert, key], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        core = None
        try:
            run('ip', 'link', 'add', 'work0', 'type', 'veth', 'peer', 'name', 'work-peer')
            deadline = time.monotonic() + 3
            while os.readlink(f'/proc/{child.pid}/ns/net') == os.readlink('/proc/self/ns/net'):
                if time.monotonic() > deadline:
                    raise RuntimeError('child namespace not ready')
                time.sleep(0.01)
            run('ip', 'link', 'set', 'work-peer', 'netns', str(child.pid))
            run('ip', 'address', 'add', '10.50.0.1/24', 'dev', 'work0')
            run('ip', 'link', 'set', 'work0', 'up')
            run('ip', 'link', 'add', 'outside0', 'type', 'veth', 'peer', 'name', 'outside-peer')
            for name in ('outside0', 'outside-peer'):
                run('ip', 'link', 'set', name, 'up')
            run('ip', 'address', 'add', '192.0.2.1/24', 'dev', 'outside0')
            run('ip', 'route', 'add', 'default', 'via', '192.0.2.2', 'dev', 'outside0')
            child.stdin.write('start\n')
            child.stdin.flush()
            assert child.stdout.readline().strip() == 'ready'
            for available in (True, False):
                cfg = run(str(ROOT / 'target/debug/examples/network-lab-config'), *(() if available else ('unavailable',))).stdout
                core = subprocess.Popen([str(ROOT / 'vendor/sing-box'), 'run', '-c', '/dev/stdin'], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                core.stdin.write(cfg)
                core.stdin.close()
                deadline = time.monotonic() + 3
                while True:
                    try:
                        with socket.create_connection(('127.0.0.1', 12080), timeout=0.1):
                            break
                    except OSError:
                        if time.monotonic() > deadline:
                            raise RuntimeError('core not ready')
                        time.sleep(0.02)
                result = subprocess.run(['curl', '-q', '--noproxy', '', '--proxy', 'http://127.0.0.1:12080', '--cacert', cert, '--silent', '--show-error', '--max-time', '5', 'https://git.company.test/'], capture_output=True)
                if available:
                    assert result.returncode == 0 and result.stdout == b'work-route-ok', result.stderr
                else:
                    assert result.returncode != 0 and (not result.stdout)
                core.terminate()
                core.wait(timeout=3)
                core = None
                child.stdin.write('stats\n')
                child.stdin.flush()
                queries = json.loads(child.stdout.readline())
                assert queries and all((q == 'git.company.test' for q in queries)), queries
                if available:
                    before = len(queries)
                else:
                    assert len(queries) == before, 'Unavailable exit queried DNS'
                print('Available: verified TLS + HTTPS + interface-bound DNS' if available else 'Unavailable: traffic rejected, no additional DNS query', flush=True)
        finally:
            if core is not None:
                core.terminate()
                core.wait(timeout=3)
            child.terminate()
            child.wait(timeout=3)
if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'server':
        server(*sys.argv[2:])
    elif len(sys.argv) > 1 and sys.argv[1] == 'lab':
        lab(sys.argv[2])
    else:
        subprocess.run(['unshare', '--user', '--map-root-user', '--net', sys.executable, __file__, 'lab', os.readlink('/proc/self/ns/net')], check=True)
