#!/usr/bin/env python3
"""Exercise installed helper IPC on a disposable macOS CI runner.

Only loopback listeners are started. No TUN, proxy, DNS or public VPN change is
requested; privileged modes are tested only with deliberately invalid grants.
"""
import json
import os
import plistlib
import socket
import struct
import subprocess
import time
import tempfile
from pathlib import Path

SOCKET = '/var/run/io.eivro.tun.sock'

def send(sock, value):
    data = json.dumps(value).encode()
    sock.sendall(struct.pack('!I', len(data)) + data)

def read_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        block = sock.recv(length - len(data))
        if not block:
            raise RuntimeError('Helper closed the channel')
        data.extend(block)
    return bytes(data)

def receive(sock):
    size, = struct.unpack('!I', read_exact(sock, 4))
    assert 0 < size <= 131072
    return json.loads(read_exact(sock, size))

def connect(version):
    sock = socket.socket(socket.AF_UNIX)
    sock.settimeout(10)
    sock.connect(SOCKET)
    assert receive(sock) == {'event': 'hello', 'version': version}
    return sock

def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

def wait_closed(port):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        with socket.socket() as sock:
            if sock.connect_ex(('127.0.0.1', port)) != 0:
                return
        time.sleep(.05)
    raise AssertionError('Proxy survived release of its owner')

def main():
    if os.uname().sysname != 'Darwin' or os.environ.get('GITHUB_ACTIONS') != 'true' or os.geteuid() == 0:
        raise SystemExit('Run only as the unprivileged user on a disposable macOS Actions runner')
    app = Path('/Applications/Eivro.app/Contents')
    info = plistlib.loads((app / 'Info.plist').read_bytes())
    version = info['CFBundleShortVersionString']
    assert info['CFBundleIdentifier'] == 'io.eivro.Client'
    for name in ('eivro-tun', 'sing-box', 'xray'):
        binary = Path('/Library/PrivilegedHelperTools/io.eivro') / name
        assert binary.stat().st_uid == 0 and binary.stat().st_mode & 0o022 == 0
    assert subprocess.check_output([str(app / 'MacOS/eivro'), '--version'], text=True).strip() == f'Eivro {version}'
    port = free_port()
    request = {'uri': 'ss://chacha20-ietf-poly1305:synthetic@127.0.0.1:9', 'bypass': [], 'port': port}
    with connect(version) as sock:
        for mode in ('tun', 'proxy'):
            send(sock, {'command': 'start', 'request': request, 'mode': mode, 'authorization': [0] * 32})
            assert receive(sock)['event'] == 'denied'
        for _ in range(2):
            send(sock, {'command': 'start', 'request': request, 'mode': 'local', 'authorization': None})
            assert receive(sock)['event'] == 'ready'
            with socket.create_connection(('127.0.0.1', port), timeout=3) as proxy:
                proxy.sendall(b'\x05\x01\x00')
                assert read_exact(proxy, 2) == b'\x05\x00'
            send(sock, {'command': 'stop'})
            assert receive(sock)['event'] == 'stopped'
            wait_closed(port)
        send(sock, {'command': 'start', 'request': request, 'mode': 'local', 'authorization': None})
        assert receive(sock)['event'] == 'ready'
    wait_closed(port)
    # Exercise the actual installed CGL/AppKit application with empty, private
    # settings. No VPN is started and no user configuration is read.
    with tempfile.TemporaryDirectory(prefix='eivro-macos-smoke-') as config:
        environment = dict(os.environ, XDG_CONFIG_HOME=config)
        gui = subprocess.Popen([str(app / 'MacOS/eivro')], env=environment,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(5)
            assert gui.poll() is None, 'Installed GUI exited during native startup'
            screenshots = Path('work/macos-smoke')
            screenshots.mkdir(parents=True, exist_ok=True)
            capture = subprocess.run(['/usr/sbin/screencapture', '-x',
                                      str(screenshots / 'desktop.png')],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     timeout=10)
            if capture.returncode:
                print('Native startup passed; screenshot permission unavailable')
        finally:
            gui.terminate()
            try:
                gui.wait(timeout=5)
            except subprocess.TimeoutExpired:
                gui.kill()
                gui.wait()
    print('PASS: installed metadata, launchd IPC, rejected authorization, Local start/stop/reconnect/owner exit')

if __name__ == '__main__':
    main()
