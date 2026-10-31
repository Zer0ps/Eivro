#!/usr/bin/env python3
"""Exercise real GSettings on a private D-Bus session, never the user's desktop."""
import ctypes
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time


def inside(binary):
    ctypes.CDLL(None).prctl(36, 1, 0, 0, 0)  # Reap the guard after its test parent dies.
    schema = 'org.gnome.system.proxy'
    def get(key, suffix=''):
        return subprocess.check_output(['gsettings', 'get', schema + suffix, key], text=True).strip()
    def put(key, value, suffix=''):
        subprocess.run(['gsettings', 'set', schema + suffix, key, value], check=True)
    def snapshot():
        return subprocess.check_output(['gsettings', 'list-recursively', schema], text=True)
    def start(port=2080):
        return subprocess.Popen([binary, '--proxy-guard', str(port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    def line(child):
        assert select.select([child.stdout], [], [], 8)[0], 'guard did not respond'
        return child.stdout.readline()
    def active():
        assert get('mode') == "'manual'"
        for suffix in ['.http', '.https', '.ftp', '.socks']:
            assert get('host', suffix) == "'127.0.0.1'" and get('port', suffix) == '2080'
        assert get('use-authentication', '.http') == 'false'
    def restored(before):
        end = time.monotonic() + 8
        while snapshot() != before and time.monotonic() < end:
            time.sleep(.05)
        assert snapshot() == before, 'original desktop settings were not restored'
        assert not (Path(os.environ['XDG_CONFIG_HOME'])/'eivro/proxy-recovery.json').exists()

    put('mode', "'auto'")
    put('autoconfig-url', "'https://proxy.example/config.pac'")
    put('host', "'old-proxy.example'", '.http')
    put('port', '3128', '.http')
    put('use-authentication', 'true', '.http')
    put('ignore-hosts', "['localhost', '*.internal.test']")
    before = snapshot()
    child = start(); assert line(child) == b'READY\n'; active()
    duplicate = start(2081); assert line(duplicate).startswith(b'ERROR:'); assert duplicate.wait(timeout=5) == 1
    active(); child.stdin.close(); assert child.wait(timeout=8) == 0; restored(before)
    print('normal stop and exclusive ownership: OK')
    child = start(); assert line(child) == b'READY\n'; child.terminate(); assert child.wait(timeout=8) == 0; restored(before)
    print('shutdown signal restores settings: OK')

    code = """import subprocess,sys,signal
c=subprocess.Popen([sys.argv[1],'--proxy-guard','2080'],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
print(c.pid,flush=True)
print(c.stdout.readline().decode().strip(),flush=True)
signal.pause()
"""
    parent = subprocess.Popen([sys.executable, '-u', '-c', code, binary], stdout=subprocess.PIPE, bufsize=0)
    guard_pid = int(line(parent)); assert line(parent) == b'READY\n'; active()
    parent.kill(); parent.wait(timeout=5); restored(before); os.waitpid(guard_pid, 0)
    print('GUI SIGKILL restores desktop settings: OK')

    child = start(); assert line(child) == b'READY\n'; child.kill(); child.wait(timeout=5)
    assert get('mode') == "'manual'"
    subprocess.run([binary, '--recover-proxy'], check=True, timeout=8); restored(before)
    print('guard SIGKILL recovered on next launch: OK')

    child = start(); assert line(child) == b'READY\n'; put('port', '10808', '.socks')
    external = snapshot(); child.stdin.close(); assert child.wait(timeout=8) == 2
    assert snapshot() == external
    print('external client changes preserved: OK')

    # Restore Eivro endpoints while retaining independently edited preferences.
    put('mode', "'none'")
    before = snapshot()
    old_exceptions = get('ignore-hosts')
    child = start(); assert line(child) == b'READY\n'
    put('ignore-hosts', "['localhost', 'private.example']")
    child.stdin.close(); assert child.wait(timeout=8) == 0
    assert get('mode') == "'none'"
    assert get('ignore-hosts') == "['localhost', 'private.example']"
    put('ignore-hosts', old_exceptions)
    restored(before)
    print('edited exceptions retained and stopped proxy removed: OK')

    # These are temporary test settings in this bus only.
    put('mode', "'none'")
    before = snapshot(); child = start(); child.stdin.close(); child.wait(timeout=8); restored(before)
    print('startup cancellation restores settings: OK')


if __name__ == '__main__':
    if sys.argv[1] == '--inside':
        inside(sys.argv[2])
    else:
        binary = str(Path(sys.argv[1]).resolve())
        with tempfile.TemporaryDirectory(prefix='eivro-desktop-test-') as folder:
            root = Path(folder)
            for name in ['config', 'runtime', 'cache']:
                (root/name).mkdir(mode=0o700)
            env = {**os.environ, 'XDG_CONFIG_HOME': str(root/'config'), 'XDG_RUNTIME_DIR': str(root/'runtime'), 'XDG_CACHE_HOME': str(root/'cache'), 'GSETTINGS_BACKEND': 'dconf'}
            result = subprocess.run(['dbus-run-session', '--', sys.executable, '-u', __file__, '--inside', binary], env=env)
            raise SystemExit(result.returncode)
