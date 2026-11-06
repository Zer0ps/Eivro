"""Run networking labs without access to the host's runtime service sockets.

A network namespace does not isolate pathname Unix sockets. In particular,
resolvectl converts a local link name to an ifindex and sends it to resolved
over D-Bus; the host may assign that index to a completely different device.
"""

import os
from pathlib import Path
import subprocess
import sys


def require_runtime_isolation():
    marker = Path("/run/eivro-test-isolated")
    assert marker.is_file() and marker.read_text() == os.readlink(
        "/proc/self/ns/net"
    ), "Run the lab's default entrypoint; private /run is required"
    assert (
        os.environ.get("DBUS_SYSTEM_BUS_ADDRESS")
        == "unix:path=/run/dbus/system_bus_socket"
    )
    assert not Path(
        "/run/dbus/system_bus_socket"
    ).exists(), "Host D-Bus socket is visible"


def launch(script, *args):
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
            "--kill-child",
            sys.executable,
            str(Path(__file__).resolve()),
            os.readlink("/proc/self/ns/net"),
            os.readlink("/proc/self/ns/mnt"),
            str(Path(script).resolve()),
            *args,
        ],
        check=True,
    )


if __name__ == "__main__":
    original_net, original_mount, script, *args = sys.argv[1:]
    assert os.readlink("/proc/self/ns/net") != original_net
    assert os.readlink("/proc/self/ns/mnt") != original_mount
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(
        [
            "mount",
            "-t",
            "tmpfs",
            "-o",
            "mode=755,nosuid,nodev,size=16m",
            "tmpfs",
            "/run",
        ],
        check=True,
    )
    # Prevent inherited addresses from selecting a socket outside the private /run.
    for key in (
        "DBUS_SESSION_BUS_ADDRESS",
        "DBUS_STARTER_ADDRESS",
        "DBUS_STARTER_BUS_TYPE",
        "SSH_AUTH_SOCK",
        "NOTIFY_SOCKET",
    ):
        os.environ.pop(key, None)
    os.environ["DBUS_SYSTEM_BUS_ADDRESS"] = "unix:path=/run/dbus/system_bus_socket"
    os.environ["XDG_RUNTIME_DIR"] = "/run/user/0"
    Path("/run/user/0").mkdir(parents=True, mode=0o700)
    for socket in (
        "/run/dbus/system_bus_socket",
        "/var/run/dbus/system_bus_socket",
        "/run/systemd/resolve/io.systemd.Resolve",
    ):
        assert not Path(socket).exists(), "Host runtime socket is visible"
    Path("/run/eivro-test-isolated").write_text(os.readlink("/proc/self/ns/net"))
    require_runtime_isolation()
    os.execv(sys.executable, [sys.executable, script, *args])
