"""Loopback-only TLS camouflage target for the Rust Reality transport test."""
from pathlib import Path
import signal
import socketserver
import ssl
import subprocess
import sys
import tempfile


def terminate(*_):
    raise SystemExit(0)


signal.signal(signal.SIGTERM, terminate)
with tempfile.TemporaryDirectory(prefix="eivro-reality-test-") as tmp:
    cert, key = Path(tmp) / "cert.pem", Path(tmp) / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=cover.eivro.test", "-addext", "subjectAltName=DNS:cover.eivro.test"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3,
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert, key)
    ctx.set_alpn_protocols(["h2", "http/1.1"])

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            try:
                with ctx.wrap_socket(self.request, server_side=True) as tls:
                    while tls.recv(4096):
                        pass
            except OSError:
                pass

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
        block_on_close = False

        def handle_error(self, *_):
            # Expected handshake cancellation during Reality authentication.
            pass

    with Server(("127.0.0.1", int(sys.argv[1])), Handler) as server:
        server.serve_forever(poll_interval=0.02)
