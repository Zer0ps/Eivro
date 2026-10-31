//! Loopback-only Xray transport regressions; no TUN, DNS, or user profiles.
use eivro::{
    config::{ConnectRequest, Mode},
    process::{self, Event, Session},
    xray,
};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

const TIMEOUT: Duration = Duration::from_secs(5);
const UUID: &str = "a3ba7b44-3275-42e7-9a54-30aa2bde0437";

struct Core(Child);

impl Drop for Core {
    fn drop(&mut self) {
        process::terminate(&mut self.0);
    }
}

fn command() -> Command {
    let mut command = Command::new(process::xray_path().unwrap());
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("HOME", "/nonexistent")
        .env("XDG_CACHE_HOME", "/nonexistent")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn output(args: &[&str]) -> String {
    let mut core = Core(command().args(args).stdout(Stdio::piped()).spawn().unwrap());
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if let Some(status) = core.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "Xray command timed out");
        thread::sleep(Duration::from_millis(10));
    }
    let mut version = String::new();
    core.0
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut version)
        .unwrap();
    version
}

fn verify_version() {
    assert!(output(&["version"]).starts_with(&format!("Xray {} ", xray::VERSION)));
}

fn start(config: Value, reservation: TcpListener) -> Core {
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);
    let mut core = Core(
        command()
            .args(["run", "-config", "stdin:"])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    core.0
        .stdin
        .take()
        .unwrap()
        .write_all(config.to_string().as_bytes())
        .unwrap();
    wait_listener(&mut core, port);
    core
}

fn wait_listener(core: &mut Core, port: u16) {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        assert!(
            core.0.try_wait().unwrap().is_none(),
            "Core exited during startup"
        );
        if TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_millis(100))
            .is_ok()
        {
            break;
        }
        assert!(Instant::now() < deadline, "Listener startup timed out");
        thread::sleep(Duration::from_millis(10));
    }
}

fn listener() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").unwrap()
}

fn stream_timeouts(stream: &TcpStream) {
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(TIMEOUT)).unwrap();
}

fn accept(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream_timeouts(&stream);
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "XHTTP target connection timed out"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("XHTTP target accept failed: {error}"),
        }
    }
}

#[test]
fn vless_xhttp_stream_one_and_packet_up_transfer_data() {
    verify_version();
    for mode in ["stream-one", "packet-up"] {
        let target = listener();
        let target_port = target.local_addr().unwrap().port();
        let server_reservation = listener();
        let server_port = server_reservation.local_addr().unwrap().port();
        let bridge_reservation = listener();
        let bridge_port = bridge_reservation.local_addr().unwrap().port();
        let transport = json!({
            "network": "xhttp",
            "security": "none",
            "xhttpSettings": {"path": "/eivro-test", "mode": mode}
        });
        let log = json!({"access": "none", "error": "none", "loglevel": "none", "dnsLog": false});
        let server = start(
            json!({
                "log": log,
                "inbounds": [{
                    "listen": "127.0.0.1", "port": server_port, "protocol": "vless",
                    "settings": {"clients": [{"id": UUID}], "decryption": "none"},
                    "streamSettings": transport
                }],
                // The upstream default blocks loopback targets. This test-only
                // server allows exactly its synthetic HTTP endpoint.
                "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{
                    "action": "allow", "network": "tcp", "ip": ["127.0.0.1/32"], "port": target_port
                }]}}]
            }),
            server_reservation,
        );
        // Xray permits unencrypted VLESS on loopback. This synthetic transport
        // test bypasses Eivro's parser, which still requires TLS/Reality.
        let client = start(
            xray::config(
                json!({
                    "protocol": "vless", "tag": "proxy",
                    "settings": {"vnext": [{
                        "address": "127.0.0.1", "port": server_port,
                        "users": [{"id": UUID, "encryption": "none"}]
                    }]},
                    "streamSettings": transport
                }),
                bridge_port,
            ),
            bridge_reservation,
        );
        let mut bridge =
            TcpStream::connect_timeout(&([127, 0, 0, 1], bridge_port).into(), TIMEOUT).unwrap();
        stream_timeouts(&bridge);
        bridge.write_all(&[5, 1, 0]).unwrap();
        let mut authentication = [0; 2];
        bridge.read_exact(&mut authentication).unwrap();
        assert_eq!(authentication, [5, 0], "{mode}");
        let mut connect = vec![5, 1, 0, 1, 127, 0, 0, 1];
        connect.extend(target_port.to_be_bytes());
        bridge.write_all(&connect).unwrap();
        let mut reply = [0; 10];
        bridge.read_exact(&mut reply).unwrap();
        assert_eq!(&reply[..4], &[5, 0, 0, 1], "{mode}");

        let request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        bridge.write_all(request).unwrap();
        // The listener's backlog accepts the TCP handshake; serving it here
        // avoids a background responder that could outlive a failed assertion.
        let mut upstream = accept(&target);
        let mut received = vec![0; request.len()];
        upstream.read_exact(&mut received).unwrap();
        assert_eq!(received, request, "{mode}");
        let body = format!("eivro-xhttp-{mode}");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        upstream.write_all(response.as_bytes()).unwrap();
        drop(upstream);
        let mut received = vec![0; response.len()];
        bridge.read_exact(&mut received).unwrap();
        assert_eq!(received, response.as_bytes(), "{mode}");
        drop(bridge);
        drop(client);
        drop(server);
        assert!(TcpListener::bind(("127.0.0.1", bridge_port)).is_ok());
        assert!(TcpListener::bind(("127.0.0.1", server_port)).is_ok());
    }
}

#[test]
fn tcp_reality_links_transfer_data_through_the_eivro_session() {
    verify_version();
    let keys = output(&["x25519"]);
    let key = |prefix: &str| {
        keys.lines()
            .find_map(|line| line.strip_prefix(prefix))
            .unwrap()
            .trim()
    };
    let private = key("PrivateKey:");
    let public = key("Password (PublicKey):");
    let tls_reservation = listener();
    let tls_port = tls_reservation.local_addr().unwrap().port();
    drop(tls_reservation);
    let mut tls = Core(
        Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/reality-tls.py"
            ))
            .arg(tls_port.to_string())
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_listener(&mut tls, tls_port);
    for flow in ["", "xtls-rprx-vision"] {
        let target = listener();
        let target_port = target.local_addr().unwrap().port();
        let remote_reservation = listener();
        let remote_port = remote_reservation.local_addr().unwrap().port();
        let local_reservation = listener();
        let local_port = local_reservation.local_addr().unwrap().port();
        let _remote = start(
            json!({
                "log": {"access":"none","error":"none","loglevel":"none","dnsLog":false},
                "inbounds": [{
                    "listen":"127.0.0.1", "port":remote_port, "protocol":"vless",
                    "settings":{"clients":[{"id":UUID,"flow":flow}],"decryption":"none"},
                    "streamSettings":{"network":"tcp","security":"reality","realitySettings":{
                        "target":format!("127.0.0.1:{tls_port}"),"serverNames":["cover.eivro.test"],
                        "privateKey":private,"shortIds":["1234567890abcdef"],"show":false
                    }}
                }],
                "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{
                    "action":"allow","network":"tcp","ip":["127.0.0.1/32"],"port":target_port
                }]}}]
            }),
            remote_reservation,
        );
        let uri = format!(
            "vless://{UUID}@127.0.0.1:{remote_port}?security=reality&pbk={public}&sid=1234567890abcdef&sni=cover.eivro.test&fp=chrome&flow={flow}&spx=%2F"
        );
        drop(local_reservation);
        let (session, events) = Session::start(
            ConnectRequest {
                connections: vec![],
                uri,
                port: local_port,
                bridge_port: None,
                probe_port: None,
                bypass: vec![],
                policies: vec![],
                kill_switch: false,
            },
            Mode::Local,
            Arc::new(|| {}),
        )
        .unwrap();
        let event = events.recv_timeout(Duration::from_secs(8)).unwrap();
        assert!(matches!(event, Event::Running), "{event:?}");
        let mut socket = TcpStream::connect(("127.0.0.1", local_port)).unwrap();
        stream_timeouts(&socket);
        socket.write_all(&[5, 1, 0]).unwrap();
        let mut auth = [0; 2];
        socket.read_exact(&mut auth).unwrap();
        assert_eq!(auth, [5, 0]);
        let mut connect = vec![5, 1, 0, 1, 127, 0, 0, 1];
        connect.extend(target_port.to_be_bytes());
        socket.write_all(&connect).unwrap();
        let mut reply = [0; 10];
        socket.read_exact(&mut reply).unwrap();
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        let request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        socket.write_all(request).unwrap();
        let mut upstream = accept(&target);
        let mut received = vec![0; request.len()];
        upstream.read_exact(&mut received).unwrap();
        assert_eq!(received, request);
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nworks";
        upstream.write_all(response).unwrap();
        drop(upstream);
        let mut received = vec![0; response.len()];
        socket.read_exact(&mut received).unwrap();
        assert_eq!(received, response);
        drop(socket);
        drop(session);
        assert!(TcpListener::bind(("127.0.0.1", local_port)).is_ok());
    }
}
