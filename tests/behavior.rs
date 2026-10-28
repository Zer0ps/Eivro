use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::json;
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use velum::{
    config::{ConnectRequest, Mode, generate},
    import::{EngineKind, import_text, parse_uri},
    routing::Rule,
    storage::{self, Settings},
};

const UUID: &str = "a3ba7b44-3275-42e7-9a54-30aa2bde0437";
fn vless() -> String {
    format!("vless://{UUID}@edge.example:443?security=tls&type=tcp#My%20server")
}
fn core() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vendor/sing-box")
}
fn request(uri: String) -> ConnectRequest {
    ConnectRequest {
        probe_port: None,
        policies: vec![],
        kill_switch: false,
        bridge_port: None,
        uri,
        bypass: vec![
            "*.example.com".into(),
            "example.org".into(),
            "10.0.0.0/8".into(),
        ],
        port: 2080,
    }
}
static COUNTER: AtomicUsize = AtomicUsize::new(0);
fn tmp() -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "velum-test-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&p).unwrap();
    p
}

#[test]
fn domain_policies_have_boundaries_and_ipv6() {
    let wildcard = Rule::parse("*.Example.COM").unwrap();
    assert!(wildcard.matches("a.b.example.com"));
    assert!(!wildcard.matches("example.com"));
    assert!(!wildcard.matches("badexample.com"));
    assert!(Rule::parse("example.com").unwrap().matches("EXAMPLE.COM."));
    assert!(!Rule::parse("example.com").unwrap().matches("a.example.com"));
    assert!(
        Rule::parse("2001:db8::/32")
            .unwrap()
            .matches("2001:db8::12")
    );
    assert!(!Rule::parse("10.0.0.0/8").unwrap().matches("11.0.0.1"));
    for invalid in [
        "",
        "*",
        "*example.com",
        "https://example.com",
        "a..com",
        "-a.com",
        "a-.com",
        "example.com/path",
        "10.0.0.0/99",
    ] {
        assert!(Rule::parse(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn importer_rejects_silent_downgrades_and_insecure_links() {
    let parsed = parse_uri(&vless()).unwrap();
    assert_eq!(parsed.name, "My server");
    assert_eq!(parsed.outbound["tls"]["insecure"], false);
    for suffix in [
        "&insecure=1",
        "&allowInsecure=true",
        "&type=unsupported-transport",
        "&encryption=unsupported",
        "&unknown=1",
        "&security=none",
    ] {
        let uri = format!("vless://{UUID}@example.com:443?security=tls{suffix}");
        assert!(parse_uri(&uri).is_err(), "{suffix}");
    }
    assert!(parse_uri("vless://bad@example.com:443?security=tls").is_err());
    assert!(
        parse_uri(&format!(
            "vless://{UUID}@example.com:443?security=reality&pbk=bad"
        ))
        .is_err()
    );
    assert!(parse_uri("ss://bm9uZTpwYXNz@example.com:443").is_err());
}

#[test]
fn subscription_import_is_atomic_and_deduplicates() {
    let text = format!("{}\n{}", vless(), vless());
    assert_eq!(import_text(&text).unwrap().len(), 1);
    assert_eq!(import_text(&STANDARD.encode(text)).unwrap().len(), 1);
    assert!(import_text(&format!("{}\ninvalid", vless())).is_err());
}

#[test]
fn dormant_xray_mux_hints_do_not_enable_sing_box_multiplex() {
    for base in [
        vless().split('#').next().unwrap().to_owned(),
        "trojan://secret@example.com:443?security=tls".into(),
    ] {
        let expected = parse_uri(&base).unwrap().outbound;
        for suffix in [
            "&concurrency=8",
            "&concurrency=-1",
            "&concurrency=0&mux=false",
            "&mux=0&concurrency=128",
        ] {
            let actual = parse_uri(&format!("{base}{suffix}")).unwrap().outbound;
            assert_eq!(actual, expected, "{suffix}");
            assert!(actual.get("multiplex").is_none());
        }
        for suffix in [
            "&mux=true&concurrency=8",
            "&mux=1",
            "&mux=maybe",
            "&concurrency=8&concurrency=4",
            "&concurrency=1.5",
            "&concurrency=99999999999999999999",
            "&concurrency=8&allowInsecure=true",
            "&concurrency=8&unknown=1",
        ] {
            assert!(parse_uri(&format!("{base}{suffix}")).is_err(), "{suffix}");
        }
    }
    assert!(parse_uri("hy2://secret@example.com:443?concurrency=8").is_err());
}

#[test]
fn core_accepts_every_supported_protocol_and_both_modes() {
    assert!(core().exists(), "Run scripts/fetch-core.py before tests");
    let vmess=STANDARD.encode(json!({"v":"2","ps":"test","add":"example.com","port":"443","id":UUID,"aid":"0","scy":"auto","net":"ws","type":"none","host":"example.com","path":"/ws","tls":"tls","sni":"example.com"}).to_string());
    let uris=vec![
        vless(),
        format!("vless://{UUID}@example.com:443?security=reality&pbk={}&sid=aabb&flow=xtls-rprx-vision&concurrency=8",base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1;32])),
        format!("vless://{UUID}@example.com:443?security=tls&type=grpc&serviceName=proxy"),
        format!("vmess://{vmess}"),
        "trojan://secret%3Apassword@example.com:443?sni=example.com".into(),
        "hy2://password@example.com:443?sni=example.com&obfs=salamander&obfs-password=another-secret".into(),
        format!("ss://{}@example.com:443",STANDARD.encode("chacha20-ietf-poly1305:secret")),
    ];
    for uri in uris {
        for mode in [Mode::Local, Mode::Tun] {
            let mut req = request(uri.clone());
            if parse_uri(&uri).unwrap().engine == EngineKind::Xray {
                req.bridge_port = Some(2081);
            }
            let config = generate(&req, mode).unwrap();
            assert_eq!(config["log"], json!({"disabled":true}));
            assert_eq!(config["experimental"]["cache_file"]["enabled"], false);
            let mut child = Command::new(core())
                .args(["check", "-c", "/dev/stdin"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(config.to_string().as_bytes())
                .unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(output.stdout.is_empty());
            assert!(
                output.stderr.is_empty(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

#[test]
fn settings_are_private_atomic_and_do_not_follow_symlinks() {
    let dir = tmp();
    let path = dir.join("velum/settings.json");
    storage::save(&path, &Settings::default()).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let loaded = storage::load(&path).unwrap();
    assert_eq!(loaded.schema, 3);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(storage::load(&path).is_err());
    fs::remove_file(&path).unwrap();
    symlink("/etc/passwd", &path).unwrap();
    assert!(storage::load(&path).is_err());
    // Atomic replace replaces the symlink itself, never its target.
    storage::save(&path, &Settings::default()).unwrap();
    assert!(fs::symlink_metadata(&path).unwrap().is_file());
    fs::remove_dir_all(dir).unwrap();
}

struct Guard(Child);
impl Drop for Guard {
    fn drop(&mut self) {
        velum::process::terminate(&mut self.0);
    }
}
fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn spawn(config: serde_json::Value, dir: &std::path::Path) -> Guard {
    let mut c = Command::new(core())
        .args(["run", "-c", "/dev/stdin"])
        .current_dir(dir)
        .env("HOME", dir)
        .env("XDG_CACHE_HOME", dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin
        .take()
        .unwrap()
        .write_all(config.to_string().as_bytes())
        .unwrap();
    Guard(c)
}
fn socks(proxy: u16, domain: &str, target: u16) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(("127.0.0.1", proxy))?;
    s.set_read_timeout(Some(Duration::from_secs(3)))?;
    s.set_write_timeout(Some(Duration::from_secs(3)))?;
    s.write_all(&[5, 1, 0])?;
    let mut r = [0; 2];
    s.read_exact(&mut r)?;
    let mut msg = vec![5, 1, 0, 3, domain.len() as u8];
    msg.extend(domain.as_bytes());
    msg.extend(target.to_be_bytes());
    s.write_all(&msg)?;
    let mut header = [0; 4];
    s.read_exact(&mut header)?;
    if header[1] != 0 {
        return Err(std::io::Error::other("rejected"));
    }
    let size = match header[3] {
        1 => 4,
        4 => 16,
        _ => return Err(std::io::Error::other("address")),
    };
    let mut rest = vec![0; size + 2];
    s.read_exact(&mut rest)?;
    Ok(s)
}

#[test]
fn real_proxy_transport_routing_and_nologs() {
    let dir = tmp();
    let http = TcpListener::bind("127.0.0.1:0").unwrap();
    let http_port = http.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in http.incoming().take(3) {
            let mut s = s.unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut buf = [0; 2048];
            let _ = s.read(&mut buf);
            let _ = s.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nvelum",
            );
        }
    });
    let remote_port = port();
    let proxy_port = port();
    let mut remote = spawn(
        json!({"log":{"disabled":true},"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":remote_port,"method":"chacha20-ietf-poly1305","password":"test-secret"}],"outbounds":[{"type":"direct"}],"dns":{"servers":[{"type":"hosts","tag":"hosts","predefined":{"example.test":"127.0.0.1","badexample.test":"127.0.0.1"}}],"final":"hosts"},"route":{"default_domain_resolver":"hosts"}}),
        &dir,
    );
    let uri = format!(
        "ss://{}@127.0.0.1:{remote_port}",
        STANDARD.encode("chacha20-ietf-poly1305:test-secret")
    );
    let req = ConnectRequest {
        probe_port: None,
        policies: vec![],
        kill_switch: false,
        bridge_port: None,
        uri,
        bypass: vec!["*.example.test".into()],
        port: proxy_port,
    };
    let mut config = generate(&req, Mode::Local).unwrap();
    // Hermetic DNS: no provider, DNS or Internet traffic in this test.
    config["dns"] = json!({"servers":[{"type":"hosts","tag":"hosts","predefined":{"a.example.test":"127.0.0.1","example.test":"127.0.0.1","badexample.test":"127.0.0.1"}}],"final":"hosts"});
    config["route"]["default_domain_resolver"] = json!("hosts");
    let mut client = spawn(config, &dir);
    velum::process::ready(&mut client.0, proxy_port).unwrap();
    // First use the encrypted transport, then stop the upstream to distinguish routes.
    let mut s = socks(proxy_port, "example.test", http_port).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    s.read_to_string(&mut response).unwrap();
    assert!(response.ends_with("velum"));
    velum::process::terminate(&mut remote.0);
    let mut s = socks(proxy_port, "a.example.test", http_port).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: a.example.test\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    s.read_to_string(&mut response).unwrap();
    assert!(response.ends_with("velum"));
    // SOCKS may acknowledge before dialing; either rejection or failed data is correct.
    for host in ["example.test", "badexample.test"] {
        if let Ok(mut s) = socks(proxy_port, host, http_port) {
            let _ = s.write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes());
            let mut data = String::new();
            let _ = s.read_to_string(&mut data);
            assert!(!data.contains("velum"));
        }
    }
    velum::process::terminate(&mut client.0);
    for child in [&mut remote.0, &mut client.0] {
        let mut out = Vec::new();
        child.stdout.take().unwrap().read_to_end(&mut out).unwrap();
        assert!(out.is_empty());
        let mut err = Vec::new();
        child.stderr.take().unwrap().read_to_end(&mut err).unwrap();
        assert!(err.is_empty(), "{}", String::from_utf8_lossy(&err));
    }
    assert_eq!(
        fs::read_dir(&dir).unwrap().count(),
        0,
        "Runtime must not create logs, configs or caches"
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn supervisor_handles_cancel_and_occupied_port() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let req = ConnectRequest {
        probe_port: None,
        policies: vec![],
        kill_switch: false,
        bridge_port: None,
        uri: vless(),
        bypass: vec![],
        port: listener.local_addr().unwrap().port(),
    };
    let (_session, rx) =
        velum::process::Session::start(req, Mode::Local, std::sync::Arc::new(|| {})).unwrap();
    assert!(matches!(
        rx.recv_timeout(Duration::from_secs(3)).unwrap(),
        velum::process::Event::Failed(_)
    ));
    let req = ConnectRequest {
        probe_port: None,
        policies: vec![],
        kill_switch: false,
        bridge_port: None,
        uri: vless(),
        bypass: vec![],
        port: port(),
    };
    let (mut session, rx) =
        velum::process::Session::start(req, Mode::Local, std::sync::Arc::new(|| {})).unwrap();
    let event = rx.recv_timeout(Duration::from_secs(8)).unwrap();
    assert!(matches!(event, velum::process::Event::Running), "{event:?}");
    session.stop();
    assert!(matches!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        velum::process::Event::Stopped
    ));
}
