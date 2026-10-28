use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};
use velum::{
    config::{ConnectRequest, Mode, generate},
    import::{EngineKind, parse_uri},
    process::{self, Event, Session},
    subscription::import_bytes,
    xray,
};

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/mixed-xray.json")).unwrap()
}
fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn request(uri: String, port: u16) -> ConnectRequest {
    ConnectRequest {
        probe_port: None,
        policies: vec![],
        kill_switch: false,
        uri,
        port,
        bypass: vec![],
        bridge_port: None,
    }
}

#[test]
fn real_provider_shapes_preserve_transports_and_pass_both_cores() {
    let profiles = import_bytes(include_bytes!("fixtures/mixed-xray.json")).unwrap();
    assert_eq!(profiles.len(), 5);
    process::validate_profiles(&profiles).unwrap();
    for profile in profiles {
        let parsed = parse_uri(&profile.uri).unwrap();
        assert!(parsed.engine == EngineKind::Xray);
        let c = xray::config(parsed.outbound.clone(), 2081);
        assert_eq!(
            c["log"],
            json!({"access":"none","error":"none","loglevel":"none","dnsLog":false})
        );
        assert!(!c.to_string().contains("should-not-be-used"));
        assert!(c.get("stats").is_none() && c.get("observatory").is_none());
        if parsed.protocol == "hysteria2" {
            assert_eq!(
                parsed.outbound["streamSettings"]["finalmask"]["quicParams"]["debug"],
                false
            );
        }
        let req = ConnectRequest {
            probe_port: None,
            policies: vec![],
            kill_switch: false,
            bridge_port: Some(2081),
            ..request(profile.uri, 2080)
        };
        for mode in [Mode::Local, Mode::Tun] {
            let config = generate(&req, mode).unwrap();
            assert_eq!(config["outbounds"][0]["type"], "socks");
            assert_eq!(config["outbounds"][0]["server"], "127.0.0.1");
            assert_eq!(config["log"]["disabled"], true);
            let mut child = Command::new(process::core_path().unwrap())
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
            let result = child.wait_with_output().unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }
}

#[test]
fn tcp_reality_links_use_xray_and_preserve_authentication_and_transport() {
    let public_key = URL_SAFE_NO_PAD.encode([1; 32]);
    let base = format!(
        "vless://a3ba7b44-3275-42e7-9a54-30aa2bde0437@edge.example:443?security=reality&pbk={public_key}&sid=aabbccdd&sni=cover.example&fp=chrome&spx=%2F&encryption=none"
    );
    for transport in ["", "&type=tcp"] {
        for flow in ["", "&flow=xtls-rprx-vision"] {
            let uri = format!("{base}{transport}{flow}");
            let parsed = parse_uri(&uri).unwrap();
            assert!(parsed.engine == EngineKind::Xray);
            let out = &parsed.outbound;
            let remote = &out["settings"]["vnext"][0];
            assert_eq!(remote["address"], "edge.example");
            assert_eq!(remote["port"], 443);
            assert_eq!(
                remote["users"][0]["id"],
                "a3ba7b44-3275-42e7-9a54-30aa2bde0437"
            );
            assert_eq!(remote["users"][0]["encryption"], "none");
            assert_eq!(
                remote["users"][0]["flow"],
                if flow.is_empty() {
                    ""
                } else {
                    "xtls-rprx-vision"
                }
            );
            let stream = &out["streamSettings"];
            assert_eq!(stream["network"], "tcp");
            assert_eq!(stream["security"], "reality");
            assert!(stream.get("xhttpSettings").is_none());
            assert!(stream.get("tlsSettings").is_none());
            assert_eq!(stream["realitySettings"]["serverName"], "cover.example");
            assert_eq!(stream["realitySettings"]["publicKey"], public_key);
            assert_eq!(stream["realitySettings"]["shortId"], "aabbccdd");
            assert_eq!(stream["realitySettings"]["fingerprint"], "chrome");
            assert_eq!(stream["realitySettings"]["spiderX"], "/");
            assert_eq!(stream["realitySettings"]["show"], false);
            process::validate_profiles(&import_bytes(uri.as_bytes()).unwrap()).unwrap();
            let req = ConnectRequest {
                bridge_port: Some(2081),
                ..request(uri.clone(), 2080)
            };
            for mode in [Mode::Local, Mode::Proxy, Mode::Tun] {
                let config = generate(&req, mode).unwrap();
                assert_eq!(config["outbounds"][0]["type"], "socks");
                assert_eq!(config["outbounds"][0]["server_port"], 2081);
            }
        }
    }
    for suffix in [
        "&mode=stream-one",
        "&extra=%7B%7D",
        "&path=%2Fxhttp",
        "&serviceName=grpc",
        "&headerType=http",
        "&allowInsecure=true",
    ] {
        assert!(parse_uri(&format!("{base}{suffix}")).is_err(), "{suffix}");
    }
    let tls = base.replace("security=reality", "security=tls");
    // Reality-only fields must still be rejected when the security changes.
    assert!(parse_uri(&tls).is_err());
    let plain_tls =
        "vless://a3ba7b44-3275-42e7-9a54-30aa2bde0437@edge.example:443?security=tls&type=tcp";
    assert!(parse_uri(plain_tls).unwrap().engine == EngineKind::SingBox);
}

#[test]
fn xhttp_links_keep_mode_and_ignore_only_known_provider_annotations() {
    let uri = format!(
        "vless://a3ba7b44-3275-42e7-9a54-30aa2bde0437@edge.example:443?security=reality&type=xhttp&mode=stream-one&path=%2Fstream&pbk={}&sid=aabbccdd&fp=chrome&concurrency=4&x-durev-block=group&x-durev-prio=1",
        URL_SAFE_NO_PAD.encode([1; 32])
    );
    let parsed = parse_uri(&uri).unwrap();
    assert!(parsed.engine == EngineKind::Xray);
    assert_eq!(
        parsed.outbound["streamSettings"]["xhttpSettings"]["mode"],
        "stream-one"
    );
    assert_eq!(
        parsed.outbound["streamSettings"]["xhttpSettings"]["path"],
        "/stream"
    );
    assert!(!parsed.outbound.to_string().contains("x-durev"));
    let profiles = import_bytes(
        base64::engine::general_purpose::STANDARD
            .encode(&uri)
            .as_bytes(),
    )
    .unwrap();
    process::validate_profiles(&profiles).unwrap();
    assert!(parse_uri(&uri.replace("stream-one", "invalid-mode")).is_err());
    assert!(parse_uri(&(uri + "&unknown_tls_override=1")).is_err());
}

#[test]
fn xhttp_session_fields_migrate_saved_profiles_and_validate_new_names() {
    let source = fixture();
    let mut outbound = source
        .as_array()
        .unwrap()
        .iter()
        .map(|config| &config["outbounds"][0])
        .find(|out| {
            out["streamSettings"]["network"] == "xhttp"
                && out["streamSettings"]["security"] == "tls"
        })
        .unwrap()
        .clone();
    let canonical = json!({"sessionIDPlacement":"header","sessionIDKey":"X-Velum-Session"});
    outbound["streamSettings"]["xhttpSettings"]["extra"] =
        json!({"sessionPlacement":"header","sessionKey":"X-Velum-Session"});
    // Old stored URIs bypass profile(), so exercise normalization during loading.
    let saved = format!(
        "{}{}",
        xray::PREFIX,
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&outbound).unwrap())
    );
    assert_eq!(
        parse_uri(&saved).unwrap().outbound["streamSettings"]["xhttpSettings"]["extra"],
        canonical
    );
    let mut profiles = vec![xray::profile(&outbound).unwrap()];
    outbound["streamSettings"]["xhttpSettings"]["extra"] = canonical.clone();
    profiles.push(xray::profile(&outbound).unwrap());
    assert_eq!(profiles[0].uri, profiles[1].uri);
    process::validate_profiles(&profiles).unwrap();
    for (old, new) in [
        ("sessionPlacement", "sessionIDPlacement"),
        ("sessionKey", "sessionIDKey"),
    ] {
        let mut duplicate = outbound.clone();
        duplicate["streamSettings"]["xhttpSettings"]["extra"][old] = canonical[new].clone();
        assert_eq!(xray::profile(&duplicate).unwrap().uri, profiles[1].uri);
        duplicate["streamSettings"]["xhttpSettings"]["extra"][old] = json!("conflicting-value");
        assert!(xray::profile(&duplicate).is_err());
    }
    let mut invalid = outbound;
    invalid["streamSettings"]["xhttpSettings"]["extra"]["sessionIDPlacement"] = json!("invalid");
    assert!(process::validate_profiles(&[xray::profile(&invalid).unwrap()]).is_err());
}

#[test]
fn native_json_rejects_paths_dialer_injection_insecure_tls_and_wrong_core_types() {
    let source = fixture();
    let original = source[2]["outbounds"][0].clone();
    // Find the actual TLS XHTTP record, without depending on fixture ordering.
    let tls = source
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["outbounds"][0]["streamSettings"]["security"] == "tls"
                && c["outbounds"][0]["protocol"] == "vless"
        })
        .unwrap()["outbounds"][0]
        .clone();
    for key in ["certificateFile", "keyFile", "allowInsecure"] {
        let mut v = tls.clone();
        v["streamSettings"]["tlsSettings"][key] = if key == "allowInsecure" {
            json!(true)
        } else {
            json!("/tmp/secret")
        };
        assert!(xray::profile(&v).is_err());
    }
    let mut v = original.clone();
    v["proxySettings"] = json!({"tag":"external"});
    assert!(xray::profile(&v).is_err());
    let mut v = tls.clone();
    v["streamSettings"]["sockopt"] = json!({"dialerProxy":"external"});
    assert!(xray::profile(&v).is_err());
    let mut v = tls.clone();
    v["streamSettings"]["realitySettings"] = json!({"certificateFile":"/tmp/secret"});
    assert!(xray::profile(&v).is_err());
    let mut v = tls;
    v["streamSettings"]["xhttpSettings"]["extra"]["scMaxBufferedPosts"] = json!("not-a-number");
    let p = xray::profile(&v).unwrap();
    assert!(process::validate_profiles(&[p]).is_err());
}

struct Guard(Child);
impl Drop for Guard {
    fn drop(&mut self) {
        process::terminate(&mut self.0);
    }
}

fn running_xray_children() -> BTreeSet<u32> {
    let mut result = BTreeSet::new();
    for task in fs::read_dir("/proc/self/task").unwrap().flatten() {
        let children = fs::read_to_string(task.path().join("children")).unwrap_or_default();
        for pid in children
            .split_whitespace()
            .filter_map(|s| s.parse::<u32>().ok())
        {
            let Ok(cmd) = fs::read(format!("/proc/{pid}/cmdline")) else {
                continue;
            };
            let args: Vec<_> = cmd.split(|b| *b == 0).filter(|b| !b.is_empty()).collect();
            if args.len() == 4
                && args[0].ends_with(b"/vendor/xray")
                && args[1] == b"run"
                && args[2] == b"-config"
                && args[3] == b"stdin:"
            {
                result.insert(pid);
            }
        }
    }
    result
}

#[test]
fn xray_bridge_transfers_traffic_and_core_exit_stops_the_session() {
    let http = TcpListener::bind("127.0.0.1:0").unwrap();
    let http_port = http.local_addr().unwrap().port();
    let responder = std::thread::spawn(move || {
        let (mut s, _) = http.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut request = [0; 1024];
        assert!(s.read(&mut request).unwrap() > 0);
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nxray!")
            .unwrap();
    });
    let upstream_port = port();
    let local_port = port();
    let config = json!({"log":{"disabled":true},"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":upstream_port,"method":"chacha20-ietf-poly1305","password":"synthetic"}],"outbounds":[{"type":"direct"}]});
    let mut remote = Guard(
        Command::new(process::core_path().unwrap())
            .args(["run", "-c", "/dev/stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    remote
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(config.to_string().as_bytes())
        .unwrap();
    let v = json!({"protocol":"shadowsocks","settings":{"servers":[{"address":"127.0.0.1","port":upstream_port,"method":"chacha20-ietf-poly1305","password":"synthetic","uot":false,"UoTVersion":2}]},"streamSettings":{"network":"tcp","security":"none","tcpSettings":{}}});
    let profile = xray::profile(&v).unwrap();
    let before = running_xray_children();
    let (session, rx) = Session::start(
        request(profile.uri, local_port),
        Mode::Local,
        Arc::new(|| {}),
    )
    .unwrap();
    let event = rx.recv_timeout(Duration::from_secs(8)).unwrap();
    assert!(matches!(event, Event::Running), "{event:?}");
    let mut sock = TcpStream::connect(("127.0.0.1", local_port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    sock.write_all(&[5, 1, 0]).unwrap();
    let mut auth = [0; 2];
    sock.read_exact(&mut auth).unwrap();
    assert_eq!(auth, [5, 0]);
    let mut req = vec![5, 1, 0, 1, 127, 0, 0, 1];
    req.extend(http_port.to_be_bytes());
    sock.write_all(&req).unwrap();
    let mut reply = [0; 10];
    sock.read_exact(&mut reply).unwrap();
    assert_eq!(reply[1], 0);
    sock.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let mut body = String::new();
    sock.read_to_string(&mut body).unwrap();
    assert!(body.ends_with("xray!"));
    responder.join().unwrap();
    let owned: Vec<_> = running_xray_children()
        .difference(&before)
        .copied()
        .collect();
    assert_eq!(owned.len(), 1);
    // Only a child of this test process, with the exact supervised command line.
    assert_eq!(unsafe { libc::kill(owned[0] as i32, libc::SIGTERM) }, 0);
    assert!(matches!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Event::Failed(_)
    ));
    drop(session);
    assert!(TcpListener::bind(("127.0.0.1", local_port)).is_ok());
    assert_eq!(running_xray_children(), before);
}
