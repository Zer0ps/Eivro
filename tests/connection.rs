use eivro::{
    config::{ConnectRequest, Mode},
    process::{self, Event, Session},
};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn request() -> ConnectRequest {
    ConnectRequest {
        connections: vec![],
        uri: format!("ss://chacha20-ietf-poly1305:synthetic@127.0.0.1:{}", port()),
        port: port(),
        bridge_port: None,
        probe_port: None,
        policies: vec![],
        kill_switch: false,
        bypass: vec!["127.0.0.1".into()],
    }
}
#[test]
fn health_check_cannot_succeed_through_a_direct_routing_exception() {
    let http = TcpListener::bind("127.0.0.1:0").unwrap();
    let http_port = http.local_addr().unwrap().port();
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    let responder = std::thread::spawn(move || {
        for incoming in http.incoming() {
            let mut s = incoming.unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut b = [0; 1024];
            if s.read(&mut b).unwrap_or(0) == 0 {
                break;
            }
            count.fetch_add(1, Ordering::Relaxed);
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
        }
    });
    let mut req = request();
    req.probe_port = Some(port());
    let mut core = process::spawn_core(&process::core_path().unwrap(), &req, Mode::Local).unwrap();
    process::ready(&mut core, req.port).unwrap();
    let url = format!("http://127.0.0.1:{http_port}/");
    let direct = eivro::connectivity::check_url(req.port, &url);
    let proxy = eivro::connectivity::check_url(req.probe_port.unwrap(), &url);
    process::terminate(&mut core);
    drop(TcpStream::connect(("127.0.0.1", http_port)).unwrap());
    responder.join().unwrap();
    assert!(direct.is_ok());
    assert!(proxy.is_err());
    assert_eq!(requests.load(Ordering::Relaxed), 1);
}
#[test]
fn failed_remote_check_never_reports_connected() {
    let req = request();
    let local_port = req.port;
    let (session, events) = Session::start(req, Mode::Proxy, Arc::new(|| {})).unwrap();
    loop {
        match events.recv_timeout(Duration::from_secs(18)).unwrap() {
            Event::Running => panic!("A dead upstream must not report connected"),
            Event::Failed(_) => break,
            Event::Progress(_) => {}
            Event::Stopped => panic!("Expected connection failure"),
        }
    }
    drop(session);
    assert!(TcpListener::bind(("127.0.0.1", local_port)).is_ok());
}
#[test]
fn real_gnome_settings_recover_on_stop_and_crash() {
    let result = Command::new("python3")
        .args([
            "scripts/check-proxy-settings.py",
            env!("CARGO_BIN_EXE_eivro"),
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn stalled_upstream_check_is_bounded_and_releases_the_proxy_port() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    upstream.set_nonblocking(true).unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stopping = stop.clone();
    // Keep TCP connections open without answering the encrypted upstream request.
    let blackhole = std::thread::spawn(move || {
        let mut connections = Vec::new();
        while !stopping.load(Ordering::Relaxed) {
            match upstream.accept() {
                Ok((connection, _)) => connections.push(connection),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("{e}"),
            }
        }
    });
    let mut req = request();
    req.uri = format!("ss://chacha20-ietf-poly1305:synthetic@127.0.0.1:{upstream_port}");
    let local_port = req.port;
    let (session, events) = Session::start(req, Mode::Proxy, Arc::new(|| {})).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(25);
    let result = loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match events.recv_timeout(remaining) {
            Ok(Event::Progress(_)) => continue,
            result => break result,
        }
    };
    drop(session);
    stop.store(true, Ordering::Relaxed);
    blackhole.join().unwrap();
    assert!(
        matches!(result, Ok(Event::Failed(ref error)) if error.contains("Истекло время")),
        "{result:?}"
    );
    assert!(TcpListener::bind(("127.0.0.1", local_port)).is_ok());
}
