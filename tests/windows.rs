#![cfg(windows)]

use eivro::{
    config::{ConnectRequest, Mode},
    platform::windows::{core_child::CoreChild, native::Job},
    process::{self, Event, Session},
};
use serde_json::json;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

struct Upstream {
    port: u16,
    _core: CoreChild,
    _job: Job,
}
fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn upstream(internet: bool) -> Upstream {
    upstream_with_udp(internet, None)
}
fn upstream_with_udp(internet: bool, udp_echo: Option<u16>) -> Upstream {
    let port = port();
    let mut config = json!({"log":{"disabled":true},
        "inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":port,
            "method":"chacha20-ietf-poly1305","password":"eivro-test-only"}],
        "outbounds":[{"type":"direct","tag":"direct"}]});
    if internet {
        let interface =
            eivro::platform::windows::network::uplink("1.1.1.1".parse().unwrap()).unwrap();
        config["outbounds"][0]["bind_interface"] = json!(interface);
        config["dns"] = json!({"servers":[{"type":"https","tag":"resolver","server":"1.1.1.1",
            "path":"/dns-query","tls":{"server_name":"cloudflare-dns.com"},"bind_interface":interface}]});
        config["route"] = json!({"default_domain_resolver":"resolver"});
    }
    if let Some(port) = udp_echo {
        config["outbounds"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type":"direct","tag":"echo"}));
        config["route"]["rules"] = json!([{"ip_cidr":["198.51.100.7/32"],"network":"udp",
            "action":"route","outbound":"echo","override_address":"127.0.0.1","override_port":port}]);
    }
    let job = Job::new().unwrap();
    let core = CoreChild::spawn(
        &process::core_path().unwrap(),
        &["run", "-c", "stdin"],
        config.to_string().as_bytes(),
        &job,
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(!core.exited().unwrap(), "Synthetic upstream exited");
        assert!(
            Instant::now() < deadline,
            "Synthetic upstream did not start"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    Upstream {
        port,
        _core: core,
        _job: job,
    }
}
fn request(upstream: &Upstream, xray: bool) -> ConnectRequest {
    let uri = if xray {
        eivro::xray::profile(&json!({"protocol":"shadowsocks","settings":{"servers":[{
            "address":"127.0.0.1","port":upstream.port,"method":"chacha20-ietf-poly1305",
            "password":"eivro-test-only","uot":false,"UoTVersion":2}]},
            "streamSettings":{"network":"tcp","security":"none","tcpSettings":{}}}))
        .unwrap()
        .uri
    } else {
        format!(
            "ss://chacha20-ietf-poly1305:eivro-test-only@127.0.0.1:{}",
            upstream.port
        )
    };
    ConnectRequest {
        ru_preset: None,
        uri,
        port: port(),
        bridge_port: None,
        probe_port: None,
        policies: vec![],
        bypass: vec![],
        connections: vec![],
        kill_switch: false,
    }
}
fn connected(request: ConnectRequest, mode: Mode) -> (Session, std::sync::mpsc::Receiver<Event>) {
    let (session, rx) = Session::start(request, mode, Arc::new(|| {})).unwrap();
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let event = rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("Connection timed out");
        match event {
            Event::Running => return (session, rx),
            Event::Progress(_) => {}
            other => panic!("Connection failed: {other:?}"),
        }
    }
}
fn assert_http(proxy: u16) {
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    server.set_nonblocking(true).unwrap();
    let destination = server.local_addr().unwrap().port();
    let responder = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut socket = loop {
            match server.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "Fixture HTTP accept timed out");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("Fixture HTTP failed: {e}"),
            }
        };
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = [0; 1024];
        assert!(socket.read(&mut request).unwrap() > 0);
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\neivro")
            .unwrap();
    });
    let output = Command::new("curl.exe")
        .args([
            "-q",
            "--silent",
            "--show-error",
            "--max-time",
            "10",
            "--noproxy",
            "",
            "--socks5-hostname",
            &format!("127.0.0.1:{proxy}"),
            &format!("http://127.0.0.1:{destination}/"),
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    responder.join().unwrap();
    assert!(
        output.status.success(),
        "curl: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"eivro");
}
fn stopped(mut session: Session, rx: std::sync::mpsc::Receiver<Event>, port: u16) {
    let start = Instant::now();
    session.stop();
    assert!(matches!(
        rx.recv_timeout(Duration::from_secs(15)).unwrap(),
        Event::Stopped
    ));
    drop(session);
    assert!(start.elapsed() < Duration::from_secs(15));
    assert!(
        TcpListener::bind(("127.0.0.1", port)).is_ok(),
        "Core left the proxy port open"
    );
}
#[test]
fn both_engines_transfer_traffic_and_close_without_orphans() {
    let upstream = upstream(false);
    for xray in [false, true] {
        let request = request(&upstream, xray);
        let port = request.port;
        let (session, rx) = connected(request, Mode::Local);
        assert_http(port);
        stopped(session, rx, port);
    }
}

#[test]
fn friendly_interface_names_are_valid_but_reserved_and_injected_names_are_not() {
    for name in ["Ethernet", "Wi-Fi", "Рабочий VPN", "Ethernet 2"] {
        eivro::network::validate_interface(name).unwrap();
    }
    for name in ["", "Eivro", "line\nbreak", "embedded\0NUL"] {
        assert!(
            eivro::network::validate_interface(name).is_err(),
            "{name:?}"
        );
    }
}

#[test]
#[ignore = "Changes only the explicitly authorized disposable Windows lab's network"]
fn installed_tunnel_passes_https_and_restores_adapter() {
    assert_eq!(std::env::var("EIVRO_WINDOWS_LAB").as_deref(), Ok("1"));
    assert!(
        process::helper_compatible(),
        "Install the matching package first"
    );
    let echo = UdpEcho::new();
    let upstream = upstream_with_udp(true, Some(echo.port));
    for xray in [false, true] {
        let request = request(&upstream, xray);
        let port = request.port;
        let (session, rx) = connected(request, Mode::Tun);
        let output = Command::new("curl.exe")
            .args([
                "-q",
                // The synthetic remote is bound to this lab's IPv4-only uplink.
                "-4",
                "--silent",
                "--show-error",
                "--max-time",
                "20",
                "--noproxy",
                "*",
                "--output",
                "NUL",
                "--write-out",
                "%{http_code}",
                "https://example.com/",
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let passed = output.status.success() && output.stdout == b"200";
        let udp = UdpSocket::bind("0.0.0.0:0").unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        udp.send_to(b"eivro-udp", "198.51.100.7:32190").unwrap();
        let mut packet = [0; 64];
        let received = udp.recv_from(&mut packet);
        stopped(session, rx, port);
        assert!(
            passed,
            "TUN HTTPS failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(received.unwrap().0, 9, "UDP did not cross the tunnel");
        assert_eq!(&packet[..9], b"eivro-udp");
    }
}

struct UdpEcho {
    port: u16,
    stop: Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl UdpEcho {
    fn new() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = std::thread::spawn(move || {
            let mut packet = [0; 512];
            while !stopped.load(std::sync::atomic::Ordering::Acquire) {
                if let Ok((length, peer)) = socket.recv_from(&mut packet) {
                    socket.send_to(&packet[..length], peer).unwrap();
                }
            }
        });
        Self {
            port,
            stop,
            worker: Some(worker),
        }
    }
}
impl Drop for UdpEcho {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

fn wait_tunnel_gone(port: u16) {
    use windows_sys::Win32::NetworkManagement::{
        IpHelper::{ConvertInterfaceAliasToLuid, GetIfEntry2, MIB_IF_ROW2},
        Ndis::{IfOperStatusUp, NET_LUID_LH},
    };
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
        let absent = unsafe {
            ConvertInterfaceAliasToLuid(
                eivro::platform::windows::native::wide("Eivro").as_ptr(),
                &mut luid,
            )
        } != 0;
        let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
        row.InterfaceLuid = luid;
        // Windows may retain the alias-to-LUID mapping briefly after device removal.
        let inactive =
            absent || unsafe { GetIfEntry2(&mut row) } != 0 || row.OperStatus != IfOperStatusUp;
        let listener_free = TcpListener::bind(("127.0.0.1", port)).is_ok();
        if inactive && listener_free {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Owner cleanup incomplete: tunnel inactive={inactive}, listener free={listener_free}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn service_xray_process() -> (u32, u32) {
    use eivro::platform::windows::native::{from_wide, owned, raw};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
    let snapshot = unsafe { owned(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) }.unwrap();
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of_val(&entry) as u32;
    let mut next = unsafe { Process32FirstW(raw(&snapshot), &mut entry) } != 0;
    while next {
        if unsafe { from_wide(entry.szExeFile.as_ptr()) } == "xray.exe"
            && eivro::platform::windows::service::is_service_process(entry.th32ParentProcessID)
        {
            return (entry.th32ProcessID, entry.th32ParentProcessID);
        }
        next = unsafe { Process32NextW(raw(&snapshot), &mut entry) } != 0;
    }
    panic!("No Xray child belonging to the lab's installed service");
}
fn terminate_lab_process(pid: u32) {
    use eivro::platform::windows::native::{owned, raw, wait};
    use windows_sys::Win32::System::Threading::*;
    let handle = unsafe {
        owned(OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | 0x0010_0000,
            0,
            pid,
        ))
    }
    .unwrap();
    let mut path = [0u16; 32768];
    let mut size = path.len() as u32;
    assert_ne!(
        unsafe { QueryFullProcessImageNameW(raw(&handle), 0, path.as_mut_ptr(), &mut size) },
        0
    );
    let path = String::from_utf16_lossy(&path[..size as usize]);
    let root = eivro::platform::windows::native::installed_dir().unwrap();
    assert!(
        path == root.join("xray.exe").to_string_lossy()
            || path == root.join("eivro-tun.exe").to_string_lossy()
    );
    assert_ne!(unsafe { TerminateProcess(raw(&handle), 1) }, 0);
    assert!(wait(&[raw(&handle)], 5000).unwrap().is_some());
}

#[test]
#[ignore = "Kills only the installed lab tunnel's own core/service; requires an explicit disposable-lab grant"]
fn windows_lab_tunnel_recovers_from_client_core_and_service_loss() {
    use eivro::platform::{
        windows::pipe::Pipe,
        wire::{self, Reply, Request},
    };
    assert_eq!(std::env::var("EIVRO_WINDOWS_LAB").as_deref(), Ok("1"));
    let upstream = upstream(true);
    println!("Lab: client channel loss");
    // Closing the connection without Stop exercises the same kernel EOF as a
    // GUI process disappearing; the service owns and must stop both cores.
    let mut req = request(&upstream, true);
    req.bridge_port = Some(port());
    req.probe_port = Some(port());
    let local_port = req.port;
    let mut pipe = Pipe::client().unwrap();
    assert!(matches!(
        wire::receive::<Reply>(&mut pipe).unwrap(),
        Reply::Hello { .. }
    ));
    wire::send(
        &mut pipe,
        &Request::Start {
            request: req,
            mode: Mode::Tun,
            authorization: None,
        },
    )
    .unwrap();
    loop {
        match wire::receive::<Reply>(&mut pipe).unwrap() {
            Reply::Checking => {}
            Reply::Ready => break,
            _ => panic!("Raw client failed to connect"),
        }
    }
    drop(pipe);
    wait_tunnel_gone(local_port);
    for crash_service in [false, true] {
        println!(
            "Lab: {} loss",
            if crash_service { "service" } else { "core" }
        );
        let req = request(&upstream, true);
        let local_port = req.port;
        let (session, rx) = connected(req, Mode::Tun);
        let (core, service) = service_xray_process();
        terminate_lab_process(if crash_service { service } else { core });
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(12)).unwrap(),
            Event::Failed(_)
        ));
        drop(session);
        wait_tunnel_gone(local_port);
        if crash_service {
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                if Pipe::client().is_ok() {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "SCM did not recover the lab service"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    let req = request(&upstream, true);
    println!("Lab: reconnect after recovery");
    let local_port = req.port;
    let (session, rx) = connected(req, Mode::Tun);
    stopped(session, rx, local_port);
    wait_tunnel_gone(local_port);
}

#[test]
#[ignore = "Uses the lab's external network to verify the synthetic upstream"]
fn lab_upstream_https_before_tunnel() {
    assert_eq!(std::env::var("EIVRO_WINDOWS_LAB").as_deref(), Ok("1"));
    let upstream = upstream(true);
    let request = request(&upstream, false);
    let port = request.port;
    let (session, rx) = connected(request, Mode::Local);
    let output = Command::new("curl.exe")
        .args([
            "-q",
            "-4",
            "--silent",
            "--show-error",
            "--max-time",
            "15",
            "--noproxy",
            "",
            "--proxy",
            &format!("http://127.0.0.1:{port}"),
            "--output",
            "NUL",
            "--write-out",
            "%{http_code}",
            "https://example.com/",
        ])
        .output()
        .unwrap();
    stopped(session, rx, port);
    assert!(
        output.status.success() && output.stdout == b"200",
        "Upstream HTTPS: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

struct PrivateSite {
    address: std::net::Ipv4Addr,
    port: u16,
    queries: Arc<std::sync::atomic::AtomicUsize>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    workers: Vec<std::thread::JoinHandle<()>>,
}
impl PrivateSite {
    fn new() -> Self {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let probe = UdpSocket::bind("0.0.0.0:0").unwrap();
        probe.connect("1.1.1.1:53").unwrap();
        let std::net::IpAddr::V4(address) = probe.local_addr().unwrap().ip() else {
            panic!("IPv4 lab required")
        };
        let dns = UdpSocket::bind((address, 53))
            .expect("The private lab DNS fixture needs a free port 53");
        dns.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let web = TcpListener::bind((address, 0)).unwrap();
        let port = web.local_addr().unwrap().port();
        web.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let queries = Arc::new(AtomicUsize::new(0));
        let stopped = stop.clone();
        let count = queries.clone();
        let dns_worker = std::thread::spawn(move || {
            let mut packet = [0; 4096];
            while !stopped.load(Ordering::Acquire) {
                let Ok((length, peer)) = dns.recv_from(&mut packet) else {
                    continue;
                };
                if length < 17 {
                    continue;
                }
                let mut end = 12;
                while end < length && packet[end] > 0 && packet[end] < 64 {
                    end += 1 + packet[end] as usize;
                }
                if end + 5 > length || packet[end] != 0 {
                    continue;
                }
                let is_a = packet[end + 1..end + 3] == [0, 1];
                end += 5;
                let mut reply = packet[..2].to_vec();
                reply.extend_from_slice(&[0x81, 0x80, 0, 1, 0, u8::from(is_a), 0, 0, 0, 0]);
                reply.extend_from_slice(&packet[12..end]);
                if is_a {
                    reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
                    reply.extend_from_slice(&address.octets());
                }
                count.fetch_add(1, Ordering::Relaxed);
                let _ = dns.send_to(&reply, peer);
            }
        });
        let stopped = stop.clone();
        let http_worker = std::thread::spawn(move || {
            while !stopped.load(Ordering::Acquire) {
                if let Ok((mut socket, _)) = web.accept() {
                    socket
                        .set_read_timeout(Some(Duration::from_millis(500)))
                        .unwrap();
                    let mut request = [0; 2048];
                    if socket.read(&mut request).is_ok_and(|n| n > 0) {
                        let _=socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nprivate");
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        });
        Self {
            address,
            port,
            queries,
            stop,
            workers: vec![dns_worker, http_worker],
        }
    }
}
impl Drop for PrivateSite {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        for worker in self.workers.drain(..) {
            worker.join().unwrap();
        }
    }
}

#[test]
#[ignore = "Uses private DNS and the installed TUN in the explicitly authorized Windows lab"]
fn windows_lab_named_exit_resolves_private_domains_and_rejects_missing_adapter() {
    use eivro::{
        network::{Connection, Dns},
        policy::{Action, PolicyRule, Target},
    };
    use std::sync::atomic::Ordering;
    assert_eq!(std::env::var("EIVRO_WINDOWS_LAB").as_deref(), Ok("1"));
    let site = PrivateSite::new();
    let upstream = upstream(true);
    let interface = eivro::platform::windows::network::uplink("1.1.1.1".parse().unwrap()).unwrap();
    for (mode, available) in [(Mode::Local, true), (Mode::Tun, true), (Mode::Local, false)] {
        let mut req = request(&upstream, false);
        let port = req.port;
        req.connections = vec![Connection {
            id: 1,
            name: "Private lab".into(),
            interface: if available {
                interface.clone()
            } else {
                "Missing lab adapter".into()
            },
            dns: Dns::Manual(vec![site.address.into()]),
        }];
        req.policies = vec![PolicyRule {
            enabled: true,
            target: Target::address("intranet.lab.test").unwrap(),
            action: Action::Connection(1),
        }];
        let before = site.queries.load(Ordering::Relaxed);
        let (session, rx) = connected(req, mode);
        let response = Command::new("curl.exe")
            .args([
                "-q",
                "-4",
                "--silent",
                "--show-error",
                "--max-time",
                "5",
                "--fail",
                "--noproxy",
                "",
                "--proxy",
                &format!("http://127.0.0.1:{port}"),
                &format!("http://intranet.lab.test:{}/", site.port),
            ])
            .output()
            .unwrap();
        stopped(session, rx, port);
        if available {
            assert!(
                response.status.success(),
                "Private DNS/exit failed ({}, queries {} -> {}): {}",
                if mode == Mode::Tun { "TUN" } else { "Local" },
                before,
                site.queries.load(Ordering::Relaxed),
                String::from_utf8_lossy(&response.stderr)
            );
            assert_eq!(response.stdout, b"private");
            assert!(site.queries.load(Ordering::Relaxed) > before);
        } else {
            assert!(!response.status.success());
            assert_eq!(
                site.queries.load(Ordering::Relaxed),
                before,
                "Unavailable exit still queried its DNS"
            );
        }
    }
}

#[test]
#[ignore = "Tests process-based routing through the installed Windows lab TUN"]
fn windows_lab_application_paths_match_windows_case_and_separator_rules() {
    use eivro::{
        network::{Connection, Dns},
        policy::{Action, PolicyRule, Target},
    };
    assert_eq!(std::env::var("EIVRO_WINDOWS_LAB").as_deref(), Ok("1"));
    let upstream = upstream(true);
    let windows = std::env::var("SystemRoot").unwrap();
    for blocked in [false, true, false] {
        let mut req = request(&upstream, false);
        let port = req.port;
        req.connections = vec![Connection {
            id: 1,
            name: "Unplugged lab".into(),
            interface: "Missing lab adapter".into(),
            dns: Dns::Manual(vec!["1.1.1.1".parse().unwrap()]),
        }];
        req.policies = vec![PolicyRule {
            enabled: blocked,
            target: Target::application(&format!("{windows}/sYsTeM32/CuRl.ExE")).unwrap(),
            action: Action::Connection(1),
        }];
        let (session, rx) = connected(req, Mode::Tun);
        let result = Command::new(format!("{windows}\\System32\\curl.exe"))
            .args([
                "-q",
                "-4",
                "--silent",
                "--show-error",
                "--max-time",
                "10",
                "--noproxy",
                "*",
                "--output",
                "NUL",
                "https://example.com/",
            ])
            .status()
            .unwrap();
        stopped(session, rx, port);
        assert_eq!(
            result.success(),
            !blocked,
            "Process rule did not follow Windows path semantics"
        );
    }
}
