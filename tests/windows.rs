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
        // Winsock inherits FIONBIO from the listening socket on accept.
        socket.set_nonblocking(false).unwrap();
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
fn websocket_mux_transfers_concurrent_streams_with_verified_tls() {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/windows-test-tls.ps1");
    let generated = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(source)
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "Could not generate disposable loopback TLS fixture"
    );
    let fixture: serde_json::Value = serde_json::from_slice(&generated.stdout).unwrap();
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_port = target.local_addr().unwrap().port();
    let server_port = port();
    let proxy_port = port();
    let job = Job::new().unwrap();
    let spawn = |config: serde_json::Value, listening| {
        let core = CoreChild::spawn(
            &process::xray_path().unwrap(),
            &["run", "-config", "stdin:"],
            config.to_string().as_bytes(),
            &job,
        )
        .unwrap();
        let due = Instant::now() + Duration::from_secs(8);
        while TcpStream::connect(("127.0.0.1", listening)).is_err() {
            assert!(
                !core.exited().unwrap() && Instant::now() < due,
                "Xray listener failed"
            );
            std::thread::sleep(Duration::from_millis(15));
        }
        core
    };
    const ID: &str = "a3ba7b44-3275-42e7-9a54-30aa2bde0437";
    let _server = spawn(
        json!({
            "log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":server_port,"protocol":"vless",
            "settings":{"clients":[{"id":ID}],"decryption":"none"},"streamSettings":{"network":"ws","security":"tls",
            "wsSettings":{"path":"/edge","host":"mux.eivro.test"},"tlsSettings":{"alpn":["http/1.1"],"certificates":[fixture]}}}],
            "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","network":"tcp","ip":["127.0.0.1/32"],"port":target_port}]}}]
        }),
        server_port,
    );
    let link = format!(
        "vless://{ID}@127.0.0.1:{server_port}?security=tls&type=ws&sni=mux.eivro.test&host=mux.eivro.test&path=%2Fedge&alpn=http%2F1.1&fp=chrome&mux=true&muxConcurrency=8"
    );
    let mut outbound = eivro::import::parse_uri(&link).unwrap().outbound;
    outbound["streamSettings"]["tlsSettings"]["certificates"] =
        json!([{"usage":"verify","certificate":fixture["certificate"]}]);
    let _client = spawn(eivro::xray::config(outbound, proxy_port), proxy_port);
    let fetch = || {
        Command::new("curl.exe")
            .args([
                "-q",
                "--silent",
                "--fail",
                "--max-time",
                "8",
                "--noproxy",
                "",
                "--socks5-hostname",
                &format!("127.0.0.1:{proxy_port}"),
                &format!("http://127.0.0.1:{target_port}/"),
            ])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let requests = [fetch(), fetch()];
    target.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    for _ in &requests {
        let mut socket = loop {
            match target.accept() {
                Ok((stream, _)) => break stream,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(e) => panic!("Loopback Mux did not deliver request: {e}"),
            }
        };
        socket.set_nonblocking(false).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            socket.read_exact(&mut byte).unwrap();
            headers.push(byte[0]);
            assert!(headers.len() < 4096);
        }
        assert!(headers.starts_with(b"GET / HTTP/1.1\r\n"));
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
    }
    for request in requests {
        let response = request.wait_with_output().unwrap();
        assert!(response.status.success());
        assert_eq!(response.stdout, b"ok");
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
        // UDP binding uses the ordinary system route, just like a user's app.
        // A single lost datagram must not decide this availability check.
        let destination = "198.51.100.7:32190"
            .parse::<std::net::SocketAddr>()
            .unwrap();
        let mut sources = Vec::new();
        let baseline = echo.received.load(std::sync::atomic::Ordering::Relaxed);
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut packet = [0; 64];
        let mut attempts = 0;
        let mut last = None;
        let mut echoed = false;
        while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            if remaining.is_zero() {
                break;
            }
            // A connected UDP socket keeps the source chosen on its first
            // connect. A fresh ordinary socket samples route convergence.
            let udp = UdpSocket::bind("0.0.0.0:0").unwrap();
            udp.connect(destination).unwrap();
            let source = udp.local_addr().unwrap().ip();
            if sources.last() != Some(&source) {
                sources.push(source);
            }
            udp.set_read_timeout(Some(remaining.min(Duration::from_secs(1))))
                .unwrap();
            attempts += 1;
            if let Err(e) = udp.send(b"eivro-udp") {
                last = e.raw_os_error();
                break;
            }
            match udp.recv(&mut packet) {
                Ok(n) if &packet[..n] == b"eivro-udp" => {
                    echoed = true;
                    break;
                }
                Ok(_) => break,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    last = e.raw_os_error();
                }
                Err(e) => {
                    last = e.raw_os_error();
                    break;
                }
            }
        }
        let received_by_echo = echo.received.load(std::sync::atomic::Ordering::Relaxed) - baseline;
        let evidence = if echoed {
            None
        } else {
            // Independent paths to the same synthetic echo distinguish source
            // selection, TUN ingestion, and proxy-to-upstream delivery. Neither
            // control can substitute for the mandatory wildcard-socket reply.
            Some((
                udp_route_context(destination.ip()),
                bound_echo(destination),
                mixed_udp_echo(port, destination),
            ))
        };
        stopped(session, rx, port);
        assert!(
            passed,
            "TUN HTTPS failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            echoed && received_by_echo > 0,
            "TUN UDP echo failed: xray={xray}, attempts={attempts}, received_by_echo={received_by_echo}, socket_error={last:?}, sources={sources:?}, (route,bound_tun_echo,mixed_udp_echo)={evidence:?}"
        );
    }
}

fn bound_echo(destination: std::net::SocketAddr) -> std::io::Result<bool> {
    let udp = UdpSocket::bind("172.31.250.1:0")?;
    udp.set_read_timeout(Some(Duration::from_secs(2)))?;
    udp.connect(destination)?;
    udp.send(b"eivro-bound")?;
    let mut reply = [0; 64];
    let size = udp.recv(&mut reply)?;
    Ok(&reply[..size] == b"eivro-bound")
}

fn mixed_udp_echo(port: u16, destination: std::net::SocketAddr) -> std::io::Result<bool> {
    let mut control =
        TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_secs(2))?;
    control.set_read_timeout(Some(Duration::from_secs(2)))?;
    control.set_write_timeout(Some(Duration::from_secs(2)))?;
    control.write_all(&[5, 1, 0])?;
    let mut greeting = [0; 2];
    control.read_exact(&mut greeting)?;
    if greeting != [5, 0] {
        return Ok(false);
    }
    let udp = UdpSocket::bind("127.0.0.1:0")?;
    udp.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut associate = vec![5, 3, 0, 1, 127, 0, 0, 1];
    associate.extend(udp.local_addr()?.port().to_be_bytes());
    control.write_all(&associate)?;
    let mut response = [0; 10];
    control.read_exact(&mut response)?;
    if response[..4] != [5, 0, 0, 1] {
        return Ok(false);
    }
    // The listener and client are loopback-only. A server may return 0.0.0.0.
    let relay = u16::from_be_bytes([response[8], response[9]]);
    udp.connect(("127.0.0.1", relay))?;
    let std::net::IpAddr::V4(ip) = destination.ip() else {
        return Ok(false);
    };
    let mut message = vec![0, 0, 0, 1];
    message.extend(ip.octets());
    message.extend(destination.port().to_be_bytes());
    message.extend(b"eivro-socks");
    udp.send(&message)?;
    let mut reply = [0; 64];
    let size = udp.recv(&mut reply)?;
    Ok(reply[..size] == message)
}

fn udp_route_context(destination: std::net::IpAddr) -> Option<String> {
    let output = Command::new("powershell.exe").args(["-NoProfile","-NonInteractive","-Command",
        &format!(r#"$ErrorActionPreference='Stop'; $r=@(Find-NetRoute -RemoteIPAddress '{destination}' | Select-Object InterfaceIndex,InterfaceAlias,AddressFamily,DestinationPrefix,IPAddress); $a=@(Get-NetIPAddress -InterfaceAlias Eivro -AddressFamily IPv4 | Select-Object PrefixLength,AddressState,SkipAsSource); $i=@(Get-NetIPInterface -AddressFamily IPv4 | Where-Object ConnectionState -eq Connected | Select-Object InterfaceAlias,InterfaceMetric,WeakHostSend,Forwarding); @{{best=$r;tun=$a;interfaces=$i}} | ConvertTo-Json -Depth 4 -Compress"#)
    ]).output().ok()?;
    output.status.success().then(|| {
        String::from_utf8_lossy(&output.stdout)
            .chars()
            .take(1400)
            .collect()
    })
}

struct UdpEcho {
    port: u16,
    received: Arc<std::sync::atomic::AtomicUsize>,
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
        let received = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = received.clone();
        let worker = std::thread::spawn(move || {
            let mut packet = [0; 512];
            while !stopped.load(std::sync::atomic::Ordering::Acquire) {
                if let Ok((length, peer)) = socket.recv_from(&mut packet) {
                    count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    socket.send_to(&packet[..length], peer).unwrap();
                }
            }
        });
        Self {
            port,
            received,
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
                    socket.set_nonblocking(false).unwrap();
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
