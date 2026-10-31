use std::{
    io::Write,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn worker_uses_system_localhost_resolution_over_private_pipes() {
    let mut worker = Command::new(env!("CARGO_BIN_EXE_eivro"))
        .arg("--resolve-system")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    worker
        .stdin
        .take()
        .unwrap()
        .write_all(br#"["localhost",443]"#)
        .unwrap();
    let output = worker.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let addresses: Vec<std::net::SocketAddr> = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!addresses.is_empty());
    assert!(
        addresses
            .iter()
            .all(|a| a.ip().is_loopback() && a.port() == 443)
    );
}

#[test]
fn production_resolver_discovers_worker_and_honors_expired_budget() {
    let result = eivro::resolver::resolve(
        "localhost:8443",
        Instant::now() + Duration::from_secs(5),
        None,
    )
    .unwrap();
    assert!(
        result
            .iter()
            .all(|a| a.ip().is_loopback() && a.port() == 8443)
    );
    assert_eq!(
        eivro::resolver::resolve("localhost:443", Instant::now(), None)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
}

#[test]
fn malformed_worker_input_does_not_echo_secrets() {
    let mut worker = Command::new(env!("CARGO_BIN_EXE_eivro"))
        .arg("--resolve-system")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    worker
        .stdin
        .take()
        .unwrap()
        .write_all(br#"["https://secret.invalid/token",443]"#)
        .unwrap();
    let output = worker.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn stalled_system_dns_bounds_subscription_and_session_cancellation() {
    use eivro::{
        config::{ConnectRequest, Mode},
        process::Session,
    };
    use std::{fs, os::unix::fs::PermissionsExt, sync::Arc};
    if std::env::var_os("EIVRO_DNS_REGRESSION_CHILD").is_none() {
        // Re-exec only this test next to a fake resolver worker. Production has
        // no test environment hooks, and the host resolver/network is untouched.
        let directory =
            std::env::temp_dir().join(format!("eivro-dns-regression-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let driver = directory.join("dns-test");
        fs::copy(std::env::current_exe().unwrap(), &driver).unwrap();
        let worker = directory.join("eivro");
        fs::write(&worker, "#!/usr/bin/python3\nimport os,sys,time\nfrom pathlib import Path\nassert sys.argv[1:] == ['--resolve-system']\nsys.stdin.read()\nPath(__file__).with_name('worker.pid').write_text(str(os.getpid()))\ntime.sleep(60)\n").unwrap();
        fs::set_permissions(&worker, fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["xray", "sing-box"] {
            std::os::unix::fs::symlink(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("vendor")
                    .join(name),
                directory.join(name),
            )
            .unwrap();
        }
        let output = Command::new(driver)
            .args([
                "--exact",
                "stalled_system_dns_bounds_subscription_and_session_cancellation",
                "--nocapture",
            ])
            .env("EIVRO_DNS_REGRESSION_CHILD", "1")
            .output()
            .unwrap();
        fs::remove_dir_all(directory).unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let pid_path = std::env::current_exe()
        .unwrap()
        .with_file_name("worker.pid");
    let req = ConnectRequest {
        connections: vec![],
        uri: "vless://00000000-0000-4000-8000-000000000001@resolver.invalid:443?security=reality&sni=example.com&fp=firefox&pbk=CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=1122334455667788&type=tcp&flow=xtls-rprx-vision".into(),
        port: std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port(),
        bridge_port: None, probe_port: None, policies: vec![], bypass: vec![], kill_switch: false,
    };
    let (session, _) = Session::start(req, Mode::Local, Arc::new(|| {})).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !pid_path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(pid_path.exists(), "Session did not start the DNS worker");
    let start = Instant::now();
    drop(session);
    assert!(start.elapsed() < Duration::from_secs(2));
    let check_reaped = || {
        let pid = fs::read_to_string(&pid_path)
            .unwrap()
            .parse::<i32>()
            .unwrap();
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    };
    check_reaped();
    fs::remove_file(&pid_path).unwrap();
    let start = Instant::now();
    let error = eivro::import::download_document("https://resolver.invalid/sub/synthetic")
        .err()
        .unwrap();
    assert!(error.contains("Время загрузки подписки истекло"), "{error}");
    assert!(
        start.elapsed() >= Duration::from_secs(19) && start.elapsed() < Duration::from_secs(23)
    );
    check_reaped();
}
