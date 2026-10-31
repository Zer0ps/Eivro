//! Explicit connectivity diagnostic: one HTTPS request to example.com per attempt.
//! Raw subscription bytes enter through stdin and are never written to disk.
use eivro::{
    config::{ConnectRequest, Mode},
    import::parse_uri,
    process::{Event, Session},
};
use std::{
    io::Read,
    net::TcpListener,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

fn run() -> eivro::Result<()> {
    eivro::privacy::harden().map_err(|_| "Cannot disable crash dumps")?;
    let kind = std::env::args()
        .nth(1)
        .ok_or("Specify a protocol or transport")?;
    let mut data = Vec::new();
    std::io::stdin()
        .take(eivro::MAX_IMPORT as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|_| "Cannot read subscription")?;
    let profiles = match std::str::from_utf8(&data) {
        Ok(text) if text.trim().starts_with("https://") => {
            eivro::catalog::read_input(text.trim())?.profiles
        }
        _ => eivro::subscription::import_bytes(&data)?,
    };
    let mut attempted = 0;
    for profile in profiles {
        let parsed = parse_uri(&profile.uri)?;
        if parsed.protocol != kind
            && parsed.outbound["streamSettings"]["network"].as_str() != Some(&kind)
            && parsed.outbound["transport"]["type"].as_str() != Some(&kind)
        {
            continue;
        }
        attempted += 1;
        let port = TcpListener::bind("127.0.0.1:0")
            .and_then(|s| s.local_addr())
            .map_err(|_| "Cannot allocate local port")?
            .port();
        let (session, events) = Session::start(
            ConnectRequest {
                connections: vec![],
                probe_port: None,
                policies: vec![],
                kill_switch: false,
                uri: profile.uri,
                bypass: vec![],
                port,
                bridge_port: None,
            },
            Mode::Local,
            Arc::new(|| {}),
        )?;
        if !matches!(
            events.recv_timeout(Duration::from_secs(10)),
            Ok(Event::Running)
        ) {
            return Err("Local session did not start".into());
        }
        let output = Command::new("curl")
            .args([
                "--disable",
                "-4",
                "--silent",
                "--fail",
                "--max-time",
                "15",
                "--noproxy",
                "",
                "--proxy",
                &format!("socks5h://127.0.0.1:{port}"),
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
                "https://example.com/",
            ])
            .stderr(Stdio::null())
            .output()
            .map_err(|_| "Cannot run curl")?;
        drop(session);
        println!(
            "Attempt {attempted}: curl={}, HTTP={}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout)
        );
        if output.status.success() && output.stdout == b"200" {
            return Ok(());
        }
        if attempted == 3 {
            break;
        }
    }
    Err("No successful remote response (at most three endpoints tested)".into())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
