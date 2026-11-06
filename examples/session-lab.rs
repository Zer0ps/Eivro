//! Opt-in disposable-VM probe of the production Session/Controller lifecycle.
//! Request JSON arrives through stdin; credentials are never printed or saved.
use eivro::{
    config::{ConnectRequest, Mode},
    process::{Event, Session},
    tun::Controller,
};
use std::{
    io::{BufRead, Write},
    sync::Arc,
    time::{Duration, Instant},
};

fn run() -> eivro::Result<()> {
    if std::env::args().nth(1).as_deref() != Some("--tun-in-disposable-vm") {
        return Err(
            "This probe changes VM routing. Pass --tun-in-disposable-vm only inside your test VM."
                .into(),
        );
    }
    eivro::privacy::harden().map_err(|_| "Cannot disable crash dumps")?;
    let mut input = std::io::stdin().lock();
    let mut frame = String::new();
    std::io::Read::take(&mut input, eivro::process::MAX_REQUEST as u64 + 1)
        .read_line(&mut frame)
        .map_err(|_| "Cannot read request")?;
    if frame.len() > eivro::process::MAX_REQUEST {
        return Err("Request too large".into());
    }
    let request: ConnectRequest = serde_json::from_str(&frame).map_err(|_| "Invalid request")?;
    if request.kill_switch {
        return Err("Use isolated namespace tests for kill switch; preserve VM SSH access.".into());
    }
    let controller = Arc::new(Controller::default());
    let (session, events) =
        Session::start_with_controller(request, Mode::Tun, Arc::new(|| {}), controller.clone())?;
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        match events.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Event::Running) => break,
            Ok(Event::Progress(_)) => (),
            Ok(Event::Failed(error)) => return Err(error),
            _ => return Err("Session did not connect within the test deadline".into()),
        }
    }
    println!("READY");
    std::io::stdout().flush().map_err(|_| "No output pipe")?;
    frame.clear();
    input
        .read_line(&mut frame)
        .map_err(|_| "Control pipe closed")?;
    drop(session);
    controller.retire()?;
    println!("STOPPED");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
