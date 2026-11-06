//! Explicit Linux diagnostic CLI for disposable-VM acceptance tests.
//! Emits only stable check IDs/statuses and action types; never settings or URIs.
#[cfg(target_os = "linux")]
fn main() {
    use eivro::diagnostics::{self, Action, Request};
    use std::sync::{Arc, atomic::AtomicBool};
    eivro::privacy::harden().unwrap();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--fingerprint") {
        println!("{}", diagnostics::fingerprint().unwrap());
        return;
    }
    let settings = if args.iter().any(|a| a == "--empty-settings") {
        eivro::storage::Settings::default()
    } else {
        let path = eivro::storage::default_path().unwrap();
        eivro::storage::load(&path).unwrap()
    };
    let target = args
        .windows(2)
        .find(|p| p[0] == "--address")
        .map(|p| p[1].clone());
    let cancel = Arc::new(AtomicBool::new(false));
    let report = diagnostics::run(
        Request {
            settings,
            connected: args.iter().any(|a| a == "--connected"),
            busy: false,
            network_tests: args.iter().any(|a| a == "--network"),
            direct_test: false,
            address: target,
        },
        cancel.clone(),
        |_| {},
    );
    if let Some(pair) = args.windows(2).find(|p| p[0] == "--restore-dns") {
        assert!(
            std::env::var("EIVRO_VM_REPAIR").as_deref() == Ok("1"),
            "Repair only in an explicitly authorized VM"
        );
        let action = Action::RestoreDns {
            interface: pair[1].clone(),
        };
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.action.as_ref() == Some(&action)),
            "No supported repair finding"
        );
        diagnostics::repair::apply(&action, &report.network_fingerprint, cancel).unwrap();
        println!("REPAIRED");
    }
    for finding in &report.findings {
        println!(
            "{} {:?} {}",
            finding.id,
            finding.status,
            match finding.action {
                Some(Action::RestoreDns { .. }) => "restore-dns",
                Some(Action::FlushDns) => "flush-dns",
                Some(Action::RecoverProxy) => "recover-proxy",
                Some(Action::Reconnect) => "reconnect",
                Some(Action::OpenRoutes) => "routes",
                Some(Action::OpenSettings) => "settings",
                None => "none",
            }
        );
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Linux-only diagnostic probe");
}
