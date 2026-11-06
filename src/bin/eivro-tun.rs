#[cfg(windows)]
fn main() {
    eivro::platform::windows::service::main();
}
#[cfg(target_os = "macos")]
fn main() {
    eivro::platform::macos::daemon::main();
}
#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}
#[cfg(target_os = "linux")]
mod linux {
    use eivro::{privacy, process};
    use std::{
        fs::OpenOptions,
        io::Write,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::Path,
    };

    pub(super) fn main() {
        if std::env::args()
            .collect::<Vec<_>>()
            .get(1)
            .is_some_and(|s| s == "--version")
        {
            println!("Eivro TUN {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        if privacy::harden().is_err() {
            std::process::exit(1);
        }
        if run().is_err() {
            let _ = std::io::stdout().write_all(b"ERROR\n");
            std::process::exit(1);
        }
    }

    fn run() -> eivro::Result<()> {
        if unsafe { libc::geteuid() } != 0
            || !process::trusted_binary(Path::new(process::INSTALLED_CORE))
        {
            return Err("privilege".into());
        }
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        let mode = match args.as_slice() {
            [] => "tunnel",
            [flag] if flag == "--release" => "release",
            [flag] if flag == "--repair-dns" => "repair-dns",
            _ => return Err("arguments".into()),
        };
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/run/velum-tun.lock")
            .map_err(|_| "lock")?;
        let metadata = lock.metadata().map_err(|_| "lock")?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
            return Err("lock".into());
        }
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            if mode == "repair-dns" {
                let _ = std::io::stdout().write_all(b"BUSY\n");
                let _ = std::io::stdout().flush();
            }
            return Err("already running".into());
        }
        if mode == "release" {
            return eivro::guard::Guard::clear_stale();
        }
        // pkexec may leave PDEATHSIG tied to the spawning Session thread
        // (notably for root callers). The controller owns us across worker
        // restarts through stdin; EOF, not creator-thread death, ends the lease.
        clear_parent_signal()?;
        if mode == "repair-dns" {
            let input = std::fs::File::open("/dev/stdin").map_err(|_| "input")?;
            return eivro::diagnostics::repair::serve_dns_repair(input, std::io::stdout());
        }
        let signals = shutdown_signals()?;
        let input = std::fs::File::open("/dev/stdin").map_err(|_| "input")?;
        eivro::tun::serve_backend_with_shutdown(
            input,
            std::io::stdout(),
            eivro::guard::SystemBackend::default(),
            Some(signals.as_raw_fd()),
        )
    }

    // Only the single-threaded privileged helper owns these signal dispositions.
    // SIGKILL cannot be caught; its surviving resources require explicit recovery.
    fn shutdown_signals() -> eivro::Result<OwnedFd> {
        unsafe {
            let mut mask = std::mem::zeroed();
            libc::sigemptyset(&mut mask);
            for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
                libc::sigaddset(&mut mask, signal);
            }
            if libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) != 0 {
                return Err("signals".into());
            }
            let fd = libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
            if fd < 0 {
                return Err("signals".into());
            }
            Ok(OwnedFd::from_raw_fd(fd))
        }
    }

    fn clear_parent_signal() -> eivro::Result<()> {
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, 0) } != 0 {
            return Err("parent signal".into());
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            cell::Cell,
            io::{BufRead, BufReader},
            os::unix::process::CommandExt,
            process::{Command, Stdio},
            rc::Rc,
            time::{Duration, Instant},
        };

        struct Backend(Rc<Cell<bool>>);
        impl eivro::tun::Backend for Backend {
            fn start(
                &mut self,
                _: &eivro::config::ConnectRequest,
            ) -> eivro::Result<eivro::tun::Running> {
                panic!("the signal test must not launch a core");
            }
            fn stop(&mut self, protection: bool, dns: bool) -> eivro::Result<()> {
                assert!(!protection && !dns);
                self.0.set(true);
                Ok(())
            }
        }

        #[test]
        fn shutdown_signal_child() {
            if std::env::var_os("EIVRO_SHUTDOWN_SIGNAL_CHILD").is_none() {
                return;
            }
            unsafe {
                assert_eq!(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM), 0);
            }
            clear_parent_signal().unwrap();
            let mut parent_signal: libc::c_int = -1;
            unsafe {
                assert_eq!(libc::prctl(libc::PR_GET_PDEATHSIG, &mut parent_signal), 0);
            }
            assert_eq!(parent_signal, 0);
            let signals = shutdown_signals().unwrap();
            let stopped = Rc::new(Cell::new(false));
            println!("SIGNAL_READY");
            std::io::stdout().flush().unwrap();
            eivro::tun::serve_backend_with_shutdown(
                std::fs::File::open("/dev/stdin").unwrap(),
                std::io::sink(),
                Backend(stopped.clone()),
                Some(signals.as_raw_fd()),
            )
            .unwrap();
            assert!(stopped.get(), "shutdown must run explicit cleanup");
        }

        #[test]
        fn termination_signals_run_cleanup_without_gui_eof() {
            for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
                // A subprocess owns the mask; parallel unit tests are unaffected.
                let mut command = Command::new(std::env::current_exe().unwrap());
                command
                    .args([
                        "--exact",
                        "linux::tests::shutdown_signal_child",
                        "--nocapture",
                    ])
                    .env("EIVRO_SHUTDOWN_SIGNAL_CHILD", "1")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped());
                // The test harness has its own main thread. Block before exec
                // so it cannot consume a process signal intended for signalfd.
                unsafe {
                    command.pre_exec(|| {
                        let mut mask = std::mem::zeroed();
                        libc::sigemptyset(&mut mask);
                        for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
                            libc::sigaddset(&mut mask, signal);
                        }
                        if libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                let mut child = command.spawn().unwrap();
                let mut output = BufReader::new(child.stdout.take().unwrap());
                loop {
                    let mut line = String::new();
                    assert_ne!(output.read_line(&mut line).unwrap(), 0);
                    if line.contains("SIGNAL_READY") {
                        break;
                    }
                }
                assert_eq!(unsafe { libc::kill(child.id() as i32, signal) }, 0);
                let end = Instant::now() + Duration::from_secs(3);
                let status = loop {
                    if let Some(status) = child.try_wait().unwrap() {
                        break status;
                    }
                    if Instant::now() >= end {
                        let _ = child.kill();
                        let _ = child.wait();
                        panic!("helper did not process signal {signal}");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                };
                assert!(status.success(), "signal {signal}: {status}");
            }
        }
    }
}
