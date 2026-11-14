//! On-demand desktop checks using each OS's adapters and the system TLS client.
use super::{Action, Report, Request, Status, https};
use crate::{
    config::Mode,
    import::{EngineKind, parse_uri},
    policy,
};
use std::{
    io::{Read, Write},
    net::SocketAddr,
    path::PathBuf,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

fn curl_path() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        Some(PathBuf::from("/usr/bin/curl"))
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
        let mut buf = [0u16; 32768];
        let size = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
        (size > 0 && size < buf.len())
            .then(|| PathBuf::from(std::ffi::OsString::from_wide(&buf[..size])).join("curl.exe"))
    }
}

// A wrapped executable can leave a child holding stdout open after its own
// exit. Read just the bytes already in the pipe; waiting for EOF would bypass
// the cancellation and time budget.
fn completed_stdout(mut pipe: std::process::ChildStdout, limit: usize) -> Option<String> {
    #[cfg(target_os = "macos")]
    let size = {
        use std::os::fd::AsRawFd;
        let mut count: libc::c_int = 0;
        if unsafe { libc::ioctl(pipe.as_raw_fd(), libc::FIONREAD, &mut count) } == -1 {
            return None;
        }
        usize::try_from(count).ok()?
    };
    #[cfg(windows)]
    let size = {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::{
            Foundation::{ERROR_BROKEN_PIPE, GetLastError},
            System::Pipes::PeekNamedPipe,
        };
        let mut count = 0u32;
        if unsafe {
            PeekNamedPipe(
                pipe.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut count,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return (unsafe { GetLastError() } == ERROR_BROKEN_PIPE).then(String::new);
        }
        count as usize
    };
    if size > limit {
        return None;
    }
    let mut bytes = vec![0; size];
    pipe.read_exact(&mut bytes).ok()?;
    String::from_utf8(bytes).ok()
}

struct Budget<'a> {
    cancel: &'a AtomicBool,
    end: Instant,
}
impl Budget<'_> {
    fn stopped(&self) -> bool {
        self.cancel.load(Ordering::Relaxed) || Instant::now() >= self.end
    }

    // Each supported worker emits a small, fixed result. If an executable
    // produces excessive output and fills its pipe, the same deadline reaps it.
    fn output(
        &self,
        path: &std::path::Path,
        args: &[&str],
        input: Option<&[u8]>,
        seconds: u64,
        limit: usize,
    ) -> Option<https::Output> {
        if self.stopped() {
            return None;
        }
        let deadline = self.end.min(Instant::now() + Duration::from_secs(seconds));
        let mut child = crate::process::child_command(path)
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let result = (|| {
            if let Some(input) = input {
                child.stdin.take()?.write_all(input).ok()?;
            }
            loop {
                if self.stopped() || Instant::now() >= deadline {
                    return None;
                }
                if let Some(status) = child.try_wait().ok()? {
                    let text = completed_stdout(child.stdout.take()?, limit)?;
                    return Some(https::Output {
                        code: status.code(),
                        text,
                    });
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        })();
        if result.is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }
        result
    }

    fn resolve(&self, host: &str) -> Option<bool> {
        if host.parse::<std::net::IpAddr>().is_ok() {
            return Some(true);
        }
        let input = serde_json::to_vec(&(host, 443_u16)).ok()?;
        let out = self.output(
            &crate::process::app_path().ok()?,
            &["--resolve-system"],
            Some(&input),
            3,
            4096,
        )?;
        if out.code != Some(0) {
            return Some(false);
        }
        let addresses: Vec<SocketAddr> = serde_json::from_str(&out.text).ok()?;
        Some((1..=32).contains(&addresses.len()) && addresses.iter().all(|addr| addr.port() == 443))
    }

    fn version(&self, path: Option<PathBuf>, arg: &str, expected: &str, prefix: bool) -> Status {
        let Some(path) = path else {
            return Status::Error;
        };
        match self.output(&path, &[arg], None, 2, 4096) {
            Some(o)
                if o.code == Some(0)
                    && o.text.lines().next().is_some_and(|line| {
                        if prefix {
                            line.starts_with(expected)
                        } else {
                            line == expected
                        }
                    }) =>
            {
                Status::Pass
            }
            Some(_) => Status::Error,
            None => Status::Unknown,
        }
    }
}

fn helper_path() -> Option<PathBuf> {
    if !crate::process::helper_available() {
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        Some(PathBuf::from(crate::platform::HELPER))
    }
    #[cfg(windows)]
    {
        crate::platform::windows::service::installed_helper_path()
    }
}

fn version_finding(report: &mut Report, id: &str, title: &str, status: Status) {
    let detail = match status {
        Status::Pass => "Версия соответствует сборке.",
        Status::Error => "Компонент недоступен или его версия отличается от установленной сборки.",
        _ => "Проверка компонента не завершилась вовремя.",
    };
    report.add(id, status, title, detail, "", None);
}

pub(super) fn run(request: Request, cancel: Arc<AtomicBool>, progress: impl Fn(&str)) -> Report {
    let mut report = Report::default();
    let budget = Budget {
        cancel: &cancel,
        end: Instant::now() + Duration::from_secs(30),
    };
    if budget.stopped() {
        report.cancelled = true;
        return report;
    }
    progress("Проверяем подключение и профиль…");
    // Read the current Darwin dynamic store directly rather than waking the
    // privileged launchd helper for a diagnostic-only observation.
    #[cfg(target_os = "macos")]
    let links = crate::platform::macos::network::raw_interfaces();
    #[cfg(windows)]
    let links = crate::network::interfaces();
    let up = links.iter().any(|l| l.up);
    report.add(
        "uplink",
        if up { Status::Pass } else { Status::Unknown },
        "Сетевые интерфейсы",
        if up {
            "В системе есть активный сетевой интерфейс."
        } else {
            "Активный внешний интерфейс не обнаружен."
        },
        "",
        None,
    );
    if let Some(profile) = request
        .settings
        .routing_profiles
        .get(request.settings.selected_routing)
    {
        for exit in &request.settings.connections {
            if profile
                .rules
                .iter()
                .any(|r| r.enabled && r.action == policy::Action::Connection(exit.id))
            {
                let available = exit.servers(&links).is_some();
                report.add(
                    "exit",
                    if available {
                        Status::Pass
                    } else {
                        Status::Error
                    },
                    "Сетевой выход профиля",
                    format!("Выход «{}», интерфейс {}.", exit.name, exit.interface),
                    if available {
                        ""
                    } else {
                        "Подключите эту сеть или измените правило."
                    },
                    Some(Action::OpenRoutes),
                );
            }
        }
        if let Some(address) = request
            .address
            .as_deref()
            .and_then(|s| https::target(s).ok())
        {
            report.add(
                "rule",
                Status::Pass,
                "Правило для адреса",
                profile.matches(&address).label(),
                "",
                Some(Action::OpenRoutes),
            );
        }
    }
    let parsed = request
        .settings
        .selected_profile()
        .map(|p| parse_uri(&p.uri));
    report.add(
        "profile",
        if matches!(parsed, Some(Ok(_))) {
            Status::Pass
        } else {
            Status::Warning
        },
        "Выбранный сервер",
        if parsed.is_some() {
            "Проверен формат сохранённого профиля."
        } else {
            "Сервер ещё не выбран."
        },
        if matches!(parsed, Some(Ok(_))) {
            ""
        } else {
            "Выберите доступный сервер в каталоге."
        },
        None,
    );
    if !budget.stopped() {
        let singbox = budget.version(
            crate::process::core_path().ok(),
            "version",
            &format!("sing-box version {}", crate::CORE_VERSION),
            false,
        );
        version_finding(&mut report, "core", "Ядро sing-box", singbox);
        if parsed.is_some_and(|v| v.is_ok_and(|p| p.engine == EngineKind::Xray))
            && !budget.stopped()
        {
            let xray = budget.version(
                crate::process::xray_path().ok(),
                "version",
                &format!("Xray {} ", crate::xray::VERSION),
                true,
            );
            version_finding(&mut report, "xray", "Ядро Xray", xray);
        }
        if (request.settings.mode == Mode::Tun || cfg!(target_os = "macos")) && !budget.stopped() {
            let helper = budget.version(
                helper_path(),
                "--version",
                concat!("Eivro TUN ", env!("CARGO_PKG_VERSION")),
                false,
            );
            version_finding(&mut report, "helper", "Системный помощник", helper);
        }
    }
    if !budget.stopped() {
        #[cfg(windows)]
        crate::platform::windows::diagnostics::inspect(&request, &mut report);
        #[cfg(target_os = "macos")]
        crate::platform::macos::diagnostics::inspect(&request, &mut report);
    }
    if request.network_tests && !request.busy && !budget.stopped() {
        let host = match https::target(request.address.as_deref().unwrap_or("example.com")) {
            Ok(host) => host,
            Err(_) => {
                report.add(
                    "https",
                    Status::Error,
                    "Проверьте адрес",
                    "Нужен домен или IP без порта и пути.",
                    "",
                    None,
                );
                return report;
            }
        };
        progress("Проверяем доступ к сайту…");
        if !request.connected || request.settings.mode == Mode::Tun {
            let success = budget.resolve(&host);
            let status = match success {
                Some(true) => Status::Pass,
                Some(false) => Status::Warning,
                None => Status::Unknown,
            };
            report.add(
                "dns_probe",
                status,
                "Системный DNS",
                if success == Some(true) {
                    "Получен адрес назначения."
                } else {
                    "Система не вернула адрес вовремя."
                },
                "",
                None,
            );
        }
        let paths = [request.connected.then_some(request.settings.port), None];
        let count = if request.connected && request.settings.mode == Mode::Tun {
            2
        } else {
            1
        };
        for port in paths.into_iter().take(count) {
            if budget.stopped() {
                break;
            }
            let args = https::curl_arguments(&host, port, None, None);
            let args: Vec<_> = args.iter().map(String::as_str).collect();
            let (status, detail) = curl_path()
                .and_then(|p| budget.output(&p, &args, None, 7, 256))
                .as_ref()
                .map(|o| https::classify(o, port.is_some(), false))
                .unwrap_or((
                    Status::Unknown,
                    "Системная проверка HTTPS недоступна или исчерпала время ожидания.",
                ));
            report.add(
                "https",
                status,
                if port.is_some() {
                    "HTTPS через Eivro"
                } else {
                    "HTTPS по системному маршруту"
                },
                detail,
                "",
                None,
            );
        }
    }
    report.cancelled = cancel.load(Ordering::Relaxed);
    if budget.stopped() && !report.cancelled {
        report.add(
            "state",
            Status::Unknown,
            "Проверка завершена не полностью",
            "Общий лимит времени исчерпан.",
            "Повторите проверку.",
            None,
        );
    }
    report
}
