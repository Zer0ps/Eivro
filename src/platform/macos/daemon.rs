//! launchd socket-activated helper. Commands are typed, peers are identified by
//! the kernel, and privileged modes require a client-held Authorization grant.
use crate::{
    Result,
    config::{ConnectRequest, Mode},
    import::{EngineKind, parse_uri},
    platform::macos::{
        native, wait,
        wire::{self, Reply, Request},
    },
    process,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
            net::{UnixListener, UnixStream},
            process::CommandExt,
        },
    },
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
const DIRECTORY: &str = "/Library/Application Support/EivroHelper";
const JOURNAL: &str = "/Library/Application Support/EivroHelper/network-recovery.json";
static ACTIVE: Mutex<()> = Mutex::new(());
static ORIGINAL_DNS: Mutex<Option<crate::network::Interface>> = Mutex::new(None);
static CLIENTS: AtomicUsize = AtomicUsize::new(0);
unsafe extern "C" {
    fn launch_activate_socket(
        name: *const libc::c_char,
        fds: *mut *mut i32,
        count: *mut usize,
    ) -> i32;
}

pub fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 2 && args[1] == "--version" {
        println!("Eivro TUN {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if crate::privacy::harden().is_err() {
        std::process::exit(1);
    }
    if args.len() == 2 && args[1] == "--resolve-system" {
        std::process::exit(if crate::resolver::worker().is_ok() {
            0
        } else {
            1
        });
    }
    if args.len() == 3 && args[1] == "--check-connection" {
        let ok = args[2]
            .parse::<u16>()
            .ok()
            .filter(|p| *p >= 1024)
            .is_some_and(|p| crate::connectivity::check(p).is_ok());
        std::process::exit(if ok { 0 } else { 1 });
    }
    if crate::privacy::silence_stdio().is_err() {
        std::process::exit(1);
    }
    let result = if args.len() == 2 && args[1] == "--release" && unsafe { libc::geteuid() } == 0 {
        recover()
    } else if args.len() == 1 {
        serve()
    } else {
        Err("arguments".into())
    };
    if result.is_err() {
        std::process::exit(1);
    }
}
fn serve() -> Result<()> {
    if unsafe { libc::geteuid() } != 0
        || !process::trusted_binary(Path::new(process::INSTALLED_CORE))
        || !process::trusted_binary(Path::new(process::INSTALLED_XRAY))
    {
        return Err("privilege".into());
    }
    secure_directory()?;
    recover()?;
    let mut fds = std::ptr::null_mut();
    let mut count = 0;
    if unsafe { launch_activate_socket(c"Control".as_ptr(), &mut fds, &mut count) } != 0
        || count != 1
    {
        return Err("launchd socket unavailable".into());
    }
    let raw = unsafe { *fds };
    unsafe {
        libc::free(fds.cast());
        libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC);
    }
    let listener = unsafe { UnixListener::from_raw_fd(raw) };
    listener.set_nonblocking(true).map_err(|_| "Socket error")?;
    let (wake, mut closed) = UnixStream::pair().map_err(|_| "Socket error")?;
    closed.set_nonblocking(true).map_err(|_| "Socket error")?;
    loop {
        while let Ok((stream, _)) = listener.accept() {
            if CLIENTS.fetch_add(1, Ordering::AcqRel) >= 8 {
                CLIENTS.fetch_sub(1, Ordering::AcqRel);
                continue;
            }
            let mut wake = wake.try_clone().map_err(|_| "Socket error")?;
            std::thread::spawn(move || {
                let _ = client(stream);
                CLIENTS.fetch_sub(1, Ordering::AcqRel);
                let _ = wake.write_all(b"C");
            });
        }
        // launchd retains the listening socket and starts us again on demand.
        // Once the GUI releases its last session, no helper process stays resident.
        if CLIENTS.load(Ordering::Acquire) == 0 {
            return Ok(());
        }
        let mut ready = [
            process::pollfd(listener.as_raw_fd(), libc::POLLIN),
            process::pollfd(closed.as_raw_fd(), libc::POLLIN),
        ];
        process::poll(&mut ready)?;
        if ready[1].revents != 0 {
            let mut bytes = [0; 32];
            while closed.read(&mut bytes).is_ok() {}
        }
    }
}

fn client(mut stream: UnixStream) -> Result<()> {
    let (uid, gid) = wait::peer(stream.as_raw_fd()).map_err(|_| "Unknown peer")?;
    if uid == 0 {
        return Err("GUI must not run as root".into());
    }
    stream.set_nonblocking(false).map_err(|_| "Socket error")?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| "Socket error")?;
    wire::send(
        &mut stream,
        &Reply::Hello {
            version: env!("CARGO_PKG_VERSION").into(),
        },
    )?;
    let mut authorized = false;
    loop {
        // Idle sockets sleep indefinitely. Once a command starts arriving, bound
        // its body read so a partial request cannot hold a privileged session.
        let mut fds = [process::pollfd(stream.as_raw_fd(), libc::POLLIN)];
        process::poll(&mut fds)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| "Socket error")?;
        match wire::receive(&mut stream)? {
            Request::Stop {} => wire::send(&mut stream, &Reply::Stopped)?,
            Request::Interfaces {} => wire::send(
                &mut stream,
                &Reply::Interfaces {
                    interfaces: crate::network::interfaces(),
                },
            )?,
            Request::Start {
                request,
                mode,
                authorization,
            } => {
                if mode != Mode::Local && !authorized {
                    authorized = authorization
                        .as_ref()
                        .is_some_and(native::verify_authorization);
                    if !authorized {
                        wire::send(&mut stream, &Reply::Denied)?;
                        continue;
                    }
                }
                let _active = if mode != Mode::Local {
                    let Ok(lease) = ACTIVE.try_lock() else {
                        wire::send(
                            &mut stream,
                            &Reply::Failed {
                                message: "Другое окно Eivro уже управляет сетью.".into(),
                            },
                        )?;
                        continue;
                    };
                    Some(lease)
                } else {
                    None
                };
                let result = session(&request, mode, &mut stream, uid, gid);
                match result {
                    Ok(()) => wire::send(&mut stream, &Reply::Stopped)?,
                    Err(message) => {
                        wire::send(&mut stream, &Reply::Failed { message })?;
                        return Ok(());
                    }
                }
            }
        }
    }
}
struct Cores {
    primary: Option<Child>,
    secondary: Option<Child>,
}
impl Drop for Cores {
    fn drop(&mut self) {
        if let Some(child) = &mut self.primary {
            process::terminate(child);
        }
        if let Some(child) = &mut self.secondary {
            process::terminate(child);
        }
    }
}
fn as_user(command: &mut Command, uid: u32, gid: u32) {
    unsafe {
        command.pre_exec(move || {
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(gid) != 0
                || libc::setuid(uid) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}
fn spawn(
    core: &Path,
    args: &[&str],
    config: &serde_json::Value,
    user: Option<(u32, u32)>,
) -> Result<Child> {
    if !process::trusted_binary(core) {
        return Err("Небезопасный исполняемый файл ядра.".into());
    }
    let mut command = process::child_command(core);
    command.args(args).stdin(Stdio::piped());
    if let Some((uid, gid)) = user {
        as_user(&mut command, uid, gid);
    }
    let mut child = command.spawn().map_err(|_| "Не удалось запустить ядро.")?;
    let result = child
        .stdin
        .take()
        .ok_or("Нет канала ядра.")
        .and_then(|mut input| {
            input
                .write_all(config.to_string().as_bytes())
                .map_err(|_| "Не удалось передать настройки ядру.")
        });
    if let Err(error) = result {
        process::terminate(&mut child);
        return Err(error.into());
    }
    Ok(child)
}
fn session(
    request: &ConnectRequest,
    mode: Mode,
    stream: &mut UnixStream,
    uid: u32,
    gid: u32,
) -> Result<()> {
    if request.kill_switch {
        return Err("Kill switch пока доступен только в Linux.".into());
    }
    let links = crate::network::interfaces();
    let mut config = crate::config::generate_with_network(request, mode, &links)?;
    let uplink = native::uplink()?;
    crate::network::validate_interface(&uplink)?;
    let parsed = parse_uri(&request.uri)?;
    let addresses = crate::resolver::resolve_host(
        &parsed.host,
        443,
        Instant::now() + Duration::from_secs(10),
        Some(stream),
    )
    .map_err(|_| "Не удалось разрешить адрес сервера.")?;
    let ip = addresses
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addresses.first())
        .ok_or("У сервера нет адреса.")?
        .ip();
    // Resolve the transport before changing DNS, and pin its external sockets.
    // The local Xray bridge must never inherit an external-interface binding.
    config["dns"]["servers"][0] = serde_json::json!({"type":"https","tag":"bootstrap","server":"1.1.1.1","bind_interface":uplink});
    config["dns"]["servers"][1]["bind_interface"] = serde_json::json!(uplink);
    config["outbounds"][1]["bind_interface"] = serde_json::json!(uplink);
    let mut cores = Cores {
        primary: None,
        secondary: None,
    };
    if parsed.engine == EngineKind::Xray {
        // Override auto_detect_interface for the local bridge as well: its
        // sockets belong on lo0, not on the physical uplink or the TUN.
        config["outbounds"][0]["bind_interface"] = serde_json::json!("lo0");
        process::xray_version_check(Path::new(process::INSTALLED_XRAY))?;
        let mut outbound = parsed.outbound;
        if !ip.is_loopback() {
            let settings = &mut outbound["settings"];
            if settings.get("vnext").is_some() {
                settings["vnext"][0]["address"] = serde_json::json!(ip.to_string());
            } else if settings.get("servers").is_some() {
                settings["servers"][0]["address"] = serde_json::json!(ip.to_string());
            } else {
                settings["address"] = serde_json::json!(ip.to_string());
            }
            outbound["streamSettings"]["sockopt"]["interface"] = serde_json::json!(uplink);
        }
        let port = request.bridge_port.ok_or("Нет порта Xray.")?;
        let xray = crate::xray::config(outbound, port);
        process::check_xray(Path::new(process::INSTALLED_XRAY), &xray)?;
        cores.secondary = Some(spawn(
            Path::new(process::INSTALLED_XRAY),
            &["run", "-config", "stdin:"],
            &xray,
            Some((uid, gid)),
        )?);
        process::ready(cores.secondary.as_mut().unwrap(), port)?;
    } else {
        config["outbounds"][0]["server"] = serde_json::json!(ip.to_string());
        config["outbounds"][0]["bind_interface"] =
            serde_json::json!(if ip.is_loopback() { "lo0" } else { &uplink });
    }
    process::version_check(Path::new(process::INSTALLED_CORE))?;
    // Capture the original primary service before utun changes the route table.
    let plan = if mode == Mode::Local {
        None
    } else {
        Some(native::settings_plan(request.port, mode == Mode::Tun)?)
    };
    if mode == Mode::Tun && unsafe { libc::if_nametoindex(c"utun233".as_ptr()) } != 0 {
        return Err("Интерфейс utun233 уже занят. Завершите другое подключение Eivro.".into());
    }
    cores.primary = Some(spawn(
        Path::new(process::INSTALLED_CORE),
        &["run", "-c", "/dev/stdin"],
        &config,
        if mode == Mode::Tun {
            None
        } else {
            Some((uid, gid))
        },
    )?);
    process::ready(cores.primary.as_mut().unwrap(), request.port)?;
    let primary = process::pid_fd(cores.primary.as_ref().unwrap())?;
    let secondary = cores.secondary.as_ref().map(process::pid_fd).transpose()?;
    let secondary_fd = secondary.as_ref().map_or(-1, AsRawFd::as_raw_fd);
    if mode != Mode::Local {
        wire::send(stream, &Reply::Checking)?;
        let port = request.probe_port.ok_or("Нет порта проверки.")?;
        let mut check = process::child_command(Path::new(process::HELPER));
        check
            .args(["--check-connection", &port.to_string()])
            .stdin(Stdio::null());
        as_user(&mut check, uid, gid);
        let child = check.spawn().map_err(|_| "Не удалось проверить HTTPS.")?;
        if !process::supervise_connection_check(
            child,
            stream,
            primary.as_raw_fd(),
            secondary_fd,
            Duration::from_secs(18),
        )? {
            // Consume the cancellation frame before acknowledging it. Otherwise
            // the next connection would receive a second, stale Stopped reply.
            return match wire::receive(stream) {
                Ok(Request::Stop {}) => Ok(()),
                Err(_) => Ok(()),
                _ => Err("Сначала остановите текущее подключение.".into()),
            };
        }
    }
    let original = if mode == Mode::Tun {
        links.iter().find(|link| link.name == uplink).cloned()
    } else {
        None
    };
    let mut lease = plan.map(|plan| Lease::apply(plan, original)).transpose()?;
    let result = (|| {
        wire::send(stream, &Reply::Ready)?;
        let mut fds = [
            process::pollfd(stream.as_raw_fd(), libc::POLLIN),
            process::pollfd(primary.as_raw_fd(), libc::POLLIN),
            process::pollfd(secondary_fd, libc::POLLIN),
        ];
        process::poll(&mut fds)?;
        if fds[0].revents != 0 {
            // EOF also ends the session. Any unexpected command closes the lease.
            match wire::receive(stream) {
                Ok(Request::Stop {}) => Ok(()),
                Err(_) => Ok(()),
                _ => Err("Сначала остановите текущее подключение.".into()),
            }
        } else {
            Err("Соединение остановлено: процесс ядра завершился.".into())
        }
    })();
    let restored = lease.as_mut().map_or(Ok(()), Lease::restore);
    drop(cores);
    result.and(restored)
}
fn secure_directory() -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(DIRECTORY)
        .map_err(|_| "Не удалось открыть каталог восстановления.")?;
    let meta = fs::symlink_metadata(DIRECTORY).map_err(|_| "Нет каталога восстановления.")?;
    if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o077 != 0 {
        return Err("Небезопасный каталог восстановления.".into());
    }
    Ok(())
}
struct Lease {
    plan: String,
    active: bool,
}
impl Lease {
    fn apply(plan: String, original: Option<crate::network::Interface>) -> Result<Self> {
        secure_directory()?;
        if Path::new(JOURNAL).exists() {
            recover()?;
        }
        let temp = Path::new(DIRECTORY).join(format!(".recovery-{}.tmp", std::process::id()));
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)
            .map_err(|_| "Не удалось сохранить настройки восстановления.")?;
        let written = (|| {
            output.write_all(plan.as_bytes())?;
            output.sync_all()?;
            fs::rename(&temp, JOURNAL)?;
            File::open(DIRECTORY)?.sync_all()
        })();
        if written.is_err() {
            let _ = fs::remove_file(temp);
            return Err("Не удалось сохранить настройки восстановления.".into());
        }
        *ORIGINAL_DNS
            .lock()
            .map_err(|_| "Не удалось сохранить DNS интерфейса.")? = original;
        let mut lease = Self { plan, active: true };
        if let Err(error) = native::settings_apply(&lease.plan, false) {
            let _ = lease.restore();
            return Err(error);
        }
        Ok(lease)
    }
    fn restore(&mut self) -> Result<()> {
        if self.active {
            native::settings_apply(&self.plan, true)?;
            fs::remove_file(JOURNAL).map_err(|_| "Не удалось завершить восстановление.")?;
            if let Ok(mut original) = ORIGINAL_DNS.lock() {
                *original = None;
            }
            self.active = false;
        }
        Ok(())
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}
fn recover() -> Result<()> {
    let input = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(JOURNAL)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("Не удалось прочитать настройки восстановления.".into()),
    };
    let meta = input
        .metadata()
        .map_err(|_| "Неверный файл восстановления.")?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.mode() & 0o077 != 0
        || meta.len() > 4 * 1024 * 1024
    {
        return Err("Небезопасный файл восстановления.".into());
    }
    let mut plan = String::new();
    input
        .take(4 * 1024 * 1024 + 1)
        .read_to_string(&mut plan)
        .map_err(|_| "Неверные настройки восстановления.")?;
    native::settings_apply(&plan, true)?;
    fs::remove_file(JOURNAL).map_err(|_| "Не удалось завершить восстановление.".into())
}

// Only override our own temporary DNS value. Other applications' changes are
// observable and must not be replaced by the saved interface snapshot.
pub(crate) fn original_dns(links: &mut [crate::network::Interface]) {
    if let Ok(saved) = ORIGINAL_DNS.lock()
        && let Some(original) = &*saved
    {
        for link in links {
            if link.name == original.name
                && link.index == original.index
                && link.dns == [std::net::IpAddr::from([172, 31, 250, 2])]
            {
                link.dns.clone_from(&original.dns);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // This test changes only the disposable macOS runner's network preferences.
    // It is never part of cargo test's default run or an installed executable.
    #[test]
    #[ignore = "requires root on a disposable macOS GitHub Actions runner"]
    fn native_preferences_restore_and_recover_after_abandoned_lease() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
        assert!(!Path::new(JOURNAL).exists());
        for tun in [false, true] {
            let before = native::settings_plan(32080, tun).unwrap();
            let expected: serde_json::Value = serde_json::from_str(&before).unwrap();
            let assert_state = |field: &str| {
                let current: serde_json::Value =
                    serde_json::from_str(&native::settings_plan(32080, tun).unwrap()).unwrap();
                for entry in expected.as_array().unwrap() {
                    let found = current
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|row| row["service"] == entry["service"])
                        .expect("network service disappeared");
                    assert_eq!(found["before"], entry[field]);
                    assert_eq!(found["before_enabled"], entry[format!("{field}_enabled")]);
                }
            };
            let mut lease = Lease::apply(before.clone(), None).unwrap();
            assert_state("applied");
            lease.restore().unwrap();
            assert_state("before");
            assert!(!Path::new(JOURNAL).exists());

            let mut lease = Lease::apply(before, None).unwrap();
            assert_state("applied");
            // Model a helper restart: its in-memory guard is gone but the
            // durable recovery plan remains. Startup must restore that plan.
            lease.active = false;
            drop(lease);
            recover().unwrap();
            assert_state("before");
            assert!(!Path::new(JOURNAL).exists());
        }
    }

    #[test]
    #[ignore = "requires root and temporary TUN on a disposable macOS GitHub Actions runner"]
    fn native_tun_transfers_https_and_releases_its_interface() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
        let uid: u32 = std::env::var("SUDO_UID").unwrap().parse().unwrap();
        let gid: u32 = std::env::var("SUDO_GID").unwrap().parse().unwrap();
        assert_ne!(uid, 0);
        let uplink = native::uplink().unwrap();
        let free_port = || {
            std::net::TcpListener::bind(("127.0.0.1", 0))
                .unwrap()
                .local_addr()
                .unwrap()
                .port()
        };
        let server_port = free_port();
        let port = free_port();
        let probe_port = free_port();
        assert!(server_port != port && port != probe_port && probe_port != server_port);
        // The synthetic remote endpoint remains outside the client's TUN. Its
        // DNS and data sockets are explicitly bound to the physical uplink.
        let server_config = serde_json::json!({
            "log":{"disabled":true},
            "dns":{"servers":[{"type":"https","tag":"outside","server":"1.1.1.1","bind_interface":uplink}]},
            "inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":server_port,
                "method":"chacha20-ietf-poly1305","password":"ci-loopback-only"}],
            "outbounds":[{"type":"direct","tag":"outside","bind_interface":uplink}],
            "route":{"default_domain_resolver":"outside","final":"outside"}
        });
        let mut endpoint = Cores {
            primary: Some(
                spawn(
                    Path::new(process::INSTALLED_CORE),
                    &["run", "-c", "/dev/stdin"],
                    &server_config,
                    Some((uid, gid)),
                )
                .unwrap(),
            ),
            secondary: None,
        };
        process::ready(endpoint.primary.as_mut().unwrap(), server_port).unwrap();
        let request = ConnectRequest {
            uri: format!("ss://chacha20-ietf-poly1305:ci-loopback-only@127.0.0.1:{server_port}"),
            bypass: vec![],
            port,
            bridge_port: None,
            probe_port: Some(probe_port),
            policies: vec![],
            kill_switch: false,
            connections: vec![],
        };
        let (client, mut server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(35)))
            .unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let worker = std::thread::spawn(move || {
            let result = session(&request, Mode::Tun, &mut server, uid, gid);
            let reply = match &result {
                Ok(()) => Reply::Stopped,
                Err(message) => Reply::Failed {
                    message: message.clone(),
                },
            };
            let _ = wire::send(&mut server, &reply);
            result
        });
        struct Owner {
            client: Option<UnixStream>,
            worker: Option<std::thread::JoinHandle<Result<()>>>,
        }
        impl Drop for Owner {
            fn drop(&mut self) {
                // Also restores the runner's settings when an assertion fails.
                self.client.take();
                if let Some(worker) = self.worker.take() {
                    let _ = worker.join();
                }
            }
        }
        let mut owner = Owner {
            client: Some(client),
            worker: Some(worker),
        };
        loop {
            match wire::receive::<Reply>(owner.client.as_mut().unwrap()).unwrap() {
                Reply::Checking => {}
                Reply::Ready => break,
                Reply::Failed { message } => panic!("TUN startup failed: {message}"),
                _ => panic!("Unexpected TUN startup reply"),
            }
        }
        assert_ne!(unsafe { libc::if_nametoindex(c"utun233".as_ptr()) }, 0);
        let mut curl = process::child_command(Path::new("/usr/bin/curl"));
        curl.args([
            "-q",
            "-4",
            "--noproxy",
            "*",
            "--connect-timeout",
            "5",
            "--max-time",
            "15",
            "--silent",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            "https://example.com/",
        ])
        .stdout(Stdio::piped())
        .stdin(Stdio::null());
        as_user(&mut curl, uid, gid);
        let result = curl.output().unwrap();
        assert!(
            result.status.success(),
            "HTTPS without an explicit proxy failed"
        );
        assert_eq!(result.stdout, b"200");
        wire::send(owner.client.as_mut().unwrap(), &Request::Stop {}).unwrap();
        assert!(matches!(
            wire::receive::<Reply>(owner.client.as_mut().unwrap()).unwrap(),
            Reply::Stopped
        ));
        owner.client.take();
        owner.worker.take().unwrap().join().unwrap().unwrap();
        assert_eq!(unsafe { libc::if_nametoindex(c"utun233".as_ptr()) }, 0);
        assert!(!Path::new(JOURNAL).exists());
    }
}
