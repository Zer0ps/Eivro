use crate::{
    CORE_VERSION, Result,
    config::{ConnectRequest, Mode, generate},
    import::{EngineKind, Profile, parse_uri},
};
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{fs::MetadataExt, net::UnixStream, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        mpsc::{self, Receiver},
    },
    thread,
    time::{Duration, Instant},
};

pub const INSTALLED_CORE: &str = "/usr/libexec/eivro/sing-box";
pub const HELPER: &str = "/usr/libexec/eivro/eivro-tun";
pub const INSTALLED_XRAY: &str = "/usr/libexec/eivro/xray";
pub const MAX_REQUEST: usize = 128 * 1024;

#[derive(Clone, Debug)]
pub enum Event {
    Progress(&'static str),
    Running,
    Stopped,
    Failed(String),
}

pub fn core_path() -> Result<PathBuf> {
    binary_path("sing-box", INSTALLED_CORE)
}

pub fn xray_path() -> Result<PathBuf> {
    binary_path("xray", INSTALLED_XRAY)
}

fn binary_path(name: &str, installed: &str) -> Result<PathBuf> {
    let exe = std::env::current_exe().map_err(|_| "Не удалось определить каталог приложения.")?;
    let dir = exe.parent().ok_or("Нет каталога приложения.")?;
    for path in [
        dir.join(name),
        dir.join(format!("../../vendor/{name}")),
        dir.join(format!("../../../vendor/{name}")),
        PathBuf::from(installed),
    ] {
        if path.is_file() {
            return Ok(path);
        }
    }
    Err(format!("Ядро {name} не найдено. Обновите сборку Eivro."))
}

pub fn helper_available() -> bool {
    trusted_binary(Path::new(HELPER)) && trusted_binary(Path::new(INSTALLED_CORE))
}

pub fn trusted_binary(path: &Path) -> bool {
    let mut current = Some(path);
    while let Some(p) = current {
        let Ok(m) = fs::symlink_metadata(p) else {
            return false;
        };
        if m.uid() != 0 || m.mode() & 0o022 != 0 || m.file_type().is_symlink() {
            return false;
        }
        current = p.parent();
    }
    path.is_file()
}

pub(crate) fn child_command(core: &Path) -> Command {
    let mut c = Command::new(core);
    c.env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("HOME", "/nonexistent")
        .env("XDG_CACHE_HOME", "/nonexistent")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let parent = unsafe { libc::getpid() };
    // No secret arguments, shell, or config files. The child dies with its supervisor.
    unsafe {
        c.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(std::io::Error::from_raw_os_error(libc::ECANCELED));
            }
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    c
}

fn version_check(core: &Path) -> Result<()> {
    let output = child_command(core)
        .arg("version")
        .stdout(Stdio::piped())
        .output()
        .map_err(|_| "Не удалось запустить ядро.")?;
    if !output.status.success()
        || !String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .is_some_and(|s| s == format!("sing-box version {CORE_VERSION}"))
    {
        return Err(format!(
            "Требуется sing-box {CORE_VERSION}. Используйте ядро из сборки Eivro."
        ));
    }
    Ok(())
}

fn xray_version_check(core: &Path) -> Result<()> {
    let output = child_command(core)
        .arg("version")
        .stdout(Stdio::piped())
        .output()
        .map_err(|_| "Не удалось запустить Xray.")?;
    if !output.status.success()
        || !String::from_utf8_lossy(&output.stdout)
            .starts_with(&format!("Xray {} ", crate::xray::VERSION))
    {
        return Err(format!(
            "Требуется Xray {} из сборки Eivro.",
            crate::xray::VERSION
        ));
    }
    Ok(())
}

fn check_xray(core: &Path, config: &serde_json::Value) -> Result<()> {
    let mut child = child_command(core)
        .args(["run", "-test", "-config", "stdin:"])
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|_| "Не удалось проверить Xray.")?;
    let written = child
        .stdin
        .take()
        .ok_or("Нет канала Xray.")?
        .write_all(config.to_string().as_bytes());
    let status = child.wait().map_err(|_| "Ошибка проверки Xray.")?;
    if written.is_err() || !status.success() {
        return Err("Xray отклонил параметры подключения. Импорт отменён.".into());
    }
    Ok(())
}

/// One offline core check for the complete imported Xray set, before storing keys.
pub fn validate_profiles(profiles: &[Profile]) -> Result<()> {
    let mut outbounds = Vec::new();
    let mut singbox = Vec::new();
    let mut first_singbox = None;
    for profile in profiles {
        let mut parsed = parse_uri(&profile.uri)?;
        if parsed.engine == EngineKind::Xray {
            parsed.outbound["tag"] = serde_json::json!(format!("endpoint-{}", outbounds.len()));
            outbounds.push(parsed.outbound);
        } else {
            if first_singbox.is_none() {
                first_singbox = Some(profile.uri.clone());
            }
            parsed.outbound["tag"] = serde_json::json!(if singbox.is_empty() {
                "proxy".into()
            } else {
                format!("endpoint-{}", singbox.len())
            });
            singbox.push(parsed.outbound);
        }
    }
    if !outbounds.is_empty() {
        let core = xray_path()?;
        xray_version_check(&core)?;
        let mut config = crate::xray::config(outbounds[0].clone(), 2081);
        config["outbounds"] = serde_json::json!(outbounds);
        check_xray(&core, &config)?;
    }
    if let Some(uri) = first_singbox {
        let core = core_path()?;
        version_check(&core)?;
        let mut config = generate(
            &ConnectRequest {
                connections: vec![],
                probe_port: None,
                policies: vec![],
                kill_switch: false,
                uri,
                bypass: vec![],
                port: 2080,
                bridge_port: None,
            },
            Mode::Proxy,
        )?;
        singbox.push(serde_json::json!({"type":"direct","tag":"direct"}));
        config["outbounds"] = serde_json::json!(singbox);
        let mut child = child_command(&core)
            .args(["check", "-c", "/dev/stdin"])
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|_| "Не удалось проверить sing-box.")?;
        let written = child
            .stdin
            .take()
            .ok_or("Нет канала sing-box.")?
            .write_all(config.to_string().as_bytes());
        let status = child.wait().map_err(|_| "Ошибка проверки sing-box.")?;
        if written.is_err() || !status.success() {
            return Err("sing-box отклонил параметры подключения. Импорт отменён.".into());
        }
    }
    Ok(())
}

struct XrayChild(Child);
impl Drop for XrayChild {
    fn drop(&mut self) {
        terminate(&mut self.0);
    }
}

fn start_xray(req: &ConnectRequest, watch: &UnixStream) -> Result<Option<XrayChild>> {
    let parsed = parse_uri(&req.uri)?;
    if parsed.engine != EngineKind::Xray {
        return Ok(None);
    }
    let port = req.bridge_port.ok_or("Нет служебного порта Xray.")?;
    let core = xray_path()?;
    xray_version_check(&core)?;
    let mut outbound = parsed.outbound;
    // Match sing-box's auto_detect_interface in every mode. Otherwise an
    // existing TUN silently turns the Xray connection into a VPN chain.
    pin_xray_uplink(&mut outbound, &parsed.host, Some(watch))?;
    let config = crate::xray::config(outbound, port);
    check_xray(&core, &config)?;
    let child = child_command(&core)
        .args(["run", "-config", "stdin:"])
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|_| "Не удалось запустить Xray.")?;
    let mut child = XrayChild(child);
    child
        .0
        .stdin
        .take()
        .ok_or("Нет канала Xray.")?
        .write_all(config.to_string().as_bytes())
        .map_err(|_| "Не удалось передать настройки Xray.")?;
    ready(&mut child.0, port)?;
    Ok(Some(child))
}

/// Only the root helper calls this path. Xray keeps the caller's uid and only
/// CAP_NET_RAW, needed for SO_MARK on Linux 5.17+, rather than running as root.
pub(crate) fn protected_xray(req: &ConnectRequest) -> Result<Option<Child>> {
    let parsed = parse_uri(&req.uri)?;
    if parsed.engine != EngineKind::Xray {
        return Ok(None);
    }
    let core = Path::new(INSTALLED_XRAY);
    if !trusted_binary(core) {
        return Err("Небезопасный исполняемый файл Xray.".into());
    }
    xray_version_check(core)?;
    let ip = crate::guard::resolve(&parsed.host)?;
    let mut outbound = parsed.outbound;
    pin_xray_uplink(&mut outbound, &ip.to_string(), None)?;
    outbound["streamSettings"]["sockopt"]["mark"] = serde_json::json!(crate::guard::MARK);
    let port = req.bridge_port.ok_or("Нет порта Xray.")?;
    let config = crate::xray::config(outbound, port);
    check_xray(core, &config)?;
    let uid = std::env::var("PKEXEC_UID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|uid| *uid > 0)
        .ok_or("Не определён пользователь Xray.")?;
    let mut cmd = child_command(core);
    restrict_xray(&mut cmd, uid)?;
    let mut child = cmd
        .args(["run", "-config", "stdin:"])
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|_| "Не удалось запустить Xray с ограниченными правами.")?;
    let result = (|| {
        child
            .stdin
            .take()
            .ok_or("Нет канала Xray.")?
            .write_all(config.to_string().as_bytes())
            .map_err(|_| "Нет канала Xray.")?;
        ready(&mut child, port)
    })();
    if let Err(e) = result {
        terminate(&mut child);
        return Err(e);
    }
    Ok(Some(child))
}

fn restrict_xray(cmd: &mut Command, uid: u32) -> Result<()> {
    let mut buffer = [0u8; 16384];
    let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    if unsafe {
        libc::getpwuid_r(
            uid,
            &mut passwd,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    } != 0
        || result.is_null()
    {
        return Err("Не удалось определить группу пользователя Xray.".into());
    }
    let gid = passwd.pw_gid;
    // Unprivileged user namespaces forbid setgroups; production always drops groups.
    #[cfg(test)]
    let skip_groups =
        uid == 0 && fs::read_to_string("/proc/self/setgroups").is_ok_and(|s| s.trim() == "deny");
    #[cfg(not(test))]
    let skip_groups = false;
    let parent = unsafe { libc::getpid() };
    unsafe {
        cmd.pre_exec(move || {
            #[repr(C)]
            struct Header {
                version: u32,
                pid: i32,
            }
            #[repr(C)]
            #[derive(Clone, Copy)]
            struct Data {
                effective: u32,
                permitted: u32,
                inheritable: u32,
            }
            let header = Header {
                version: 0x20080522,
                pid: 0,
            };
            let cap = 1u32 << 13;
            let data = [
                Data {
                    effective: cap,
                    permitted: cap,
                    inheritable: cap,
                },
                Data {
                    effective: 0,
                    permitted: 0,
                    inheritable: 0,
                },
            ];
            if libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0
                || (!skip_groups && libc::setgroups(0, std::ptr::null()) != 0)
                || libc::setresgid(gid, gid, gid) != 0
                || libc::setresuid(uid, uid, uid) != 0
                || libc::syscall(libc::SYS_capset, &header, data.as_ptr()) != 0
                || libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE, 13, 0, 0) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0
                || libc::getppid() != parent
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

/// Resolve before TUN exists and bind the external socket to an uplink. Otherwise
/// Xray's own DNS/dial can re-enter sing-box's TUN and recurse through the bridge.
fn pin_xray_uplink(
    out: &mut serde_json::Value,
    host: &str,
    watch: Option<&UnixStream>,
) -> Result<()> {
    let addresses =
        crate::resolver::resolve_host(host, 443, Instant::now() + Duration::from_secs(10), watch)
            .map_err(|e| match e.kind() {
            std::io::ErrorKind::Interrupted => "Подключение отменено.",
            std::io::ErrorKind::TimedOut => {
                "Истекло время DNS-запроса сервера Xray. Проверьте DNS и сеть."
            }
            _ => "Не удалось разрешить адрес сервера Xray.",
        })?;
    let ip = addresses
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addresses.first())
        .ok_or("У сервера нет IP-адреса.")?
        .ip();
    // Local endpoints belong to the local routing table, regardless of uplink.
    if ip.is_loopback() {
        return Ok(());
    }
    let utility = ["/usr/sbin/ip", "/usr/bin/ip"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
        .ok_or("Для выбора внешнего интерфейса Xray нужен iproute2.")?;
    let result = Command::new(utility)
        .args([
            "-j",
            if ip.is_ipv4() { "-4" } else { "-6" },
            "route",
            "show",
            "table",
            "main",
            "default",
        ])
        .stderr(Stdio::null())
        .output()
        .map_err(|_| "Не удалось определить внешний интерфейс.")?;
    if !result.status.success() {
        return Err("Не удалось прочитать внешние маршруты Xray.".into());
    }
    let routes: serde_json::Value =
        serde_json::from_slice(&result.stdout).map_err(|_| "Неверный ответ iproute2.")?;
    let route = routes
        .as_array()
        .and_then(|a| {
            a.iter()
                .filter(|r| {
                    r["dev"].as_str().is_some_and(|d| {
                        d != "lo"
                            && d != "eivro0"
                            && d != "velum0"
                            && !Path::new("/sys/class/net")
                                .join(d)
                                .join("tun_flags")
                                .exists()
                    })
                })
                .min_by_key(|r| r["metric"].as_u64().unwrap_or(0))
        })
        .ok_or("Нет внешнего маршрута для Xray.")?;
    let interface = route["dev"].as_str().ok_or("Нет сетевого интерфейса.")?;
    let name = std::ffi::CString::new(interface).map_err(|_| "Неверный сетевой интерфейс.")?;
    // Fail before starting cores if this kernel forbids unprivileged binding.
    let fd = unsafe {
        libc::socket(
            if ip.is_ipv4() {
                libc::AF_INET
            } else {
                libc::AF_INET6
            },
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err("Не удалось проверить внешний интерфейс.".into());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    if unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            name.as_bytes_with_nul().len() as libc::socklen_t,
        )
    } != 0
    {
        return Err("Система запрещает привязку Xray к внешнему интерфейсу.".into());
    }
    // The parser has made serverName explicit. Xray's WS/XHTTP defaults use
    // that SNI for Host; setting Host to the dial address would change behavior.
    let settings = &mut out["settings"];
    if settings.get("vnext").is_some() {
        settings["vnext"][0]["address"] = serde_json::json!(ip.to_string());
    } else if settings.get("servers").is_some() {
        settings["servers"][0]["address"] = serde_json::json!(ip.to_string());
    } else {
        settings["address"] = serde_json::json!(ip.to_string());
    }
    out["streamSettings"]["sockopt"] = serde_json::json!({"interface":interface});
    Ok(())
}

pub fn spawn_core(core: &Path, req: &ConnectRequest, mode: Mode) -> Result<Child> {
    version_check(core)?;
    let links = if req.connections.is_empty() {
        Vec::new()
    } else {
        crate::network::interfaces()
    };
    spawn_configuration(
        core,
        &crate::config::generate_with_network(req, mode, &links)?,
    )
}

pub(crate) fn spawn_configuration(core: &Path, config: &serde_json::Value) -> Result<Child> {
    let data = serde_json::to_vec(config).map_err(|_| "Ошибка конфигурации.")?;
    let mut check = child_command(core)
        .args(["check", "-c", "/dev/stdin"])
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|_| "Не удалось проверить конфигурацию.")?;
    let written = check
        .stdin
        .take()
        .ok_or("Нет канала конфигурации.")?
        .write_all(&data);
    let valid = check.wait().map_err(|_| "Ошибка проверки конфигурации.")?;
    if written.is_err() || !valid.success() {
        return Err("Ядро отклонило конфигурацию. Проверьте параметры сервера.".into());
    }
    let mut child = child_command(core)
        .args(["run", "-c", "/dev/stdin"])
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|_| "Не удалось запустить ядро.")?;
    if child
        .stdin
        .take()
        .ok_or("Нет канала конфигурации.")?
        .write_all(&data)
        .is_err()
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err("Не удалось передать конфигурацию ядру.".into());
    }
    Ok(child)
}

pub fn pid_fd(child: &Child) -> Result<OwnedFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) };
    if fd < 0 {
        return Err("Нужен Linux 5.3+ с поддержкой pidfd.".into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

pub fn terminate(child: &mut Child) {
    if child.try_wait().ok().flatten().is_some() {
        return;
    }
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let end = Instant::now() + Duration::from_secs(3);
    while Instant::now() < end {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        thread::sleep(Duration::from_millis(30));
    }
    let _ = child.kill();
    let _ = child.wait();
}

pub fn ready(child: &mut Child, port: u16) -> Result<()> {
    let end = Instant::now() + Duration::from_secs(5);
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    while Instant::now() < end {
        if child
            .try_wait()
            .map_err(|_| "Ошибка процесса ядра.")?
            .is_some()
        {
            return Err("Ядро остановилось при запуске. Проверьте порт и доступность TUN.".into());
        }
        if let Ok(mut sock) = TcpStream::connect_timeout(&addr, Duration::from_millis(100)) {
            let _ = sock.set_read_timeout(Some(Duration::from_millis(150)));
            let _ = sock.set_write_timeout(Some(Duration::from_millis(150)));
            let mut reply = [0; 2];
            if sock.write_all(&[5, 1, 0]).is_ok()
                && sock.read_exact(&mut reply).is_ok()
                && reply == [5, 0]
            {
                thread::sleep(Duration::from_millis(100));
                if child.try_wait().ok().flatten().is_none() {
                    return Ok(());
                }
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err("Ядро не открыло локальный прокси.".into())
}

pub struct Session {
    stop: Option<UnixStream>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Session {
    pub fn start(
        req: ConnectRequest,
        mode: Mode,
        notify: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<(Self, Receiver<Event>)> {
        Self::start_with_controller(
            req,
            mode,
            notify,
            Arc::new(crate::tun::Controller::default()),
        )
    }
    pub fn start_with_controller(
        mut req: ConnectRequest,
        mode: Mode,
        notify: Arc<dyn Fn() + Send + Sync>,
        controller: Arc<crate::tun::Controller>,
    ) -> Result<(Self, Receiver<Event>)> {
        if parse_uri(&req.uri)?.engine == EngineKind::Xray {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
                .map_err(|_| "Нет свободного порта Xray.")?;
            let port = listener
                .local_addr()
                .map_err(|_| "Нет адреса Xray.")?
                .port();
            if port == req.port {
                return Err("Не удалось выбрать служебный порт. Повторите подключение.".into());
            }
            req.bridge_port = Some(port);
        }
        if mode != Mode::Local {
            req.probe_port = Some(free_port(&[req.port, req.bridge_port.unwrap_or(0)])?);
        } else {
            req.probe_port = None;
        }
        generate(&req, mode)?;
        if mode == Mode::Tun && !helper_available() {
            return Err("Для TUN установите RPM/DEB: нужен системный помощник Eivro.".into());
        }
        let (stop, watch) =
            UnixStream::pair().map_err(|_| "Не удалось создать канал управления.")?;
        let (tx, rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let event = match supervise(req, mode, watch, &controller, |event| {
                let _ = tx.send(event);
                notify();
            }) {
                Ok(()) => Event::Stopped,
                Err(e) => Event::Failed(e),
            };
            let _ = tx.send(event);
            notify();
        });
        Ok((
            Self {
                stop: Some(stop),
                worker: Some(worker),
            },
            rx,
        ))
    }
    pub fn stop(&mut self) {
        self.stop.take();
    }
    pub fn restart(&mut self) {
        if let Some(mut stop) = self.stop.take() {
            let _ = stop.write_all(b"R");
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop.take();
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}

fn supervise(
    req: ConnectRequest,
    mode: Mode,
    watch: UnixStream,
    controller: &crate::tun::Controller,
    notify: impl Fn(Event),
) -> Result<()> {
    if mode == Mode::Tun {
        tun_preflight()?;
        let output = child_command(Path::new(HELPER))
            .arg("--version")
            .stdout(Stdio::piped())
            .output()
            .map_err(|_| "Не удалось проверить версию помощника TUN.")?;
        if output.stdout != format!("Eivro TUN {}\n", env!("CARGO_PKG_VERSION")).as_bytes() {
            return Err(
                "Обновите RPM/DEB Eivro: версия помощника TUN не совпадает с приложением.".into(),
            );
        }
        notify(Event::Progress("Запрос прав TUN…"));
    }
    // Reserve-check only; startup liveness below detects the bind race.
    let probe = std::net::TcpListener::bind(("127.0.0.1", req.port))
        .map_err(|_| "Локальный порт уже занят.")?;
    drop(probe);
    let xray = if req.kill_switch {
        None
    } else {
        match start_xray(&req, &watch) {
            Ok(child) => child,
            Err(error) => {
                let mut fd = pollfd(watch.as_raw_fd(), libc::POLLIN);
                if unsafe { libc::poll(&mut fd, 1, 0) } > 0 {
                    return Ok(());
                }
                return Err(error);
            }
        }
    };
    let xray_pid = xray.as_ref().map(|c| pid_fd(&c.0)).transpose()?;
    let xray_fd = xray_pid.as_ref().map_or(-1, AsRawFd::as_raw_fd);
    if mode == Mode::Tun {
        return controller.run(&req, &watch, xray_fd, |pid| {
            if let Some(port) = req.probe_port {
                notify(Event::Progress("Проверка соединения…"));
                if !check_connection(port, &watch, pid, xray_fd)? {
                    return Ok(false);
                }
            }
            notify(Event::Running);
            Ok(true)
        });
    }
    let mut child = spawn_core(&core_path()?, &req, mode)?;
    let mut proxy_guard: Option<ProxyGuard> = None;
    let result = (|| {
        let pid = pid_fd(&child)?;
        ready(&mut child, req.port)?;
        if let Some(port) = req.probe_port {
            notify(Event::Progress("Проверка соединения…"));
            if !check_connection(port, &watch, pid.as_raw_fd(), xray_fd)? {
                return Ok(());
            }
        }
        if mode == Mode::Proxy {
            notify(Event::Progress("Включение прокси GNOME…"));
            proxy_guard = Some(ProxyGuard::start(req.port)?);
            if !proxy_guard
                .as_mut()
                .unwrap()
                .ready(&watch, pid.as_raw_fd(), xray_fd)?
            {
                return Ok(());
            }
        }
        let guard_pid = proxy_guard.as_ref().map(|g| pid_fd(&g.child)).transpose()?;
        notify(Event::Running);
        let mut fds = [
            pollfd(watch.as_raw_fd(), libc::POLLIN),
            pollfd(pid.as_raw_fd(), libc::POLLIN),
            pollfd(xray_fd, libc::POLLIN),
            pollfd(
                guard_pid.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                libc::POLLIN,
            ),
        ];
        poll(&mut fds)?;
        if fds[0].revents != 0 {
            Ok(())
        } else {
            Err("Соединение остановлено: процесс ядра завершился.".into())
        }
    })();
    let restored = proxy_guard.as_mut().map_or(Ok(()), ProxyGuard::finish);
    terminate(&mut child);
    result.and(restored)
}

pub fn pollfd(fd: i32, events: i16) -> libc::pollfd {
    libc::pollfd {
        fd,
        events,
        revents: 0,
    }
}
pub fn poll(fds: &mut [libc::pollfd]) -> Result<()> {
    loop {
        let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if result >= 0 {
            return Ok(());
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err("Ошибка ожидания процесса.".into());
        }
    }
}
fn set_nonblocking(fd: i32) -> Result<()> {
    if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
        Err("Ошибка канала управления.".into())
    } else {
        Ok(())
    }
}

pub(crate) fn free_port(excluded: &[u16]) -> Result<u16> {
    for _ in 0..8 {
        let socket = std::net::TcpListener::bind(("127.0.0.1", 0))
            .map_err(|_| "Нет свободного служебного порта.")?;
        let port = socket
            .local_addr()
            .map_err(|_| "Нет служебного порта.")?
            .port();
        if !excluded.contains(&port) {
            return Ok(port);
        }
    }
    Err("Не удалось выбрать свободный порт.".into())
}

pub fn tun_preflight() -> Result<()> {
    if !Path::new("/dev/net/tun").exists() {
        return Err("Устройство /dev/net/tun недоступно этому процессу.".into());
    }
    let ip = ["/usr/sbin/ip", "/usr/bin/ip"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .ok_or("Для TUN нужен iproute2.")?;
    let output = Command::new(ip)
        .args(["-j", "route", "show", "table", "all"])
        .stderr(Stdio::null())
        .output()
        .map_err(|_| "Не удалось проверить маршруты перед TUN.")?;
    if !output.status.success() {
        return Err("Не удалось проверить маршруты перед TUN.".into());
    }
    let routes: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|_| "Неверный ответ iproute2.")?;
    if routes.as_array().is_some_and(|rs| {
        rs.iter().any(|r| {
            let dev = r["dev"].as_str().unwrap_or("");
            let dst = r["dst"].as_str().unwrap_or("");
            ["default", "0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"].contains(&dst)
                && (dev == "eivro0"
                    || dev == "velum0"
                    || Path::new("/sys/class/net")
                        .join(dev)
                        .join("tun_flags")
                        .exists())
        })
    }) {
        return Err("Уже активен другой VPN/TUN. Отключите его перед подключением Eivro.".into());
    }
    Ok(())
}

pub(crate) fn app_path() -> Result<PathBuf> {
    let exe = std::env::current_exe().map_err(|_| "Нет пути Eivro.")?;
    if exe.file_name().is_some_and(|s| s == "eivro") {
        return Ok(exe);
    }
    // Integration tests and diagnostic examples are one directory below the GUI.
    for dir in exe.parent().into_iter().flat_map(|p| p.ancestors()).take(3) {
        let path = dir.join("eivro");
        if path.is_file() {
            return Ok(path);
        }
    }
    Err("Не найден исполняемый файл Eivro.".into())
}

fn check_connection(port: u16, watch: &UnixStream, core: i32, xray: i32) -> Result<bool> {
    let child = child_command(&app_path()?)
        .args(["--check-connection", &port.to_string()])
        .stdin(Stdio::null())
        .spawn()
        .map_err(|_| "Не удалось проверить соединение.")?;
    // The HTTP client's timeout does not bound every proxy/TLS operation.
    // Keep cancellation and core-exit monitoring active under a total deadline.
    supervise_connection_check(child, watch, core, xray, Duration::from_secs(18))
}

fn supervise_connection_check(
    mut child: Child,
    watch: &UnixStream,
    core: i32,
    xray: i32,
    timeout: Duration,
) -> Result<bool> {
    let result = (|| {
        let pid = pid_fd(&child)?;
        let mut fds = [
            pollfd(watch.as_raw_fd(), libc::POLLIN),
            pollfd(core, libc::POLLIN),
            pollfd(xray, libc::POLLIN),
            pollfd(pid.as_raw_fd(), libc::POLLIN),
        ];
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let millis = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
            let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, millis) };
            if result > 0 {
                break;
            }
            if result == 0 || Instant::now() >= deadline {
                return Err("Истекло время проверки HTTPS через выбранный сервер. Проверьте сеть или выберите другой сервер.".into());
            }
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return Err("Ошибка ожидания проверки соединения.".into());
            }
        }
        if fds[0].revents != 0 {
            return Ok(false);
        }
        if fds[1].revents != 0 || fds[2].revents != 0 {
            return Err("Ядро остановилось во время проверки соединения.".into());
        }
        if !child
            .wait()
            .map_err(|_| "Ошибка проверки соединения.")?
            .success()
        {
            return Err("Нет HTTPS-соединения через выбранный сервер. Попробуйте другой сервер; если запущен другой VPN, отключите его.".into());
        }
        Ok(true)
    })();
    terminate(&mut child);
    result
}

struct ProxyGuard {
    child: Child,
    finished: bool,
}
impl ProxyGuard {
    fn start(port: u16) -> Result<Self> {
        // Deliberately no parent-death signal: this process must survive a GUI
        // crash long enough to restore GNOME settings when its stdin closes.
        let child = Command::new(app_path()?)
            .args(["--proxy-guard", &port.to_string()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "Не удалось запустить восстановление системного прокси.")?;
        Ok(Self {
            child,
            finished: false,
        })
    }
    fn ready(&mut self, watch: &UnixStream, core: i32, xray: i32) -> Result<bool> {
        let pid = pid_fd(&self.child)?;
        let mut output = self
            .child
            .stdout
            .take()
            .ok_or("Нет ответа системного прокси.")?;
        set_nonblocking(output.as_raw_fd())?;
        let mut reply = Vec::new();
        loop {
            let mut fds = [
                pollfd(watch.as_raw_fd(), libc::POLLIN),
                pollfd(core, libc::POLLIN),
                pollfd(xray, libc::POLLIN),
                pollfd(pid.as_raw_fd(), libc::POLLIN),
                pollfd(output.as_raw_fd(), libc::POLLIN),
            ];
            poll(&mut fds)?;
            if fds[0].revents != 0 {
                return Ok(false);
            }
            if fds[1].revents != 0 || fds[2].revents != 0 {
                return Err("Ядро остановилось при включении системного прокси.".into());
            }
            if fds[4].revents != 0 {
                let mut buffer = [0; 1024];
                match output.read(&mut buffer) {
                    Ok(0) => return Err("Не удалось включить системный прокси GNOME.".into()),
                    Ok(n) => reply.extend_from_slice(&buffer[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => return Err("Не удалось прочитать ответ системного прокси.".into()),
                }
                if reply.ends_with(b"\n") {
                    if reply == b"READY\n" {
                        return Ok(true);
                    }
                    return Err(String::from_utf8_lossy(&reply)
                        .trim()
                        .trim_start_matches("ERROR: ")
                        .to_owned());
                }
                if reply.len() > 2048 {
                    return Err("Неверный ответ системного прокси.".into());
                }
            }
            if fds[3].revents != 0 {
                return Err("Процесс системного прокси завершился.".into());
            }
        }
    }
    fn finish(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        self.child.stdin.take();
        let pid = pid_fd(&self.child)?;
        let mut fd = pollfd(pid.as_raw_fd(), libc::POLLIN);
        let timed_out = unsafe { libc::poll(&mut fd, 1, 10000) } <= 0;
        if timed_out {
            let _ = self.child.kill();
        }
        let status = self
            .child
            .wait()
            .map_err(|_| "Ошибка восстановления системного прокси.")?;
        self.finished = true;
        match status.code() {
            Some(0)=>Ok(()),
            Some(2)=>Err("Прокси изменён другим приложением. Его настройки оставлены без изменений.".into()),
            _=>Err("Соединение остановлено, но восстановить прокси GNOME не удалось. Перезапустите Eivro для повторного восстановления.".into()),
        }
    }
}
impl Drop for ProxyGuard {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

pub fn helper_compatible() -> bool {
    helper_available()
        && child_command(Path::new(HELPER))
            .arg("--version")
            .stdout(Stdio::piped())
            .output()
            .is_ok_and(|o| {
                o.status.success()
                    && o.stdout == format!("Eivro TUN {}\n", env!("CARGO_PKG_VERSION")).as_bytes()
            })
}

pub fn install_package_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let arch = std::env::consts::ARCH;
    let version = env!("CARGO_PKG_VERSION").replace('-', "~");
    let name = if Path::new("/usr/bin/dnf").exists() {
        format!("eivro-{version}-1.{arch}.rpm")
    } else {
        let arch = match arch {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            _ => return None,
        };
        format!("eivro_{version}_{arch}.deb")
    };
    exe.parent()?
        .ancestors()
        .take(4)
        .map(|p| p.join("dist").join(&name))
        .find(|p| p.is_file())
}

pub fn install_package() -> Result<()> {
    let package = install_package_path()
        .ok_or("Рядом с приложением нет RPM/DEB этой версии.")?
        .canonicalize()
        .map_err(|_| "Нет установочного пакета.")?;
    let mut cmd = Command::new("/usr/bin/pkexec");
    if package.extension().is_some_and(|e| e == "rpm") {
        cmd.args(["/usr/bin/dnf", "install", "-y"]);
    } else {
        cmd.args(["/usr/bin/apt-get", "install", "-y"]);
    }
    let status = cmd
        .arg(package)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "Не удалось открыть установщик.")?;
    if !status.success() || !helper_compatible() {
        return Err(
            "Пакет не установлен: запрос прав отменён или установка завершилась ошибкой.".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod privilege_tests {
    use super::*;
    #[test]
    fn xray_mark_capability_is_limited_in_user_namespace() {
        if std::env::var_os("EIVRO_CAP_TEST").is_none() {
            let out = Command::new("unshare")
                .args(["--user", "--map-root-user", "--net"])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "process::privilege_tests::xray_mark_capability_is_limited_in_user_namespace",
                    "--nocapture",
                ])
                .env("EIVRO_CAP_TEST", "1")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        }
        let mapping = fs::read_to_string("/proc/self/uid_map").unwrap();
        assert_eq!(mapping.split_whitespace().last(), Some("1"));
        let mut cmd = Command::new("python3");
        restrict_xray(&mut cmd, 0).unwrap();
        let script = "import socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\ns.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,0x56454c55)\nv=dict(x.split(':',1) for x in open('/proc/self/status') if ':' in x)\nassert int(v['CapEff'],16)==1<<13,v['CapEff']\nassert int(v['NoNewPrivs'])==1\n";
        let out = cmd.args(["-c", script]).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[cfg(test)]
mod connection_check_tests {
    use super::*;

    fn sleeper() -> Child {
        Command::new("sleep").arg("30").spawn().unwrap()
    }

    #[test]
    fn stalled_check_times_out_and_is_reaped() {
        let (_stop, watch) = UnixStream::pair().unwrap();
        let mut core = sleeper();
        let core_fd = pid_fd(&core).unwrap();
        let check = sleeper();
        let check_fd = pid_fd(&check).unwrap();
        let start = Instant::now();
        let result = supervise_connection_check(
            check,
            &watch,
            core_fd.as_raw_fd(),
            -1,
            Duration::from_millis(50),
        );
        terminate(&mut core);
        assert!(result.unwrap_err().contains("Истекло время"));
        assert!(start.elapsed() < Duration::from_secs(5));
        let mut ended = [pollfd(check_fd.as_raw_fd(), libc::POLLIN)];
        assert_eq!(unsafe { libc::poll(ended.as_mut_ptr(), 1, 0) }, 1);
    }

    #[test]
    fn cancelling_a_stalled_check_does_not_wait_for_the_deadline() {
        let (stop, watch) = UnixStream::pair().unwrap();
        drop(stop);
        let mut core = sleeper();
        let core_fd = pid_fd(&core).unwrap();
        let result = supervise_connection_check(
            sleeper(),
            &watch,
            core_fd.as_raw_fd(),
            -1,
            Duration::from_secs(30),
        );
        terminate(&mut core);
        assert!(!result.unwrap());
    }

    #[test]
    fn successful_check_is_accepted_only_with_a_live_core() {
        let (_stop, watch) = UnixStream::pair().unwrap();
        let mut core = sleeper();
        let core_fd = pid_fd(&core).unwrap();
        let result = supervise_connection_check(
            Command::new("true").spawn().unwrap(),
            &watch,
            core_fd.as_raw_fd(),
            -1,
            Duration::from_secs(2),
        );
        terminate(&mut core);
        assert!(result.unwrap());
    }

    #[test]
    fn core_exit_interrupts_a_stalled_check() {
        let (_stop, watch) = UnixStream::pair().unwrap();
        let mut core = Command::new("true").spawn().unwrap();
        let core_fd = pid_fd(&core).unwrap();
        let result = supervise_connection_check(
            sleeper(),
            &watch,
            core_fd.as_raw_fd(),
            -1,
            Duration::from_secs(30),
        );
        let _ = core.wait();
        assert!(result.unwrap_err().contains("Ядро остановилось"));
    }
}
