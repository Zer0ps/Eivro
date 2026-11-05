use crate::platform::windows::{
    core_child::CoreChild,
    native::{self, Event as Signal, Job, raw, wait},
    network,
};
pub use crate::process_profiles::validate_profiles;
use crate::{
    CORE_VERSION, Result,
    config::{ConnectRequest, Mode},
    import::{EngineKind, parse_uri},
};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        mpsc::{self, Receiver},
    },
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::System::{
    Pipes::PeekNamedPipe, SystemInformation::GetWindowsDirectoryW, Threading::*,
};
pub(crate) const CONFIG_INPUT: &str = "stdin";
pub const MAX_REQUEST: usize = 2 * 1024 * 1024;
#[derive(Clone, Debug)]
pub enum Event {
    Progress(&'static str),
    Running,
    Stopped,
    Failed(String),
}
pub fn core_path() -> Result<PathBuf> {
    binary_path("sing-box.exe")
}
pub fn xray_path() -> Result<PathBuf> {
    binary_path("xray.exe")
}
fn binary_path(name: &str) -> Result<PathBuf> {
    let exe = std::env::current_exe().map_err(|_| "Нет пути Eivro.")?;
    for dir in exe
        .parent()
        .into_iter()
        .flat_map(|dir| dir.ancestors())
        .take(4)
    {
        for candidate in [dir.join(name), dir.join("vendor/windows").join(name)] {
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    let installed = native::installed_dir()
        .map_err(|_| "Нет каталога установки.")?
        .join(name);
    if installed.is_file() {
        Ok(installed)
    } else {
        Err(format!("Не найден {name}. Переустановите Eivro."))
    }
}
pub(crate) fn app_path() -> Result<PathBuf> {
    let exe = std::env::current_exe().map_err(|_| "Нет пути Eivro.")?;
    if exe
        .file_name()
        .is_some_and(|name| name == "eivro.exe" || name == "eivro-tun.exe")
    {
        return Ok(exe);
    }
    binary_path("eivro.exe")
}
pub fn trusted_binary(path: &Path) -> bool {
    native::protected_binary(path)
}
pub fn helper_available() -> bool {
    native::installed_dir().is_ok_and(|dir| {
        [
            "eivro-tun.exe",
            "sing-box.exe",
            "xray.exe",
            "wintun.dll",
            "libcronet.dll",
        ]
        .iter()
        .all(|name| trusted_binary(&dir.join(name)))
    })
}
pub fn helper_compatible() -> bool {
    helper_available() && crate::platform::windows::service::installed_version_matches()
}
pub fn install_package_path() -> Option<PathBuf> {
    None
}
pub fn install_package() -> Result<()> {
    Err(crate::platform::HELPER_HINT.into())
}
pub(crate) fn child_command(path: &Path) -> Command {
    let mut command = Command::new(path);
    let mut system = [0u16; 32768];
    let count = unsafe { GetWindowsDirectoryW(system.as_mut_ptr(), system.len() as u32) } as usize;
    command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW);
    if count > 0 && count < system.len() {
        let root = String::from_utf16_lossy(&system[..count]);
        command
            .env("SystemRoot", &root)
            .env("WINDIR", &root)
            .env("PATH", format!("{root}\\System32"));
    }
    if let Some(dir) = path.parent() {
        command.current_dir(dir);
    }
    command
}
fn finish_check(
    mut child: Child,
    job: &Job,
    input: Option<&[u8]>,
    timeout: u32,
) -> Result<Vec<u8>> {
    let result = (|| {
        if job.assign(&child).is_err()
            && child.try_wait().map_err(|_| "Нет статуса ядра.")?.is_none()
        {
            return Err("Не удалось ограничить процесс ядра.".into());
        }
        if let Some(bytes) = input {
            child
                .stdin
                .take()
                .ok_or("Нет канала ядра.")?
                .write_all(bytes)
                .map_err(|_| "Нет канала ядра.")?;
        }
        if wait(&[raw(&child)], timeout)
            .map_err(|_| "Ошибка ожидания ядра.")?
            .is_none()
        {
            return Err("Истекло время проверки ядра.".into());
        }
        if !child.wait().map_err(|_| "Нет статуса ядра.")?.success() {
            return Err("Ядро отклонило параметры подключения.".into());
        }
        let mut output = Vec::new();
        if let Some(stdout) = child.stdout.take() {
            stdout
                .take(65537)
                .read_to_end(&mut output)
                .map_err(|_| "Ошибка ответа ядра.")?;
        }
        if output.len() > 65536 {
            return Err("Слишком большой ответ ядра.".into());
        }
        Ok(output)
    })();
    terminate(&mut child);
    result
}
fn version(path: &Path, expected: &str) -> Result<()> {
    let job = Job::new().map_err(|_| "Не удалось ограничить процесс ядра.")?;
    let child = child_command(path)
        .arg("version")
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|_| "Не удалось запустить ядро.")?;
    let output = finish_check(child, &job, None, 10000)?;
    if !String::from_utf8_lossy(&output).starts_with(expected) {
        return Err("Версия ядра отличается от версии в сборке Eivro.".into());
    }
    Ok(())
}
pub(crate) fn version_check(path: &Path) -> Result<()> {
    version(path, &format!("sing-box version {CORE_VERSION}\n"))
}
pub(crate) fn xray_version_check(path: &Path) -> Result<()> {
    version(path, &format!("Xray {} ", crate::xray::VERSION))
}
pub(crate) fn check_xray(path: &Path, config: &serde_json::Value) -> Result<()> {
    check_configuration(path, &["run", "-test", "-config", "stdin:"], config)
}
fn check_configuration(path: &Path, args: &[&str], config: &serde_json::Value) -> Result<()> {
    let bytes = serde_json::to_vec(config).map_err(|_| "Ошибка конфигурации.")?;
    let job = Job::new().map_err(|_| "Нет задания ядра.")?;
    let child = child_command(path)
        .args(args)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|_| "Не удалось проверить ядро.")?;
    finish_check(child, &job, Some(&bytes), 15000).map(|_| ())
}
pub fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}
pub fn ready(child: &CoreChild, port: u16) -> Result<()> {
    let end = Instant::now() + Duration::from_secs(5);
    let address: SocketAddr = ([127, 0, 0, 1], port).into();
    while Instant::now() < end {
        if child.exited().map_err(|_| "Ошибка процесса ядра.")? {
            return Err("Ядро остановилось при запуске.".into());
        }
        if let Ok(mut socket) = TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            let _ = socket.set_read_timeout(Some(Duration::from_millis(150)));
            let _ = socket.set_write_timeout(Some(Duration::from_millis(150)));
            let mut reply = [0; 2];
            if socket.write_all(&[5, 1, 0]).is_ok()
                && socket.read_exact(&mut reply).is_ok()
                && reply == [5, 0]
            {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err("Ядро не открыло локальный прокси.".into())
}
pub(crate) fn free_port(excluded: &[u16]) -> Result<u16> {
    for _ in 0..8 {
        let socket = TcpListener::bind(("127.0.0.1", 0)).map_err(|_| "Нет свободного порта.")?;
        let port = socket
            .local_addr()
            .map_err(|_| "Нет адреса прокси.")?
            .port();
        if !excluded.contains(&port) {
            return Ok(port);
        }
    }
    Err("Не удалось выбрать порт.".into())
}
pub struct Running {
    pub primary: CoreChild,
    pub secondary: Option<CoreChild>,
    _job: Job,
    lease: Option<crate::platform::windows::network_lease::Lease>,
}
impl Running {
    pub fn shutdown(&mut self) -> Result<()> {
        self.primary.stop();
        if let Some(child) = &mut self.secondary {
            child.stop();
        }
        if let Some(lease) = &mut self.lease {
            lease.restore()?;
        }
        Ok(())
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}
fn start_child(
    path: &Path,
    args: &[&str],
    config: &serde_json::Value,
    job: &Job,
) -> Result<CoreChild> {
    CoreChild::spawn(path, args, config.to_string().as_bytes(), job)
}
pub fn start_cores(
    req: &ConnectRequest,
    mode: Mode,
    cancel: &Signal,
    privileged: bool,
) -> Result<Running> {
    if cancel.signaled() {
        return Err("Подключение отменено.".into());
    }
    let paths = if privileged {
        let dir = native::installed_dir().map_err(|_| "Нет каталога установки.")?;
        (dir.join("sing-box.exe"), dir.join("xray.exe"))
    } else {
        (core_path()?, xray_path()?)
    };
    if privileged
        && (!trusted_binary(&paths.0)
            || !trusted_binary(&paths.1)
            || !paths.0.parent().is_some_and(|dir| {
                ["wintun.dll", "libcronet.dll"]
                    .iter()
                    .all(|name| trusted_binary(&dir.join(name)))
            }))
    {
        return Err("Небезопасные права установки Eivro.".into());
    }
    let lease = if mode == Mode::Tun {
        Some(crate::platform::windows::network_lease::Lease::begin()?)
    } else {
        None
    };
    version_check(&paths.0)?;
    let job = Job::new().map_err(|_| "Не удалось создать задание ядра.")?;
    let parsed = parse_uri(&req.uri)?;
    let mut secondary = None;
    if parsed.engine == EngineKind::Xray {
        xray_version_check(&paths.1)?;
        let mut outbound = parsed.outbound;
        let addresses = crate::resolver::resolve_host(
            &parsed.host,
            443,
            Instant::now() + Duration::from_secs(10),
            Some(cancel),
        )
        .map_err(|_| {
            if cancel.signaled() {
                "Подключение отменено."
            } else {
                "Не удалось разрешить адрес VPN-сервера."
            }
        })?;
        let ip = addresses
            .iter()
            .find(|a| a.is_ipv4())
            .or_else(|| addresses.first())
            .ok_or("У сервера нет IP-адреса.")?
            .ip();
        if !ip.is_loopback() {
            let interface = network::uplink(ip)?;
            let settings = &mut outbound["settings"];
            if settings.get("vnext").is_some() {
                settings["vnext"][0]["address"] = serde_json::json!(ip.to_string());
            } else if settings.get("servers").is_some() {
                settings["servers"][0]["address"] = serde_json::json!(ip.to_string());
            } else {
                settings["address"] = serde_json::json!(ip.to_string());
            }
            outbound["streamSettings"]["sockopt"] = serde_json::json!({"interface":interface});
        }
        let port = req.bridge_port.ok_or("Нет порта Xray.")?;
        let config = crate::xray::config(outbound, port);
        check_xray(&paths.1, &config)?;
        let mut child = start_child(&paths.1, &["run", "-config", "stdin:"], &config, &job)?;
        if let Err(e) = ready(&child, port) {
            child.stop();
            return Err(e);
        }
        secondary = Some(child);
    }
    let result = (|| {
        if cancel.signaled() {
            return Err("Подключение отменено.".into());
        }
        let config = crate::config::generate_with_network(req, mode, &network::interfaces())?;
        check_configuration(&paths.0, &["check", "-c", CONFIG_INPUT], &config)?;
        let mut child = start_child(&paths.0, &["run", "-c", CONFIG_INPUT], &config, &job)?;
        if let Err(e) = ready(&child, req.port) {
            child.stop();
            return Err(e);
        }
        Ok(child)
    })();
    match result {
        Ok(primary) => Ok(Running {
            primary,
            secondary,
            _job: job,
            lease,
        }),
        Err(e) => {
            if let Some(child) = &mut secondary {
                child.stop();
            }
            Err(e)
        }
    }
}
pub fn check_connection(running: &Running, port: u16, cancel: &Signal) -> Result<bool> {
    let mut child = child_command(&app_path()?)
        .args(["--check-connection", &port.to_string()])
        .spawn()
        .map_err(|_| "Не удалось проверить соединение.")?;
    let result = (|| {
        running
            ._job
            .assign(&child)
            .map_err(|_| "Не удалось ограничить проверку.")?;
        let mut handles = vec![cancel.handle(), raw(&child), raw(&running.primary)];
        if let Some(xray) = &running.secondary {
            handles.push(raw(xray));
        }
        match wait(&handles, 18000).map_err(|_| "Ошибка ожидания проверки.")?
        {
            Some(0) => Ok(false),
            Some(1) => {
                if child.wait().map_err(|_| "Ошибка проверки.")?.success() {
                    Ok(true)
                } else {
                    Err("Нет HTTPS-соединения через выбранный сервер.".into())
                }
            }
            Some(_) => Err("Ядро остановилось во время проверки.".into()),
            None => Err("Истекло время проверки HTTPS через сервер.".into()),
        }
    })();
    terminate(&mut child);
    result
}
pub struct Session {
    cancel: Signal,
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
            req.bridge_port = Some(free_port(&[req.port])?);
        }
        req.probe_port = if mode != Mode::Local {
            Some(free_port(&[req.port, req.bridge_port.unwrap_or(0)])?)
        } else {
            None
        };
        crate::config::generate(&req, mode)?;
        if mode == Mode::Tun && !helper_available() {
            return Err(crate::platform::HELPER_HINT.into());
        }
        let cancel = Signal::new().map_err(|_| "Нет события управления.")?;
        let stop = cancel.clone();
        let (tx, rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let report = |event| {
                let _ = tx.send(event);
                notify();
            };
            let result = if mode == Mode::Tun {
                controller.run_session(&req, mode, &stop, report)
            } else {
                supervise_local(&req, mode, &stop, report)
            };
            report(match result {
                Ok(()) => Event::Stopped,
                Err(ref e) if stop.signaled() && e == "Подключение отменено." => {
                    Event::Stopped
                }
                Err(e) => Event::Failed(e),
            });
        });
        Ok((
            Self {
                cancel,
                worker: Some(worker),
            },
            rx,
        ))
    }
    pub fn stop(&mut self) {
        self.cancel.set();
    }
    pub fn restart(&mut self) {
        self.cancel.set();
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.cancel.set();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn supervise_local(
    req: &ConnectRequest,
    mode: Mode,
    cancel: &Signal,
    notify: impl Fn(Event),
) -> Result<()> {
    notify(Event::Progress("Подключение…"));
    let running = start_cores(req, mode, cancel, false)?;
    if mode != Mode::Local {
        notify(Event::Progress("Проверка соединения…"));
        if !check_connection(&running, req.probe_port.unwrap_or(req.port), cancel)? {
            return Ok(());
        }
    }
    let mut guard = if mode == Mode::Proxy {
        Some(ProxyGuard::start(req.port)?)
    } else {
        None
    };
    if cancel.signaled() {
        return Ok(());
    }
    notify(Event::Running);
    let mut handles = vec![cancel.handle(), raw(&running.primary)];
    if let Some(child) = &running.secondary {
        handles.push(raw(child));
    }
    if let Some(guard) = &guard {
        handles.push(raw(&guard.child));
    }
    let result = wait(&handles, INFINITE).map_err(|_| "Ошибка ожидания процессов.")?;
    if let Some(guard) = guard.as_mut() {
        guard.stop()?;
    }
    drop(running);
    if result == Some(0) {
        Ok(())
    } else {
        Err("Соединение остановилось. Повторите подключение.".into())
    }
}
struct ProxyGuard {
    child: Child,
}
impl ProxyGuard {
    fn start(port: u16) -> Result<Self> {
        let child = child_command(&app_path()?)
            .args(["--proxy-guard", &port.to_string()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|_| "Не удалось запустить защиту прокси.")?;
        let mut guard = Self { child };
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let mut available = 0;
            let out = guard.child.stdout.as_ref().ok_or("Нет канала прокси.")?;
            if unsafe {
                PeekNamedPipe(
                    raw(out),
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut available,
                    std::ptr::null_mut(),
                )
            } != 0
                && available >= 6
            {
                let mut ready = [0; 6];
                guard
                    .child
                    .stdout
                    .as_mut()
                    .unwrap()
                    .read_exact(&mut ready)
                    .map_err(|_| "Нет ответа настройки прокси.")?;
                if &ready == b"READY\n" {
                    return Ok(guard);
                }
                return Err("Windows не удалось включить прокси.".into());
            }
            if guard.child.try_wait().ok().flatten().is_some() || Instant::now() >= deadline {
                return Err("Windows не удалось включить прокси.".into());
            }
            thread::sleep(Duration::from_millis(30));
        }
    }
    fn stop(&mut self) -> Result<()> {
        self.child.stdin.take();
        if wait(&[raw(&self.child)], 8000)
            .map_err(|_| "Ошибка восстановления прокси.")?
            .is_none()
        {
            terminate(&mut self.child);
        }
        let success = self.child.wait().is_ok_and(|status| status.success());
        crate::system_proxy::recover_stale()?;
        if success {
            Ok(())
        } else {
            Err(
                "Не удалось штатно завершить восстановление прокси; проверьте сетевые настройки."
                    .into(),
            )
        }
    }
}
impl Drop for ProxyGuard {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
