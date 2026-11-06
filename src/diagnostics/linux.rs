use super::{Report, Request, Status, analysis, probe};
use crate::{Result, network::Interface};
use serde_json::Value;
use std::{
    collections::hash_map::DefaultHasher,
    fs,
    hash::{Hash, Hasher},
    io::Read,
    net::IpAddr,
    os::{fd::AsRawFd, unix::process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub(super) struct Context {
    pub cancel: Arc<AtomicBool>,
    pub deadline: Instant,
}
pub(super) struct Output {
    pub code: Option<i32>,
    pub text: String,
}
impl Context {
    fn new(cancel: Arc<AtomicBool>) -> Self {
        Self {
            cancel,
            deadline: Instant::now() + Duration::from_secs(45),
        }
    }
    pub fn stopped(&self) -> bool {
        self.cancel.load(Ordering::Relaxed) || Instant::now() >= self.deadline
    }
    pub fn system(&self, program: &str, args: &[&str]) -> Result<String> {
        let output = self.command(
            &system_binary(program)?,
            args,
            Duration::from_secs(2),
            program == "gsettings",
        )?;
        if output.code != Some(0) {
            return Err("Системная команда недоступна или отклонила запрос.".into());
        }
        Ok(output.text)
    }
    pub fn command(
        &self,
        program: &Path,
        args: &[&str],
        timeout: Duration,
        session: bool,
    ) -> Result<Output> {
        if self.stopped() {
            return Err("Проверка остановлена.".into());
        }
        let mut command = Command::new(program);
        command
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LC_ALL", "C");
        if session {
            for name in [
                "DBUS_SESSION_BUS_ADDRESS",
                "XDG_RUNTIME_DIR",
                "XDG_CONFIG_HOME",
                "HOME",
            ] {
                if let Some(value) = std::env::var_os(name) {
                    command.env(name, value);
                }
            }
        }
        command
            .process_group(0)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let parent = unsafe { libc::getpid() };
        // A killed GUI cannot leave a stuck NSS or D-Bus reader behind. These
        // commands are read-only; repairs deliberately use a separate lifecycle.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent {
                    return Err(std::io::Error::from_raw_os_error(libc::ECANCELED));
                }
                Ok(())
            });
        }
        let mut child = command
            .spawn()
            .map_err(|_| "Не удалось запустить проверку.")?;
        let mut stdout = child.stdout.take().ok_or("Нет вывода проверки.")?;
        let deadline = self.deadline.min(Instant::now() + timeout);
        let result = (|| {
            if unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
                return Err("Не удалось ограничить проверку.".into());
            }
            let mut bytes = Vec::new();
            loop {
                if self.stopped() || Instant::now() >= deadline {
                    return Err("Проверка отменена или истекло время ожидания.".into());
                }
                let mut buffer = [0; 4096];
                match stdout.read(&mut buffer) {
                    Ok(0) => {
                        if let Some(status) = child
                            .try_wait()
                            .map_err(|_| "Не удалось завершить проверку.")?
                        {
                            return Ok(Output {
                                code: status.code(),
                                text: String::from_utf8(bytes)
                                    .map_err(|_| "Неверный формат вывода.")?,
                            });
                        }
                    }
                    Ok(n) => {
                        bytes.extend_from_slice(&buffer[..n]);
                        if bytes.len() > 256 * 1024 {
                            return Err("Слишком большой ответ проверки.".into());
                        }
                        continue;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => return Err("Не удалось прочитать ответ проверки.".into()),
                }
                std::thread::sleep(Duration::from_millis(15));
            }
        })();
        // Kill only this check's process group, and reap on every exit path.
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
        let _ = child.wait();
        result
    }
}

pub(super) fn system_binary(name: &str) -> Result<PathBuf> {
    for dir in ["/usr/bin", "/usr/sbin", "/bin", "/sbin"] {
        if let Ok(path) = Path::new(dir).join(name).canonicalize()
            && crate::process::trusted_binary(&path)
        {
            return Ok(path);
        }
    }
    Err(format!("Системная утилита {name} недоступна."))
}

pub(super) struct Link {
    pub interface: Interface,
    pub physical: bool,
    pub carrier: bool,
}
fn hardware_uplink(path: &Path, depth: usize) -> bool {
    if path.join("device").exists() {
        return true;
    }
    if depth >= 4 || !(path.join("bridge").exists() || path.join("bonding").exists()) {
        return false;
    }
    // Bridges and bonds are legitimate WAN uplinks when backed by real hardware.
    // A VPN TAP, veth-only bridge, or arbitrary virtual device does not qualify.
    fs::read_dir(path)
        .ok()
        .into_iter()
        .flatten()
        .take(128)
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("lower_"))
        })
        .any(|entry| hardware_uplink(&entry.path(), depth + 1))
}
pub(super) fn links() -> Result<Vec<Link>> {
    let mut links = Vec::new();
    for entry in fs::read_dir("/sys/class/net").map_err(|_| "Нет сведений об интерфейсах.")?
    {
        let entry = entry.map_err(|_| "Не удалось прочитать интерфейс.")?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name == "lo" {
            continue;
        }
        let read = |file: &str| {
            fs::read_to_string(entry.path().join(file))
                .unwrap_or_default()
                .trim()
                .to_owned()
        };
        let flags = u32::from_str_radix(read("flags").trim_start_matches("0x"), 16).unwrap_or(0);
        links.push(Link {
            interface: Interface {
                name,
                index: read("ifindex").parse().unwrap_or(0),
                up: flags & libc::IFF_UP as u32 != 0,
                dns: Vec::new(),
            },
            physical: hardware_uplink(&entry.path(), 0),
            carrier: read("carrier") == "1",
        });
    }
    links.sort_by(|a, b| a.interface.name.cmp(&b.interface.name));
    Ok(links)
}

pub(super) struct Snapshot {
    pub links: Vec<Link>,
    pub routes4: Result<Value>,
    pub routes6: Result<Value>,
    pub rules4: Result<Value>,
    pub rules6: Result<Value>,
    pub dns: Result<Value>,
    pub domains: Result<Value>,
    pub nm_dns: Vec<(String, Result<Vec<IpAddr>>)>,
    pub resolv: Result<String>,
    pub resolv_link: Option<PathBuf>,
    pub dangling_resolv: bool,
}
impl Snapshot {
    fn capture(ctx: &Context) -> Result<Self> {
        let json = |program, args: &[&str]| -> Result<Value> {
            let raw = ctx.system(program, args)?;
            let value: Value =
                serde_json::from_str(&raw).map_err(|_| "Неизвестный формат системных сведений.")?;
            if !value.is_array() {
                return Err("Ожидался список параметров.".into());
            }
            Ok(value)
        };
        let links = links()?;
        let nm_dns = links
            .iter()
            .filter(|link| link.physical && link.interface.up && link.carrier)
            .take(8)
            .map(|link| {
                (
                    link.interface.name.clone(),
                    nm_dns(ctx, &link.interface.name),
                )
            })
            .collect();
        Ok(Self {
            links,
            nm_dns,
            routes4: json("ip", &["-j", "-4", "route", "show", "table", "all"]),
            routes6: json("ip", &["-j", "-6", "route", "show", "table", "all"]),
            rules4: json("ip", &["-j", "-4", "rule", "show"]),
            rules6: json("ip", &["-j", "-6", "rule", "show"]),
            dns: json("resolvectl", &["--json=short", "dns"]),
            domains: json("resolvectl", &["--json=short", "domain"]),
            resolv: bounded_file(Path::new("/etc/resolv.conf")),
            resolv_link: fs::read_link("/etc/resolv.conf").ok(),
            dangling_resolv: fs::symlink_metadata("/etc/resolv.conf")
                .is_ok_and(|m| m.file_type().is_symlink())
                && !Path::new("/etc/resolv.conf").exists(),
        })
    }
    fn fingerprint(&self) -> Result<String> {
        fn stable(value: &Value) -> Value {
            match value {
                Value::Object(map) => Value::Object(
                    map.iter()
                        .filter(|(k, _)| {
                            ![
                                "expires",
                                "used",
                                "lastuse",
                                "age",
                                "cache",
                                "valid_life_time",
                                "preferred_life_time",
                                "accessible",
                            ]
                            .contains(&k.as_str())
                        })
                        .map(|(k, v)| (k.clone(), stable(v)))
                        .collect(),
                ),
                Value::Array(rows) => Value::Array(rows.iter().map(stable).collect()),
                _ => value.clone(),
            }
        }
        let mut hash = DefaultHasher::new();
        for (value, unordered) in [
            (&self.routes4, false),
            (&self.routes6, false),
            (&self.rules4, false),
            (&self.rules6, false),
            (&self.dns, true),
            (&self.domains, true),
        ] {
            // DNS link rows are unordered; rule order at equal priorities is not.
            let mut normalized = stable(value.as_ref().map_err(Clone::clone)?);
            if unordered && let Some(rows) = normalized.as_array_mut() {
                rows.sort_by_key(Value::to_string);
            }
            normalized.to_string().hash(&mut hash);
        }
        for link in &self.links {
            (
                &link.interface.name,
                link.interface.index,
                link.interface.up,
                link.physical,
                link.carrier,
            )
                .hash(&mut hash);
        }
        for (interface, candidates) in &self.nm_dns {
            interface.hash(&mut hash);
            // Missing NM is a stable unknown marker; valid source DNS retains
            // its priority and binds the repair preview to this exact source.
            candidates.as_ref().ok().hash(&mut hash);
        }
        self.resolv.as_ref().map_err(Clone::clone)?.hash(&mut hash);
        self.resolv_link.hash(&mut hash);
        Ok(format!("{:016x}", hash.finish()))
    }
}
fn bounded_file(path: &Path) -> Result<String> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| "Файл недоступен.")?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| "Не удалось прочитать файл.")?;
    if bytes.len() > 65536 {
        return Err("Файл слишком большой.".into());
    }
    String::from_utf8(bytes).map_err(|_| "Неизвестный формат файла.".into())
}
pub(super) fn fingerprint() -> Result<String> {
    fingerprint_cancelled(Arc::new(AtomicBool::new(false)))
}

pub(super) fn fingerprint_cancelled(cancel: Arc<AtomicBool>) -> Result<String> {
    let ctx = Context::new(cancel);
    let snapshot = Snapshot::capture(&ctx)?;
    if ctx.stopped() {
        return Err("Проверка состояния сети отменена.".into());
    }
    snapshot.fingerprint()
}
pub(super) fn runtime_dns(interface: &str) -> Result<Vec<IpAddr>> {
    crate::network::validate_interface(interface)?;
    let raw = Context::new(Arc::new(AtomicBool::new(false)))
        .system("resolvectl", &["--json=short", "dns", interface])?;
    analysis::runtime_dns(
        &serde_json::from_str(&raw).map_err(|_| "Неизвестный формат DNS.")?,
        interface,
    )
}
pub(super) fn dns_repair_interface_allowed(interface: &str) -> Result<()> {
    crate::network::validate_interface(interface)?;
    let links = links()?;
    if links.iter().any(|link| {
        [crate::platform::TUN_NAME, "eivro0", "velum0"].contains(&link.interface.name.as_str())
    }) {
        return Err("Сначала отключите TUN Eivro и восстановите его состояние.".into());
    }
    if !links.iter().any(|link| {
        link.interface.name == interface && link.interface.up && link.physical && link.carrier
    }) {
        return Err("Нужен активный физический сетевой интерфейс.".into());
    }
    let path = Path::new("/sys/class/net").join(interface);
    if path.join("bridge").exists() || path.join("bonding").exists() {
        let raw = Context::new(Arc::new(AtomicBool::new(false)))
            .system("ip", &["-j", "-4", "route", "show", "table", "main"])?;
        let routes: Value = serde_json::from_str(&raw)
            .map_err(|_| "Неизвестный формат маршрута основного выхода.")?;
        if !routes.as_array().is_some_and(|rows| {
            rows.iter().any(|row| {
                row["dev"] == interface
                    && row["dst"] == "default"
                    && row.get("type").is_none_or(|kind| kind == "unicast")
            })
        }) {
            return Err(
                "Мост или bond должен быть подтверждённым основным физическим выходом IPv4.".into(),
            );
        }
    }
    Ok(())
}
pub(super) fn nm_dns(ctx: &Context, interface: &str) -> Result<Vec<IpAddr>> {
    crate::network::validate_interface(interface)?;
    analysis::nm_dns(&ctx.system(
        "nmcli",
        &[
            "--terse",
            "--escape",
            "no",
            "--fields",
            "GENERAL.TYPE,GENERAL.STATE,IP4.DNS",
            "device",
            "show",
            interface,
        ],
    )?)
}
pub(super) fn restore_dns_candidate(interface: &str) -> Result<Vec<IpAddr>> {
    dns_repair_interface_allowed(interface)?;
    let candidate = nm_dns(&Context::new(Arc::new(AtomicBool::new(false))), interface)?;
    if !runtime_dns(interface)?.is_empty() {
        return Err("DNS интерфейса уже настроен; замена не предлагается.".into());
    }
    dns_repair_interface_allowed(interface)?;
    Ok(candidate)
}
pub(super) fn run(request: Request, cancel: Arc<AtomicBool>, progress: impl Fn(&str)) -> Report {
    let ctx = Context::new(cancel);
    let mut report = Report::default();
    progress("Проверяем интерфейсы, маршруты и системный DNS…");
    let snapshot = match Snapshot::capture(&ctx) {
        Ok(snapshot) => snapshot,
        Err(_) => {
            report.cancelled = ctx.cancel.load(Ordering::Relaxed);
            report.add(
                "state",
                Status::Unknown,
                "Нет снимка сети",
                "Системные сведения недоступны.",
                "Повторите проверку после завершения изменений сети.",
                None,
            );
            return report;
        }
    };
    report.network_fingerprint = snapshot.fingerprint().unwrap_or_default();
    analysis::network(&snapshot, &mut report);
    progress("Сопоставляем DNS, профиль и сетевые выходы…");
    analysis::dns(&ctx, &snapshot, &request, &mut report);
    let endpoint = analysis::profile(&request, &snapshot, &mut report);
    if let Some(address) = request
        .address
        .as_deref()
        .map(str::trim)
        .filter(|address| !address.is_empty())
    {
        if !analysis::target_kernel_allowed(&request) {
            report.add("target_route", Status::Unknown, "Маршрут проблемного адреса", "При HTTP-прокси прямой маршрут ядра к сайту не описывает путь через прокси и отдельно не проверялся.", "Смотрите адресное правило профиля и HTTPS через прокси. Для сравнения прямого пути нужно отдельно разрешить прямой тест.", None);
        } else if let Ok(ip) = address.parse::<IpAddr>() {
            analysis::target_route(&ctx, &snapshot, ip, &mut report);
        } else if !request.network_tests {
            report.add(
                "target_route",
                Status::Unknown,
                "Маршрут проблемного адреса",
                "Для имени адреса нужен DNS-запрос; в локальной проверке он не выполнялся.",
                "Разрешите сетевые проверки для разрешения имени на допустимом пути.",
                None,
            );
        }
    }
    if !request.network_tests {
        if let Some(ip) = endpoint
            .as_deref()
            .and_then(|host| host.parse::<IpAddr>().ok())
        {
            if crate::domain_dns::gateways::synthetic(ip) {
                report.add(
                    "fakeip",
                    Status::Error,
                    "Транспорт VPN использует виртуальный адрес",
                    "В настройках сервера указан адрес из диапазона FakeIP.",
                    "Задайте реальный IP или точное имя сервера.",
                    Some(super::Action::OpenSettings),
                );
            } else {
                analysis::route_to(
                    &ctx,
                    ip,
                    "endpoint_route",
                    "Маршрут к серверу VPN",
                    true,
                    &mut report,
                );
            }
        } else if endpoint.is_some() {
            report.add("endpoint_route", Status::Unknown, "Маршрут к серверу VPN", "Сервер задан именем. Без разрешённых DNS-запросов его адрес и маршрут не проверяются.", "Разрешите сетевые проверки, чтобы проверить системный DNS сервера.", None);
        }
    }
    if !ctx.stopped() {
        progress("Проверяем локальный прокси и установленные компоненты…");
        super::environment::check(&ctx, &request, &mut report);
        analysis::local(&ctx, &request, &mut report);
    }
    if request.network_tests && !request.busy && !ctx.stopped() {
        progress("Проверяем DNS и HTTPS по разрешённым сетевым путям…");
        probe::run(&ctx, &request, &snapshot, endpoint.as_deref(), &mut report);
    } else {
        report.add(
            "scope",
            Status::Unknown,
            "Сетевые запросы не выполнялись",
            if request.busy {
                "Подключение меняется; активная проверка отложена."
            } else {
                "Собраны только локальные сведения. Доступность DNS, TCP и TLS не проверена."
            },
            "Разрешите сетевые проверки для проверки DNS и HTTPS.",
            None,
        );
    }
    report.cancelled = ctx.cancel.load(Ordering::Relaxed);
    if ctx.stopped() {
        report.add(
            "state",
            Status::Unknown,
            "Проверка завершена не полностью",
            "Отмена или общий лимит времени остановили оставшиеся проверки.",
            "Повторите диагностику при стабильном подключении.",
            None,
        );
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn read_only_workers_die_with_parent_and_time_out() {
        let ctx = Context::new(Arc::new(AtomicBool::new(false)));
        let output = ctx.command(Path::new("/usr/bin/python3"), &["-c", "import ctypes; n=ctypes.c_int(); assert ctypes.CDLL(None).prctl(2,ctypes.byref(n),0,0,0)==0; print(n.value)"], Duration::from_secs(2), false).unwrap();
        assert_eq!(output.text.trim(), libc::SIGKILL.to_string());
        let start = Instant::now();
        assert!(
            ctx.command(
                Path::new("/usr/bin/python3"),
                &["-c", "import time; time.sleep(30)"],
                Duration::from_millis(100),
                false
            )
            .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(2));
    }
    use serde_json::json;
    #[test]
    fn fingerprint_preserves_dns_priority_bytes_and_split_domains() {
        let mut snapshot = Snapshot {
            links: vec![],
            routes4: Ok(json!([])),
            routes6: Ok(json!([])),
            rules4: Ok(json!([])),
            rules6: Ok(json!([])),
            dns: Ok(json!([
                {"ifname":"eth0","servers":[{"address":[10,0,1,2],"accessible":true},{"address":[10,0,2,1]}]},
                {"ifname":"tun0","servers":null}
            ])),
            domains: Ok(
                json!([{"ifname":"eth0","domains":[{"domain":"corp.test","routeOnly":true}]}]),
            ),
            nm_dns: vec![(
                "eth0".into(),
                Ok(vec![
                    "192.0.2.53".parse().unwrap(),
                    "192.0.2.54".parse().unwrap(),
                ]),
            )],
            resolv: Ok("nameserver 127.0.0.53\n".into()),
            resolv_link: None,
            dangling_resolv: false,
        };
        let initial = snapshot.fingerprint().unwrap();
        snapshot
            .dns
            .as_mut()
            .unwrap()
            .as_array_mut()
            .unwrap()
            .reverse();
        assert_eq!(
            initial,
            snapshot.fingerprint().unwrap(),
            "top-level order is immaterial"
        );
        snapshot.dns.as_mut().unwrap()[1]["servers"][0]["accessible"] = json!(false);
        assert_eq!(
            initial,
            snapshot.fingerprint().unwrap(),
            "reachability is not configuration"
        );
        snapshot.dns.as_mut().unwrap()[1]["servers"]
            .as_array_mut()
            .unwrap()
            .reverse();
        assert_ne!(
            initial,
            snapshot.fingerprint().unwrap(),
            "DNS preference is configuration"
        );
        snapshot.dns.as_mut().unwrap()[1]["servers"]
            .as_array_mut()
            .unwrap()
            .reverse();
        snapshot.dns.as_mut().unwrap()[1]["servers"][0]["address"] = json!([10, 0, 2, 1]);
        assert_ne!(
            initial,
            snapshot.fingerprint().unwrap(),
            "address bytes must not be sorted"
        );
        snapshot.dns.as_mut().unwrap()[1]["servers"][0]["address"] = json!([10, 0, 1, 2]);
        snapshot.domains.as_mut().unwrap()[0]["domains"][0]["routeOnly"] = json!(false);
        assert_ne!(
            initial,
            snapshot.fingerprint().unwrap(),
            "split DNS scope changed"
        );
        snapshot.domains.as_mut().unwrap()[0]["domains"][0]["routeOnly"] = json!(true);
        assert_eq!(initial, snapshot.fingerprint().unwrap());
        snapshot.nm_dns[0].1.as_mut().unwrap()[0] = "192.0.2.55".parse().unwrap();
        assert_ne!(
            initial,
            snapshot.fingerprint().unwrap(),
            "NM source differs from preview"
        );
        snapshot.rules4 = Ok(json!([
            {"priority":100,"src":"all","table":"100"},
            {"priority":100,"src":"all","table":"200"}
        ]));
        let ordered = snapshot.fingerprint().unwrap();
        snapshot
            .rules4
            .as_mut()
            .unwrap()
            .as_array_mut()
            .unwrap()
            .reverse();
        assert_ne!(
            ordered,
            snapshot.fingerprint().unwrap(),
            "equal-priority rule order matters"
        );
        snapshot.nm_dns[0].1 = Err("NM unavailable".into());
        let unknown = snapshot.fingerprint().unwrap();
        snapshot.nm_dns[0].1 = Err("NM timed out".into());
        assert_eq!(
            unknown,
            snapshot.fingerprint().unwrap(),
            "unknown is stable"
        );
    }
}
