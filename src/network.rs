//! Named, interface-bound exits. A missing exit never falls back to the VPN.
use crate::Result;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    io::Read,
    net::IpAddr,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "source", content = "servers", rename_all = "snake_case")]
pub enum Dns {
    #[default]
    Interface,
    Manual(Vec<IpAddr>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Connection {
    pub id: u64,
    pub name: String,
    pub interface: String,
    pub dns: Dns,
}

#[derive(Clone, Debug, Default)]
pub struct Interface {
    pub name: String,
    pub index: u32,
    pub up: bool,
    pub dns: Vec<IpAddr>,
}

pub fn validate_interface(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() >= libc::IFNAMSIZ
        || name == "lo"
        || name == "eivro0"
        || name == "velum0"
        || name.starts_with('-')
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
    {
        return Err("Выберите внешний сетевой интерфейс, например tun0 или wg0.".into());
    }
    Ok(())
}

pub fn validate(connections: &[Connection]) -> Result<()> {
    if connections.len() > 16 {
        return Err("Максимум 16 сетевых выходов.".into());
    }
    let mut ids = HashSet::new();
    let mut names = HashSet::new();
    for connection in connections {
        if connection.id == 0 || !ids.insert(connection.id) {
            return Err("Некорректный идентификатор сетевого выхода.".into());
        }
        if connection.name.trim().is_empty()
            || connection.name.chars().count() > 40
            || connection.name.chars().any(char::is_control)
            || !names.insert(connection.name.trim().to_lowercase())
        {
            return Err("Задайте уникальное название выхода: до 40 символов.".into());
        }
        validate_interface(&connection.interface)?;
        if let Dns::Manual(servers) = &connection.dns {
            if servers.len() != 1 {
                return Err("Укажите один IP-адрес DNS.".into());
            }
            if servers.iter().any(|ip| !valid_dns(*ip)) {
                return Err("DNS должен иметь конкретный адрес вне loopback и eivro0.".into());
            }
        }
    }
    Ok(())
}

fn valid_dns(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && ip != "172.31.250.2".parse::<IpAddr>().unwrap()
        && ip != "fdfe:5645:4c55::2".parse::<IpAddr>().unwrap()
        && !matches!(ip, IpAddr::V4(ip) if ip.is_broadcast())
        && !matches!(ip, IpAddr::V6(ip) if ip.is_unicast_link_local())
}

impl Connection {
    pub fn servers(&self, interfaces: &[Interface]) -> Option<Vec<IpAddr>> {
        let link = interfaces
            .iter()
            .find(|link| link.name == self.interface && link.up)?;
        let candidates = match &self.dns {
            Dns::Interface => &link.dns,
            Dns::Manual(servers) => servers,
        };
        let mut servers = Vec::new();
        for &ip in candidates {
            if valid_dns(ip) && !servers.contains(&ip) {
                servers.push(ip);
            }
        }
        (!servers.is_empty()).then_some(servers)
    }
}

/// One bounded snapshot on demand. No periodic DNS queries or persistent logs.
pub fn interfaces() -> Vec<Interface> {
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    let mut links: Vec<_> = entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name().into_string().ok()?;
            validate_interface(&name).ok()?;
            let flags = std::fs::read_to_string(entry.path().join("flags")).ok()?;
            let flags = u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).ok()?;
            let index = std::fs::read_to_string(entry.path().join("ifindex"))
                .ok()?
                .trim()
                .parse()
                .ok()?;
            Some(Interface {
                name,
                index,
                up: flags & libc::IFF_UP as u32 != 0,
                dns: Vec::new(),
            })
        })
        .collect();
    // resolvectl is a trusted system executable; interface names are never shell text.
    if let Some(program) = ["/usr/bin/resolvectl", "/bin/resolvectl"]
        .into_iter()
        .find(|path| crate::process::trusted_binary(Path::new(path)))
        && let Ok(bytes) = bounded_output(program, &["--json=short", "dns"])
    {
        apply_dns(&bytes, &mut links);
    }
    links.sort_by(|a, b| a.name.cmp(&b.name));
    links
}

pub fn apply_dns(bytes: &[u8], links: &mut [Interface]) {
    let Ok(rows) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return;
    };
    let Some(rows) = rows.as_array() else { return };
    for row in rows {
        let Some(name) = row["ifname"].as_str() else {
            continue;
        };
        let Some(link) = links.iter_mut().find(|link| link.name == name) else {
            continue;
        };
        let Some(servers) = row["servers"].as_array() else {
            continue;
        };
        for server in servers {
            // Non-default ports and TLS names need a different transport, never downgrade them.
            if server["port"]
                .as_u64()
                .is_some_and(|port| port != 0 && port != 53)
                || server["accessible"].as_bool() == Some(false)
                || server["serverName"].as_str().is_some_and(|s| !s.is_empty())
            {
                continue;
            }
            if let Some(ip) = server["addressString"]
                .as_str()
                .and_then(|s| s.parse::<IpAddr>().ok())
                && valid_dns(ip)
                && !link.dns.contains(&ip)
            {
                link.dns.push(ip);
            }
        }
    }
}

fn bounded_output(program: &str, args: &[&str]) -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    let mut child = Command::new(program)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Не удалось прочитать DNS интерфейсов.")?;
    let mut output = child.stdout.take().unwrap();
    let fd = output.as_raw_fd();
    if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
        let _ = child.kill();
        let _ = child.wait();
        return Err("Не удалось прочитать DNS интерфейсов.".into());
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    let result = (|| {
        let mut data = Vec::new();
        loop {
            let mut buf = [0u8; 4096];
            match output.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => data.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return Err("Ошибка чтения DNS интерфейсов.".into()),
            }
            if data.len() > 128 * 1024 || Instant::now() >= deadline {
                return Err("Не удалось получить DNS интерфейсов вовремя.".into());
            }
            let mut poll = crate::process::pollfd(fd, libc::POLLIN);
            unsafe {
                libc::poll(&mut poll, 1, 30);
            }
        }
        let status = loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|_| "Ошибка чтения DNS интерфейсов.")?
            {
                break status;
            }
            if Instant::now() >= deadline {
                return Err("Не удалось получить DNS интерфейсов вовремя.".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        if status.success() {
            Ok(data)
        } else {
            Err("Системный DNS недоступен.".into())
        }
    })();
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
    result
}

/// A sleeping rtnetlink subscription. Only kernel notifications trigger a snapshot.
/// Closing the stop socket joins the worker; no periodic timer or probe is needed.
pub struct Monitor {
    stop: Option<std::os::unix::net::UnixStream>,
    worker: Option<std::thread::JoinHandle<()>>,
    pub events: std::sync::mpsc::Receiver<()>,
}
impl Monitor {
    pub fn start(wake: std::sync::Arc<dyn Fn() + Send + Sync>) -> std::io::Result<Self> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        address.nl_groups =
            (libc::RTMGRP_LINK | libc::RTMGRP_IPV4_IFADDR | libc::RTMGRP_IPV6_IFADDR) as u32;
        if unsafe {
            libc::bind(
                fd,
                (&address as *const libc::sockaddr_nl).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let (stop, stopped) = std::os::unix::net::UnixStream::pair()?;
        let (tx, events) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            loop {
                let mut fds = [
                    crate::process::pollfd(socket.as_raw_fd(), libc::POLLIN),
                    crate::process::pollfd(stopped.as_raw_fd(), libc::POLLIN),
                ];
                if crate::process::poll(&mut fds).is_err() || fds[1].revents != 0 {
                    break;
                }
                if fds[0].revents & (libc::POLLHUP | libc::POLLNVAL) != 0 {
                    break;
                }
                let mut buf = [0u8; 8192];
                // Packet contents are not interpreted as configuration. Overflow also
                // requests a fresh snapshot, so dropped notifications cannot leave it stale.
                let n = unsafe {
                    libc::recv(
                        socket.as_raw_fd(),
                        buf.as_mut_ptr().cast(),
                        buf.len(),
                        libc::MSG_DONTWAIT,
                    )
                };
                if (n > 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOBUFS))
                    && tx.try_send(()).is_ok()
                {
                    wake();
                }
            }
        });
        Ok(Self {
            stop: Some(stop),
            worker: Some(worker),
            events,
        })
    }
}
impl Drop for Monitor {
    fn drop(&mut self) {
        self.stop.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
