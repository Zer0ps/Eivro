//! A separate nftables table, held across reconnects. Never flush other rules.
use crate::Result;
use std::{
    io::{Read, Write},
    os::fd::AsRawFd,
    path::Path,
    process::{Command, Stdio},
};
pub const MARK: u32 = 0x56454c55;
const TABLE: &str = "velum_guard";
const OWNER: &str = "Velum connection guard v1";
pub struct Guard {
    active: bool,
}
#[derive(Default)]
pub struct SystemBackend {
    guard: Option<Guard>,
    dns: Option<crate::domain_dns::state::State>,
    dns_active: bool,
    gateways: crate::domain_dns::gateways::Gateways,
}
impl crate::tun::Backend for SystemBackend {
    fn preflight(&self, req: &crate::config::ConnectRequest) -> Result<()> {
        crate::config::generate(req, crate::config::Mode::Tun)?;
        crate::domain_dns::check_ranges()
    }
    fn start(&mut self, req: &crate::config::ConnectRequest) -> Result<crate::tun::Running> {
        crate::config::generate(req, crate::config::Mode::Tun)?;
        crate::process::tun_preflight()?;
        crate::domain_dns::check_ranges()?;
        let core = Path::new(crate::process::INSTALLED_CORE);
        crate::process::version_check(core)?;
        let mut config = crate::config::generate_with_network(
            req,
            crate::config::Mode::Tun,
            &crate::network::interfaces(),
        )?;
        crate::domain_dns::configure(&mut config, req)?;
        self.gateways.configure(&mut config, req)?;
        if self.dns.is_none() {
            self.dns = Some(crate::domain_dns::state::State::open()?);
        }
        let dns = self.dns.as_ref().unwrap();
        dns.validate()?;
        let fd = dns.file.as_raw_fd();
        config["experimental"]["cache_file"] = serde_json::json!({
            "enabled":true,"path":format!("/proc/self/fd/{fd}"),
            "store_fakeip":true,"store_dns":false
        });
        if req.kill_switch {
            if self.guard.is_none() {
                self.guard = Some(Guard::arm()?);
            }
        } else if let Some(mut guard) = self.guard.take() {
            guard.release()?;
        }
        // Resolve the VPN endpoint before the TUN can intercept system DNS.
        // Keep the hostname in the outbound so TLS, WS Host and gRPC authority
        // retain their original values; only its bootstrap answer is pinned.
        let parsed = crate::import::parse_uri(&req.uri)?;
        if parsed.engine == crate::import::EngineKind::SingBox
            && parsed.host.parse::<std::net::IpAddr>().is_err()
        {
            let addresses = if req.kill_switch {
                vec![resolve(&parsed.host)?]
            } else {
                crate::domain_dns::gateways::resolve_transport(
                    &parsed.host,
                    std::time::Instant::now() + std::time::Duration::from_secs(10),
                    None,
                )
                .map_err(|_| "Не удалось получить реальный IP VPN-сервера.")?
            };
            let mut hosts = serde_json::Map::new();
            hosts.insert(parsed.host, serde_json::json!(addresses));
            config["dns"]["servers"][0] = serde_json::json!({
                "type":"hosts","tag":"bootstrap","predefined":hosts
            });
        }
        let mut secondary = if req.kill_switch {
            crate::process::protected_xray(req)?
        } else {
            None
        };
        let started = crate::process::spawn_configuration_with_state(
            core,
            &config,
            Some((fd, crate::domain_dns::state::MAX_BYTES)),
        )
        .and_then(|mut primary| {
            self.dns_active = true;
            if let Err(error) = crate::process::ready(&mut primary, req.port)
                .and_then(|_| dns.initialized())
                .and_then(|_| crate::domain_dns::flush_system_cache())
            {
                crate::process::terminate(&mut primary);
                return Err(error);
            }
            Ok(primary)
        });
        match started {
            Ok(primary) => Ok(crate::tun::Running { primary, secondary }),
            Err(e) => {
                if let Some(child) = &mut secondary {
                    crate::process::terminate(child);
                }
                Err(e)
            }
        }
    }
    fn stop(&mut self, preserve: bool, preserve_dns: bool) -> Result<()> {
        if !preserve && let Some(mut guard) = self.guard.take() {
            guard.release()?;
        }
        if !preserve_dns && self.dns_active {
            crate::domain_dns::flush_system_cache()?;
            self.dns_active = false;
        }
        if !preserve_dns {
            self.gateways = Default::default();
        }
        Ok(())
    }
    fn retire(&mut self) -> Result<()> {
        if self.dns.is_none() {
            self.dns = crate::domain_dns::state::State::open_existing()?;
            if self.dns.is_some() {
                crate::domain_dns::flush_system_cache()?;
            }
        }
        if let Some(dns) = self.dns.as_mut() {
            let core = Path::new(crate::process::INSTALLED_CORE);
            crate::process::version_check(core)?;
            dns.retire(core)?;
        }
        Ok(())
    }
}
impl Drop for SystemBackend {
    fn drop(&mut self) {
        if self.dns_active {
            let _ = crate::domain_dns::flush_system_cache();
        }
    }
}
impl Guard {
    pub fn arm() -> Result<Self> {
        let exists = owned_table()?;
        let mut script = String::new();
        if exists {
            script.push_str("delete table inet velum_guard\n");
        }
        script.push_str(&ruleset());
        apply(&script)?;
        Ok(Self { active: true })
    }
    pub fn release(&mut self) -> Result<()> {
        if self.active {
            Self::clear_stale()?;
            self.active = false;
        }
        Ok(())
    }
    pub fn clear_stale() -> Result<()> {
        if owned_table()? {
            apply("delete table inet velum_guard\n")?;
        }
        Ok(())
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.release();
    }
}
pub fn ruleset() -> String {
    format!(
        r#"table inet {TABLE} {{
 comment "{OWNER}"
 chain output {{
  type filter hook output priority -150; policy drop;
  oifname "lo" accept
  oifname "eivro0" accept
  meta mark {MARK} accept
  meta nfproto ipv4 udp sport 68 udp dport 67 accept
  meta nfproto ipv6 ip6 daddr ff02::1:2 udp sport 546 udp dport 547 accept
  meta nfproto ipv6 icmpv6 type {{ nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert }} ip6 hoplimit 255 accept
 }}
 chain forward {{
  type filter hook forward priority -150; policy drop;
  oifname "eivro0" accept
  iifname "eivro0" accept
 }}
}}
"#
    )
}
fn command() -> Result<Command> {
    let path = ["/usr/bin/nft", "/usr/sbin/nft"]
        .into_iter()
        .map(Path::new)
        .find(|p| {
            #[cfg(not(test))]
            {
                crate::process::trusted_binary(p)
            }
            #[cfg(test)]
            {
                p.is_file()
            }
        })
        .ok_or("Для защиты TUN нужен системный nftables.")?;
    let mut cmd = Command::new(path);
    cmd.env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .stderr(Stdio::null());
    Ok(cmd)
}
fn owned_table() -> Result<bool> {
    let out = command()?
        .args(["-j", "list", "tables"])
        .output()
        .map_err(|_| "Не удалось проверить защиту TUN.")?;
    if !out.status.success() {
        return Err("nftables недоступен; защита TUN не включена.".into());
    }
    let value: serde_json::Value =
        serde_json::from_slice(&out.stdout).map_err(|_| "Неверный ответ nftables.")?;
    let exists = value["nftables"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|x| x["table"]["family"] == "inet" && x["table"]["name"] == TABLE)
    });
    if exists {
        let out = command()?
            .args(["-j", "list", "table", "inet", TABLE])
            .output()
            .map_err(|_| "Не удалось проверить владельца правил.")?;
        let value: serde_json::Value = serde_json::from_slice(&out.stdout)
            .map_err(|_| "Не удалось проверить владельца правил.")?;
        if !out.status.success()
            || !value["nftables"]
                .as_array()
                .is_some_and(|items| items.iter().any(|x| x["table"]["comment"] == OWNER))
        {
            return Err("Таблица velum_guard занята чужими правилами; они сохранены.".into());
        }
    }
    Ok(exists)
}
fn apply(script: &str) -> Result<()> {
    let mut child = command()?
        .args(["-f", "/dev/stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|_| "Не удалось запустить nftables.")?;
    let written = child
        .stdin
        .take()
        .ok_or("Нет канала nftables.")?
        .write_all(script.as_bytes());
    let status = child.wait().map_err(|_| "Ошибка nftables.")?;
    if written.is_err() || !status.success() {
        return Err("Не удалось применить защиту TUN; проверьте nftables.".into());
    }
    Ok(())
}

/// Resolve through a short-lived, marked local core. No system DNS exception
/// is opened in the firewall, including while reconnecting without a TUN.
pub fn resolve(host: &str) -> Result<std::net::IpAddr> {
    if let Ok(ip) = host.parse() {
        return Ok(ip);
    }
    let port = crate::process::free_port(&[])?;
    let config = serde_json::json!({
        "log":{"disabled":true},
        "inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":port}],
        "outbounds":[{"type":"direct","tag":"direct","routing_mark":MARK}],
        "route":{"final":"direct"}
    });
    let mut child =
        crate::process::spawn_configuration(Path::new(crate::process::INSTALLED_CORE), &config)?;
    let result = (|| {
        crate::process::ready(&mut child, port)?;
        // The certificate includes 1.1.1.1; no DNS bootstrap is needed.
        let proxy =
            ureq::Proxy::new(format!("http://127.0.0.1:{port}")).map_err(|_| "Нет DNS-канала.")?;
        let agent = ureq::AgentBuilder::new()
            .proxy(proxy)
            .redirects(0)
            .timeout(std::time::Duration::from_secs(6))
            .build();
        let response = agent
            .get("https://1.1.1.1/dns-query")
            .query("name", host)
            .query("type", "A")
            .set("accept", "application/dns-json")
            .call()
            .map_err(|_| "Не удалось разрешить сервер через защищённый DNS-канал.")?;
        let mut data = Vec::new();
        response
            .into_reader()
            .take(65537)
            .read_to_end(&mut data)
            .map_err(|_| "Ошибка ответа DNS.")?;
        if data.len() > 65536 {
            return Err("Слишком большой ответ DNS.".into());
        }
        let value: serde_json::Value =
            serde_json::from_slice(&data).map_err(|_| "Неверный ответ DNS.")?;
        if value["Status"] != 0 {
            return Err("DNS не вернул адрес сервера.".into());
        }
        value["Answer"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|a| a["type"] == 1)
            .find_map(|a| {
                a["data"]
                    .as_str()?
                    .parse::<std::net::Ipv4Addr>()
                    .ok()
                    .map(std::net::IpAddr::V4)
            })
            .ok_or("У сервера нет IPv4-адреса для защищённого TUN.".into())
    })();
    crate::process::terminate(&mut child);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::UdpSocket, os::fd::AsRawFd};
    fn run(args: &[&str]) {
        let result = Command::new(args[0]).args(&args[1..]).output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    #[test]
    fn kernel_guard_isolated_network_namespace() {
        if std::env::var_os("EIVRO_GUARD_CHILD").is_none() {
            let output = Command::new("unshare")
                .args(["--user", "--map-root-user", "--net", "--mount"])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "guard::tests::kernel_guard_isolated_network_namespace",
                    "--nocapture",
                ])
                .env("EIVRO_GUARD_CHILD", "1")
                .env(
                    "EIVRO_PARENT_NETNS",
                    std::fs::read_link("/proc/self/ns/net").unwrap(),
                )
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        // Assert isolation before any mutation. No TUN, D-Bus or host DNS is used.
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::path::PathBuf::from(std::env::var_os("EIVRO_PARENT_NETNS").unwrap())
        );
        run(&["ip", "link", "set", "lo", "up"]);
        run(&["ip", "link", "add", "guard-test0", "type", "dummy"]);
        run(&["ip", "addr", "add", "192.0.2.1/24", "dev", "guard-test0"]);
        run(&["ip", "link", "set", "guard-test0", "up"]);
        run(&[
            "ip",
            "neigh",
            "add",
            "192.0.2.2",
            "lladdr",
            "02:00:00:00:00:02",
            "dev",
            "guard-test0",
            "nud",
            "permanent",
        ]);
        apply("table inet other_application { comment \"keep me\"; }\n").unwrap();
        let send = |mark: u32, port: u16| {
            let socket = UdpSocket::bind("192.0.2.1:0").unwrap();
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        socket.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_MARK,
                        (&mark as *const u32).cast(),
                        4,
                    )
                },
                0
            );
            socket.send_to(b"synthetic", ("192.0.2.2", port)).is_ok()
        };
        assert!(send(0, 443));
        let mut guard = Guard::arm().unwrap();
        assert!(!send(0, 443), "unmarked application traffic escaped");
        assert!(!send(0, 53), "direct DNS escaped");
        assert!(send(MARK, 443), "marked core traffic was blocked");
        // Removing a core/TUN does not remove this separate table.
        assert!(owned_table().unwrap());
        assert!(!send(0, 443));
        guard.release().unwrap();
        assert!(send(0, 443));
        run(&["nft", "list", "table", "inet", "other_application"]);
        apply("table inet velum_guard { comment \"belongs to someone else\"; }\n").unwrap();
        assert!(Guard::arm().is_err());
        run(&["nft", "list", "table", "inet", "velum_guard"]);
    }
}
