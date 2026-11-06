//! Another VPN's transport must not depend on our TUN or its FakeIP lifetime.
use crate::{Result, config::ConnectRequest};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    net::IpAddr,
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};

pub fn validate(host: &str) -> Result<()> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        if real_address(ip) {
            return Ok(());
        }
    } else if matches!(
        crate::routing::Rule::parse(host),
        Ok(crate::routing::Rule::Exact(_))
    ) {
        return Ok(());
    }
    Err("Сервер VPN: точный домен или реальный IP, без URL, порта и маски.".into())
}

pub fn canonical(host: &str) -> Result<String> {
    let host = host.trim();
    validate(host)?;
    Ok(match host.parse::<IpAddr>() {
        Ok(ip) => ip.to_string(),
        Err(_) => crate::routing::Rule::parse(host)?.canonical(),
    })
}

pub(crate) fn synthetic(ip: IpAddr) -> bool {
    if let IpAddr::V6(ip) = ip
        && let Some(mapped) = ip.to_ipv4_mapped()
    {
        return synthetic(IpAddr::V4(mapped));
    }
    [super::IPV4_RANGE, "2001:2::/48"]
        .iter()
        .any(|range| range.parse::<ipnet::IpNet>().unwrap().contains(&ip))
}

fn real_address(ip: IpAddr) -> bool {
    !synthetic(ip)
        && !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && !matches!(ip, IpAddr::V4(v) if v.is_broadcast() || v.is_link_local())
        && !matches!(ip, IpAddr::V6(v) if v.is_unicast_link_local() || v.to_ipv4_mapped().is_some_and(|v| !real_address(IpAddr::V4(v))))
        && ip != "172.31.250.1".parse::<IpAddr>().unwrap()
        && ip != "172.31.250.2".parse::<IpAddr>().unwrap()
        && ip != "fdfe:5645:4c55::1".parse::<IpAddr>().unwrap()
        && ip != "fdfe:5645:4c55::2".parse::<IpAddr>().unwrap()
}

/// Keep transport addresses stable across policy/core restarts, so an already
/// connected external VPN does not lose its kernel bypass after a DNS change.
/// Explicit disconnect releases these small, bounded pins; data DNS is separate.
#[derive(Default)]
pub(crate) struct Gateways(BTreeMap<String, Vec<IpAddr>>);

impl Gateways {
    pub fn configure(&mut self, config: &mut Value, request: &ConnectRequest) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut next = BTreeMap::new();
        for connection in &request.connections {
            let Some(host) = connection.gateway.as_deref() else {
                continue;
            };
            let host = canonical(host)?;
            if next.contains_key(&host) {
                continue;
            }
            let addresses = match self.0.get(&host) {
                Some(addresses) => addresses.clone(),
                None => resolve(&host, deadline).map_err(|_| format!(
                    "Не удалось получить реальный IP сервера VPN для выхода «{}». Проверьте адрес и системный DNS.", connection.name
                ))?,
            };
            next.insert(host, addresses);
        }
        apply(config, &next);
        self.0 = next;
        Ok(())
    }
}

fn resolve(host: &str, deadline: Instant) -> Result<Vec<IpAddr>> {
    let addresses = resolve_transport(host, deadline, None)?;
    if !addresses.iter().all(|ip| real_address(*ip)) {
        return Err("Недопустимый адрес сервера VPN.".into());
    }
    Ok(addresses)
}

/// Transport bootstrap is separate from data DNS. A previous FakeIP must not
/// become the WAN destination of Xray or of a native sing-box outbound either.
pub(crate) fn resolve_transport(
    host: &str,
    deadline: Instant,
    watch: Option<&UnixStream>,
) -> Result<Vec<IpAddr>> {
    let addresses = crate::resolver::resolve_host(host, 443, deadline, watch)
        .map_err(|_| "DNS сервера VPN недоступен.")?
        .into_iter()
        .map(|address| address.ip())
        .collect::<Vec<_>>();
    if !addresses.iter().any(|ip| synthetic(*ip)) {
        return Ok(addresses);
    }
    // A previous TUN session may have left FakeIP answers in resolved's cache.
    // Bypass only that cache: never flush unrelated clients or use public DNS
    // as a fallback for a potentially private corporate hostname.
    let program = ["/usr/bin/resolvectl", "/bin/resolvectl"]
        .into_iter()
        .find(|p| crate::process::trusted_binary(std::path::Path::new(p)))
        .ok_or("DNS сохранил виртуальный адрес сервера VPN.")?;
    let mut real = Vec::new();
    for rr in ["--type=A", "--type=AAAA"] {
        if Instant::now() >= deadline {
            return Err("Истекло время DNS сервера VPN.".into());
        }
        if let Ok(data) = crate::network::bounded_output(
            program,
            &[
                "--cache=no",
                "--search=no",
                "--json=short",
                rr,
                "query",
                host,
            ],
        ) {
            for record in serde_json::Deserializer::from_slice(&data).into_iter::<Value>() {
                let record = record.map_err(|_| "Некорректный ответ системного DNS.")?;
                if let Some(ip) = record_address(&record) {
                    if synthetic(ip) {
                        return Err("DNS вернул виртуальный адрес сервера VPN.".into());
                    }
                    if !real.contains(&ip) {
                        real.push(ip);
                    }
                    if real.len() > 32 {
                        return Err("Слишком много адресов сервера VPN.".into());
                    }
                }
            }
        }
    }
    if real.is_empty() {
        return Err("У сервера VPN нет реального IP.".into());
    }
    Ok(real)
}

fn record_address(record: &Value) -> Option<IpAddr> {
    let bytes: Vec<u8> = record["address"]
        .as_array()?
        .iter()
        .map(|v| u8::try_from(v.as_u64()?).ok())
        .collect::<Option<_>>()?;
    match (record["key"]["type"].as_u64()?, bytes.len()) {
        (1, 4) => Some(IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?)),
        (28, 16) => Some(IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?)),
        _ => None,
    }
}

fn apply(config: &mut Value, gateways: &BTreeMap<String, Vec<IpAddr>>) {
    if gateways.is_empty() {
        return;
    }
    let mut hosts = BTreeMap::new();
    let mut networks = Vec::new();
    for (host, addresses) in gateways {
        if host.parse::<IpAddr>().is_err() {
            hosts.insert(host, addresses);
        }
        for ip in addresses {
            let network = ipnet::IpNet::from(*ip).to_string();
            if !networks.contains(&network) {
                networks.push(network);
            }
        }
    }
    for inbound in config["inbounds"].as_array_mut().unwrap() {
        if inbound["type"] == "tun" {
            inbound["route_exclude_address"] = json!(networks);
        }
    }
    config["dns"]["servers"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"hosts","tag":"vpn-gateways","predefined":hosts}));
    let domains: Vec<_> = hosts.keys().copied().collect();
    if !domains.is_empty() {
        config["dns"]["rules"].as_array_mut().unwrap().insert(
            0,
            json!({"domain":domains,"action":"route","server":"vpn-gateways"}),
        );
    }
    config["outbounds"].as_array_mut().unwrap().push(json!({
        "type":"direct","tag":"vpn-gateway","domain_resolver":"vpn-gateways"
    }));
    let rules = config["route"]["rules"].as_array_mut().unwrap();
    let position = rules
        .iter()
        .position(|r| r["action"] == "hijack-dns")
        .unwrap()
        + 1;
    let mut matchers = vec![json!({"ip_cidr":networks})];
    if !domains.is_empty() {
        matchers.push(json!({"domain":domains}));
    }
    rules.insert(
        position,
        json!({"type":"logical","mode":"or", "rules":matchers,
            "action":"route","outbound":"vpn-gateway"}),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gateway_is_one_exact_real_host() {
        assert_eq!(canonical(" VPN.Example.test ").unwrap(), "vpn.example.test");
        for host in ["10.0.0.1", "2001:db8::1", "vpn.example.test"] {
            assert!(validate(host).is_ok());
        }
        for host in [
            "",
            "*.example.test",
            "https://vpn.test/",
            "198.18.1.38",
            "::ffff:198.18.1.38",
            "2001:2::1",
            "127.0.0.1",
            "0.0.0.0",
            "10.0.0.0/8",
            "vpn.test:443",
        ] {
            assert!(validate(host).is_err(), "{host}");
        }
    }
    #[test]
    fn resolved_records_do_not_treat_cname_or_text_as_an_address() {
        assert_eq!(
            record_address(&json!({"key":{"type":1},"address":[203,0,113,5]})),
            Some("203.0.113.5".parse().unwrap())
        );
        assert!(record_address(&json!({"key":{"type":5},"name":"198.18.1.1"})).is_none());
        assert!(record_address(&json!({"key":{"type":1},"address":[203,0,113,999]})).is_none());
    }

    #[test]
    fn host_and_ip_gateways_pass_the_core_and_only_exempt_exact_endpoints() {
        use std::io::Write;
        for host in ["gateway.test", "203.0.113.5"] {
            let request: ConnectRequest = serde_json::from_value(json!({
                "uri":"ss://chacha20-ietf-poly1305:synthetic@127.0.0.1:443",
                "port":12080,"bypass":[],"connections":[]
            }))
            .unwrap();
            let mut config = crate::config::generate(&request, crate::config::Mode::Tun).unwrap();
            super::super::configure(&mut config, &request).unwrap();
            apply(
                &mut config,
                &BTreeMap::from([(
                    host.into(),
                    vec![
                        "203.0.113.5".parse().unwrap(),
                        "2001:db8::5".parse().unwrap(),
                    ],
                )]),
            );
            let inbound = config["inbounds"]
                .as_array()
                .unwrap()
                .iter()
                .find(|i| i["type"] == "tun")
                .unwrap();
            assert_eq!(
                inbound["route_exclude_address"],
                json!(["203.0.113.5/32", "2001:db8::5/128"])
            );
            if host == "gateway.test" {
                assert_eq!(config["dns"]["rules"][0]["domain"], json!(["gateway.test"]));
                assert_eq!(config["dns"]["rules"][1]["server"], "domain-identity");
            }
            let mut child = std::process::Command::new(crate::process::core_path().unwrap())
                .args(["check", "-c", "/dev/stdin"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(config.to_string().as_bytes())
                .unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
