//! Linux TUN domain identity. Real DNS responses belong to each core session;
//! FakeIP identities must outlive a transport reconnect.
use crate::{Result, config::ConnectRequest, policy::Target, routing::Rule};
use serde_json::{Value, json};

pub(crate) mod state;

pub const IPV4_RANGE: &str = "198.18.0.0/15";
// Bound the IPv6 table to the same address count as IPv4.
pub const IPV6_RANGE: &str = "2001:2::/111";

pub fn flush_system_cache() -> Result<()> {
    // No DNS addresses or routing domains are changed. An inactive resolved
    // has no cache to flush and must not be enabled by the VPN client.
    if !std::path::Path::new("/run/systemd/resolve/io.systemd.Resolve").exists() {
        return Ok(());
    }
    let program = ["/usr/bin/resolvectl", "/bin/resolvectl"]
        .into_iter()
        .find(|path| crate::process::trusted_binary(std::path::Path::new(path)))
        .ok_or("Для очистки системного DNS-кэша нужен resolvectl.")?;
    crate::network::bounded_output(program, &["flush-caches"])
        .map_err(|_| "Не удалось очистить системный DNS-кэш.".to_owned())?;
    Ok(())
}

pub fn check_ranges() -> Result<()> {
    let program = ["/usr/sbin/ip", "/usr/bin/ip"]
        .into_iter()
        .find(|path| crate::process::trusted_binary(std::path::Path::new(path)))
        .ok_or("Для проверки диапазона DNS нужен системный iproute2.")?;
    for family in ["-4", "-6"] {
        let output = crate::network::bounded_output(
            program,
            &[family, "-j", "route", "show", "table", "all"],
        )?;
        let routes: Vec<Value> =
            serde_json::from_slice(&output).map_err(|_| "Не удалось проверить диапазон DNS.")?;
        if routes.iter().any(range_conflict) {
            return Err("Диапазон виртуальных адресов DNS занят другой сетью или VPN.".into());
        }
    }
    Ok(())
}

fn range_conflict(route: &Value) -> bool {
    if route["dev"] == crate::platform::TUN_NAME {
        return false;
    }
    let Some(destination) = route["dst"].as_str() else {
        return false;
    };
    let network = destination.parse::<ipnet::IpNet>().ok().or_else(|| {
        destination
            .parse::<std::net::IpAddr>()
            .ok()
            .map(ipnet::IpNet::from)
    });
    let Some(network) = network else {
        return false;
    };
    [IPV4_RANGE, "2001:2::/48"].iter().any(|range| {
        let reserved: ipnet::IpNet = range.parse().unwrap();
        // Broad default/Internet routes are not claims on our synthetic range.
        network.prefix_len() >= reserved.prefix_len() && reserved.contains(&network.network())
    })
}

pub fn configure(config: &mut Value, request: &ConnectRequest) -> Result<()> {
    config["dns"]["servers"]
        .as_array_mut()
        .ok_or("Нет DNS-конфигурации.")?
        .push(json!({"type":"fakeip","tag":"domain-identity",
            "inet4_range":IPV4_RANGE,"inet6_range":IPV6_RANGE}));
    // Identity allocation is local and does not resolve the name. The actual
    // connection supplies process metadata and chooses its resolver/exit;
    // applying a lower-priority domain rejection here would override app rules.
    config["dns"]["rules"]
        .as_array_mut()
        .ok_or("Нет правил DNS.")?
        .insert(
            0,
            json!({"inbound":["tun"],"query_type":["A","AAAA"],
            "action":"route","server":"domain-identity"}),
        );
    config["dns"]["reverse_mapping"] = json!(false);
    config["outbounds"][1]["domain_resolver"] = json!("direct-dns");

    let mut prefix = Vec::new();
    // Unknown synthetic addresses must never escape to a VPN server. Known
    // FakeIPs have already become domain destinations before rule evaluation.
    prefix.push(json!({"ip_cidr":[IPV4_RANGE,"2001:2::/48"],"action":"reject"}));
    let needs_resolution = request.policies.iter().filter(|rule| rule.enabled).any(|rule| {
        matches!(&rule.target, Target::Address(address) if matches!(Rule::parse(address), Ok(Rule::Network(_))))
    }) || request.bypass.iter().any(|address| matches!(Rule::parse(address), Ok(Rule::Network(_))))
        || request.ru_preset.as_ref().is_some_and(|preset| preset.has_networks());
    if needs_resolution
        && !request
            .ru_preset
            .as_ref()
            .is_some_and(|preset| preset.has_networks())
    {
        prefix.extend(crate::config::resolution_rules(
            config,
            request,
            crate::config::Mode::Tun,
        )?);
    }
    let routes = config["route"]["rules"]
        .as_array_mut()
        .ok_or("Нет маршрутов.")?;
    for rule in routes.iter_mut().filter(|rule| rule["action"] == "sniff") {
        // Explicit SOCKS/HTTP destinations and FakeIP identities outrank an
        // observed Host or an ECH outer SNI belonging to a shared CDN.
        rule["domain_regex"] = json!([".+"]);
        rule["invert"] = json!(true);
    }
    let insert = routes
        .iter()
        .position(|rule| rule["action"] == "hijack-dns")
        .ok_or("Нет перехвата DNS.")?
        + 1;
    routes.splice(insert..insert, prefix);
    Ok(())
}
