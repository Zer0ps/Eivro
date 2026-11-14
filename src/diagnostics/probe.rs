#[cfg(test)]
use super::https::Output;
pub(super) use super::https::target;
use super::{
    Action, Report, Request, Status,
    analysis::route_to,
    https::{classify, curl_arguments, probe_address},
    linux::{Context, Snapshot, system_binary},
};
use crate::{Result, routing::Rule};
use std::{net::IpAddr, time::Duration};

fn resolve(ctx: &Context, host: &str) -> Result<Vec<IpAddr>> {
    if let Ok(ip) = host.parse() {
        return Ok(vec![ip]);
    }
    let host = match Rule::parse(host)? {
        Rule::Exact(host) => host,
        _ => return Err("Нужен точный адрес.".into()),
    };
    let mut addresses = Vec::new();
    // getent runs NSS in a killable child, so broken modules cannot strand a worker.
    for database in ["ahostsv4", "ahostsv6"] {
        if ctx.stopped() {
            break;
        }
        if let Ok(text) = ctx.system("getent", &[database, &host]) {
            for ip in text
                .lines()
                .filter_map(|line| line.split_whitespace().next()?.parse::<IpAddr>().ok())
            {
                if !addresses.contains(&ip) && addresses.len() < 32 {
                    addresses.push(ip);
                }
            }
        }
    }
    if addresses.is_empty() {
        Err("Системный DNS/NSS не вернул адрес в пределах времени ожидания.".into())
    } else {
        Ok(addresses)
    }
}

fn endpoint(ctx: &Context, host: &str, report: &mut Report) {
    match resolve(ctx, host) {
        Ok(addresses) => {
            let synthetic = addresses.iter().any(|ip| crate::domain_dns::gateways::synthetic(*ip));
            report.add("endpoint", if synthetic { Status::Warning } else { Status::Pass }, "DNS сервера VPN", format!("Системный DNS/NSS вернул адресов сервера: {}. {}", addresses.len(), if synthetic { "NSS содержит адрес FakeIP; ядро может уже использовать закреплённый реальный адрес. Сбой текущего транспорта не доказан." } else { "Это подтверждает разрешение имени, но не доступность сервера или действительность ключа." }), if synthetic { "При сбое переподключения очистите системный DNS-кэш и перепроверьте адрес сервера. Если FakeIP возвращается снова, проверьте DNS и исключение транспорта VPN." } else { "Сопоставьте маршрут к серверу с активными VPN." }, synthetic.then_some(Action::FlushDns));
            for ip in addresses.into_iter().filter(|ip| !crate::domain_dns::gateways::synthetic(*ip)).take(2) { route_to(ctx, ip, "endpoint_route", "Маршрут к серверу VPN", true, report); }
        }
        Err(_) => report.add("endpoint", Status::Error, "DNS сервера VPN не подтверждён", "Системный DNS/NSS не вернул адрес сервера за ограниченное время. Причина может быть в DNS, сети или имени сервера.", "Проверьте системный DNS и адрес сервера. Это не доказательство неверного ключа или блокировки.", None),
    }
}

fn https(
    ctx: &Context,
    host: &str,
    proxy: Option<u16>,
    interface: Option<&str>,
    address: Option<IpAddr>,
    system_tun: bool,
    report: &mut Report,
) {
    let id = if interface.is_some() {
        "direct"
    } else {
        "https"
    };
    let title = if interface.is_some() {
        "HTTPS через физический выход"
    } else if proxy.is_some() {
        "HTTPS через локальный прокси Eivro"
    } else {
        "HTTPS по системному маршруту"
    };
    let args = curl_arguments(host, proxy, interface, address);
    let result = system_binary("curl").and_then(|path| {
        ctx.command(
            &path,
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
            Duration::from_secs(7),
            false,
        )
    });
    let (status, detail) = result
        .as_ref()
        .map(|output| classify(output, proxy.is_some(), system_tun))
        .unwrap_or((
            Status::Unknown,
            "Проверка отменена, исчерпала время или системный curl недоступен.",
        ));
    let title = if let Some(address) = address {
        format!(
            "{title} · {}",
            if address.is_ipv4() { "IPv4" } else { "IPv6" }
        )
    } else {
        title.into()
    };
    report.add(id, status, &title, detail, if proxy.is_some() { "Проверен локальный прокси и выбранное адресное правило. Семейство адреса удалённого транспорта выбирает ядро; этот тест не доказывает отдельно доступность IPv6." } else if interface.is_some() { "Проверка привязана к физическому интерфейсу и использует ранее полученный системный DNS-адрес. Чужой VPN или фильтр могут всё ещё влиять на путь." } else { "Проверен обычный системный путь; другие VPN и политики могут влиять на него. Новое подключение Eivro не запускалось." }, None);
}

fn physical_default(snapshot: &Snapshot, ipv6: bool) -> Option<&str> {
    let routes = if ipv6 {
        &snapshot.routes6
    } else {
        &snapshot.routes4
    };
    let mut defaults: Vec<_> = routes
        .as_ref()
        .ok()?
        .as_array()?
        .iter()
        .filter(|row| {
            row["dst"] == "default" && row.get("type").is_none_or(|kind| kind == "unicast")
        })
        .collect();
    defaults.sort_by_key(|row| row["metric"].as_u64().unwrap_or(0));
    defaults
        .into_iter()
        .filter_map(|row| row["dev"].as_str())
        .find(|name| {
            snapshot.links.iter().any(|link| {
                link.interface.name == *name && link.physical && link.interface.up && link.carrier
            })
        })
}

fn active_gateways(request: &Request) -> Vec<String> {
    let Some(profile) = request
        .settings
        .routing_profiles
        .get(request.settings.selected_routing)
    else {
        return Vec::new();
    };
    let mut hosts = Vec::new();
    for connection in &request.settings.connections {
        if !profile.rules.iter().any(|rule| {
            rule.enabled && rule.action == crate::policy::Action::Connection(connection.id)
        }) {
            continue;
        }
        if let Some(host) = connection
            .gateway
            .as_deref()
            .and_then(|host| crate::domain_dns::gateways::canonical(host).ok())
            && !hosts.contains(&host)
        {
            hosts.push(host);
            if hosts.len() == 4 {
                break;
            }
        }
    }
    hosts
}

fn gateway_probe_allowed(request: &Request, host: &str) -> bool {
    // An IP literal needs only local route inspection. Hostnames may invoke NSS
    // outside an HTTP proxy and need the same consent as other system DNS tests.
    host.parse::<IpAddr>().is_ok() || super::analysis::target_kernel_allowed(request)
}

pub(super) fn run(
    ctx: &Context,
    request: &Request,
    snapshot: &Snapshot,
    selected_endpoint: Option<&str>,
    report: &mut Report,
) {
    if let Some(host) = selected_endpoint {
        endpoint(ctx, host, report);
    }
    let mut skipped_gateway_dns = false;
    for host in active_gateways(request) {
        if ctx.stopped() {
            break;
        }
        if gateway_probe_allowed(request, &host) {
            endpoint(ctx, &host, report);
        } else {
            skipped_gateway_dns = true;
        }
    }
    if skipped_gateway_dns {
        report.add("endpoint", Status::Unknown, "DNS серверов внешних выходов не проверялся", "Имена серверов выходов выбранного профиля не отправлялись системному DNS вне активного HTTP-прокси.", "Для отдельного сравнения системного DNS нужно явно разрешить прямой тест при выключенном kill switch.", None);
    }
    let host = match target(
        request
            .address
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("example.com"),
    ) {
        Ok(host) => host,
        Err(_) => {
            report.add(
                "https",
                Status::Error,
                "Адрес не пригоден для проверки",
                "Допустим точный домен или реальный IP без URL, пути, маски и порта.",
                "Исправьте адрес и повторите диагностику.",
                None,
            );
            return;
        }
    };
    let system_dns_allowed = !request.connected
        || request.settings.mode == crate::config::Mode::Tun
        || (request.direct_test && !request.settings.kill_switch);
    let addresses = if system_dns_allowed {
        resolve(ctx, &host)
    } else {
        Err("Системный DNS не запрашивался вне прокси.".into())
    };
    match &addresses {
        Ok(addresses) => report.add("dns_probe", Status::Pass, "Проверка системного DNS/NSS", format!("Получено адресов: {}; IPv4: {}; IPv6: {}. Отсутствие AAAA само по себе не ошибка. FakeIP для домена назначения допустим при активном TUN.", addresses.len(), addresses.iter().filter(|ip| ip.is_ipv4()).count(), addresses.iter().filter(|ip| ip.is_ipv6()).count()), "Эта проверка использует системный NSS; DNS выбранного выхода дополнительно проверяется HTTPS через Eivro.", None),
        Err(_) if !system_dns_allowed => report.add("dns_probe", Status::Unknown, "Системный DNS вне прокси не запрашивался", "При активном локальном или системном прокси имя назначения передаётся только прокси в HTTPS-запросе.", "Для отдельного сравнения с системным DNS нужно явно разрешить прямой тест при выключенном kill switch.", None),
        Err(_) => report.add("dns_probe", Status::Warning, "Системный DNS/NSS не ответил", "Адрес назначения не получен за ограниченное время. Прокси может использовать независимый DNS и продолжать работать.", "Сопоставьте системный DNS, область DNS профиля и результат HTTPS.", None),
    }
    if request.address.as_deref().is_some_and(|address| {
        !address.trim().is_empty() && address.trim().parse::<IpAddr>().is_err()
    }) && super::analysis::target_kernel_allowed(request)
        && let Ok(addresses) = &addresses
    {
        for ip in addresses.iter().take(4) {
            if ctx.stopped() {
                break;
            }
            super::analysis::target_route(ctx, snapshot, *ip, report);
        }
    }
    if !ctx.stopped() {
        https(
            ctx,
            &host,
            request.connected.then_some(request.settings.port),
            None,
            None,
            false,
            report,
        );
    }
    if request.connected && request.settings.mode == crate::config::Mode::Tun && !ctx.stopped() {
        // A healthy local proxy does not demonstrate that system interception
        // works. This follows ordinary routing, including deliberate bypasses.
        https(ctx, &host, None, None, None, true, report);
    }
    if !request.connected && !ctx.stopped() {
        // A separate IPv6 request is useful only when both the local route and AAAA
        // exist. A normal IPv4-only installation is never labelled broken IPv6.
        let v6 = addresses
            .as_ref()
            .ok()
            .and_then(|ips| ips.iter().find(|ip| ip.is_ipv6() && probe_address(**ip)))
            .copied();
        if physical_default(snapshot, true).is_some()
            && let Some(ip) = v6
        {
            https(ctx, &host, None, None, Some(ip), false, report);
        }
    }
    if request.direct_test {
        if request.settings.kill_switch {
            report.add(
                "direct",
                Status::Unknown,
                "Прямой тест запрещён защитой",
                "Kill switch включён; обходной запрос не выполнялся.",
                "Сохраните защиту или отдельно измените её настройки перед повторной проверкой.",
                None,
            );
            return;
        }
        let mut tested = false;
        for ipv6 in [false, true] {
            let interface = physical_default(snapshot, ipv6);
            let address = addresses
                .as_ref()
                .ok()
                .and_then(|addresses| {
                    addresses
                        .iter()
                        .find(|ip| ip.is_ipv6() == ipv6 && probe_address(**ip))
                })
                .copied();
            if let (Some(interface), Some(address)) = (interface, address)
                && !ctx.stopped()
            {
                https(
                    ctx,
                    &host,
                    None,
                    Some(interface),
                    Some(address),
                    false,
                    report,
                );
                tested = true;
            }
        }
        if !tested {
            report.add("direct", Status::Unknown, "Нет безопасного прямого теста", "Не найден физический маршрут по умолчанию и реальный адрес назначения подходящего семейства. Синтетические и локальные адреса не проверяются как внешняя сеть.", "Проверьте физическое подключение и системный DNS. Отсутствие IPv6 не считается неисправностью IPv4.", None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gateway_probes_use_enabled_selected_exits_before_deduplication_and_limit() {
        let mut request = Request {
            settings: Default::default(),
            connected: true,
            busy: false,
            network_tests: true,
            direct_test: false,
            address: None,
        };
        request.settings.routing_profiles.truncate(1);
        request.settings.routing_profiles[0].rules.clear();
        for id in 1..=10 {
            request
                .settings
                .connections
                .push(crate::network::Connection {
                    id,
                    name: format!("exit-{id}"),
                    interface: "eth0".into(),
                    dns: Default::default(),
                    gateway: Some(match id {
                        5 => "shared.example.test".into(),
                        6 => "SHARED.EXAMPLE.TEST".into(),
                        _ => format!("gateway{id}.example.test"),
                    }),
                });
            if id == 2 || id >= 5 {
                request.settings.routing_profiles[0]
                    .rules
                    .push(crate::policy::PolicyRule {
                        enabled: id != 2,
                        target: crate::policy::Target::Address(format!("target{id}.example.test")),
                        action: crate::policy::Action::Connection(id),
                    });
            }
        }
        assert_eq!(
            active_gateways(&request),
            [
                "shared.example.test",
                "gateway7.example.test",
                "gateway8.example.test",
                "gateway9.example.test"
            ]
        );
        assert!(!gateway_probe_allowed(&request, "shared.example.test"));
        assert!(gateway_probe_allowed(&request, "192.0.2.1"));
        request.direct_test = true;
        assert!(gateway_probe_allowed(&request, "shared.example.test"));
        request.settings.kill_switch = true;
        assert!(!gateway_probe_allowed(&request, "shared.example.test"));
        request.settings.mode = crate::config::Mode::Tun;
        assert!(gateway_probe_allowed(&request, "shared.example.test"));
    }

    #[test]
    fn tun_system_probe_uses_normal_routes_and_accepts_only_verified_fakeip_https() {
        let args = curl_arguments("example.com", None, None, None);
        assert!(args.windows(2).any(|pair| pair == ["--proxy", ""]));
        assert!(args.windows(2).any(|pair| pair == ["--noproxy", "*"]));
        assert!(
            !args
                .iter()
                .any(|arg| ["--interface", "--resolve", "--insecure"].contains(&arg.as_str()))
        );
        let mut output = Output {
            code: Some(0),
            text: "200 198.18.1.2".into(),
        };
        assert_eq!(classify(&output, false, true).0, Status::Pass);
        assert_eq!(classify(&output, false, false).0, Status::Warning);
        output.text = "200 127.0.0.1".into();
        assert_eq!(classify(&output, false, true).0, Status::Warning);
        output.code = Some(60);
        output.text = "000 198.18.1.2".into();
        assert_eq!(classify(&output, false, true).0, Status::Error);
    }
    #[test]
    fn target_cannot_be_url_or_local_false_positive() {
        for input in [
            "https://example.com/path",
            "user@host",
            "example.com:443",
            "*.example.com",
            "192.0.2.0/24",
            "127.0.0.1",
            "127.1",
            "0x7f000001",
            "2130706433",
            "::1",
            "::ffff:127.0.0.1",
            "198.18.1.1",
            "--help",
            "example.com\n--insecure",
        ] {
            assert!(target(input).is_err(), "{input}");
        }
        assert_eq!(target(" EXAMPLE.COM ").unwrap(), "example.com");
        assert_eq!(target("2001:db8::1").unwrap(), "2001:db8::1");
    }
    #[test]
    fn curl_cannot_load_user_settings_or_follow_redirects() {
        let args = curl_arguments("example.com", Some(2080), None, None);
        assert_eq!(args.first().unwrap(), "--disable");
        assert!(
            !args
                .iter()
                .any(|arg| ["--insecure", "--location", "-L"].contains(&arg.as_str()))
        );
        assert!(args.windows(2).any(|pair| pair == ["--proto", "=https"]));
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--proxy", "http://127.0.0.1:2080"])
        );
        let direct = curl_arguments(
            "example.com",
            None,
            Some("eth0"),
            Some("192.0.2.1".parse().unwrap()),
        );
        assert!(
            direct
                .windows(2)
                .any(|pair| pair == ["--interface", "if!eth0"])
        );
        assert!(
            direct
                .windows(2)
                .any(|pair| pair == ["--resolve", "example.com:443:192.0.2.1"])
        );
    }
    #[test]
    fn http_tls_and_transport_failures_are_distinct() {
        let output = |code, text: &str| Output {
            code: Some(code),
            text: text.into(),
        };
        assert_eq!(
            classify(&output(0, "200 192.0.2.1"), false, false).0,
            Status::Pass
        );
        assert_eq!(
            classify(&output(0, "200 127.0.0.1"), false, false).0,
            Status::Warning
        );
        assert_eq!(
            classify(&output(0, "302 192.0.2.1"), false, false).0,
            Status::Warning
        );
        assert!(
            classify(&output(60, "000"), false, false)
                .1
                .contains("сертификат")
        );
        assert!(classify(&output(7, "000"), true, false).1.contains("TCP"));
    }
}
