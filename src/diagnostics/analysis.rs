use super::{
    Action, Report, Request, Status,
    linux::{Context, Snapshot},
};
use crate::{Result, config::Mode, policy};
use serde_json::Value;
use std::os::unix::fs::MetadataExt;
use std::{net::IpAddr, path::Path, time::Duration};

pub(super) fn runtime_dns(value: &Value, interface: &str) -> Result<Vec<IpAddr>> {
    let rows = value.as_array().ok_or("Неизвестный формат DNS.")?;
    let row = rows
        .iter()
        .find(|row| row["ifname"] == interface)
        .ok_or("Нет достоверного состояния DNS интерфейса.")?;
    let servers = match row.get("servers") {
        Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(servers)) => servers,
        _ => return Err("Неизвестный формат DNS интерфейса.".into()),
    };
    let mut addresses = Vec::new();
    for server in servers {
        if server["port"]
            .as_u64()
            .is_some_and(|port| port != 0 && port != 53)
            || server["serverName"]
                .as_str()
                .is_some_and(|name| !name.is_empty())
            || server["accessible"].as_bool() == Some(false)
        {
            return Err("DNS имеет особые параметры; безопасное сравнение невозможно.".into());
        }
        let ip = server["addressString"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or("Нельзя безопасно сравнить DNS интерфейса.")?;
        if !addresses.contains(&ip) {
            addresses.push(ip);
        }
    }
    Ok(addresses)
}

pub(super) fn nm_dns(text: &str) -> Result<Vec<IpAddr>> {
    let mut physical = false;
    let mut active = false;
    let mut servers = Vec::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key {
            "GENERAL.TYPE" => {
                physical = matches!(value.trim(), "ethernet" | "wifi" | "bridge" | "bond")
            }
            "GENERAL.STATE" => active = value.split_whitespace().next() == Some("100"),
            _ if key.starts_with("IP4.DNS[") => {
                let ip: IpAddr = value
                    .trim()
                    .parse()
                    .map_err(|_| "Некорректный DNS активного подключения.")?;
                if !valid_candidate(ip) {
                    return Err("DNS активного подключения нельзя безопасно восстановить.".into());
                }
                if !servers.contains(&ip) {
                    servers.push(ip);
                }
            }
            _ => {}
        }
    }
    if !physical || !active || servers.is_empty() || servers.len() > 8 {
        return Err("Нет пригодного DNS активного физического подключения NetworkManager.".into());
    }
    Ok(servers)
}

fn valid_candidate(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(ip) if !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast() && !ip.is_link_local() && ip.octets()[0] != 0 && ip.octets()[0] < 240)
        && !crate::domain_dns::gateways::synthetic(ip)
        && !["172.31.250.1", "172.31.250.2"]
            .iter()
            .any(|s| s.parse::<IpAddr>() == Ok(ip))
}

fn rows(value: &Result<Value>) -> Option<&Vec<Value>> {
    value.as_ref().ok()?.as_array()
}
fn blocked(row: &Value) -> bool {
    ["blackhole", "unreachable", "prohibit"]
        .iter()
        .any(|kind| row["type"] == *kind || row["action"] == *kind)
}
fn default_route(row: &Value) -> bool {
    ["default", "0.0.0.0/0", "::/0"]
        .iter()
        .any(|dst| row["dst"] == *dst)
        && !blocked(row)
}

pub(super) fn network(snapshot: &Snapshot, report: &mut Report) {
    let physical: Vec<_> = snapshot
        .links
        .iter()
        .filter(|link| link.physical && link.interface.up && link.carrier)
        .collect();
    report.add("uplink", if physical.is_empty() { Status::Warning } else { Status::Pass }, "Физическое подключение", if physical.is_empty() { "Не найден физический интерфейс с активным линком. Виртуальные машины и мосты могут не иметь такого интерфейса.".into() } else { format!("Активные интерфейсы: {}. Это подтверждает линк, но не доступ в Интернет.", physical.iter().map(|link| link.interface.name.as_str()).collect::<Vec<_>>().join(", ")) }, "Если сеть не работает, проверьте Wi-Fi, кабель и активное подключение системы.", None);
    for (id, title, routes, optional) in [
        ("routes4", "Маршруты IPv4", &snapshot.routes4, false),
        ("routes6", "Маршруты IPv6", &snapshot.routes6, true),
    ] {
        match rows(routes) {
            None => report.add(
                id,
                Status::Unknown,
                title,
                "Не удалось прочитать таблицы маршрутизации ядра.",
                "Проверьте наличие системного iproute2.",
                None,
            ),
            Some(routes) => {
                let defaults: Vec<_> = routes.iter().filter(|r| default_route(r)).collect();
                let status = if !defaults.is_empty() {
                    Status::Pass
                } else if optional {
                    Status::Unknown
                } else {
                    Status::Warning
                };
                report.add(id, status, title, if !defaults.is_empty() { format!("Найдено маршрутов по умолчанию: {}. Политики ядра могут выбирать другую таблицу.", defaults.len()) } else if optional { "IPv6-маршрут по умолчанию отсутствует. Для IPv4-подключения IPv6 не обязателен; это не доказательство неисправности.".into() } else { "Нет обычного маршрута по умолчанию. Возможны раздельные маршруты VPN; маршрут к конкретному адресу проверяется отдельно.".into() }, "Сопоставьте маршрут к проблемному адресу с активным VPN и системным подключением.", Some(Action::OpenRoutes));
            }
        }
    }
    if let (Some(a), Some(b), Some(ra), Some(rb)) = (
        rows(&snapshot.rules4),
        rows(&snapshot.rules6),
        rows(&snapshot.routes4),
        rows(&snapshot.routes6),
    ) {
        let blocks = a
            .iter()
            .chain(b)
            .chain(ra)
            .chain(rb)
            .filter(|r| blocked(r))
            .count();
        let custom = a
            .iter()
            .chain(b)
            .filter(|r| !matches!(r["table"].as_str(), Some("local" | "main" | "default")))
            .count();
        report.add("policy", if blocks > 0 { Status::Warning } else { Status::Pass }, "Политики ядра", format!("Дополнительных правил: {custom}; запрещающих правил/маршрутов: {blocks}. Запрет может быть намеренной защитой VPN; наличие правила само по себе не означает сбой."), "Проверьте, не конкурируют ли несколько VPN. Диагностика не удаляет чужие маршруты или правила.", Some(Action::OpenRoutes));
        let collisions = ra
            .iter()
            .chain(rb)
            .filter(|route| route["dev"] != crate::platform::TUN_NAME)
            .filter(|route| {
                route["dst"]
                    .as_str()
                    .and_then(|dst| {
                        dst.parse::<ipnet::IpNet>()
                            .ok()
                            .or_else(|| dst.parse::<IpAddr>().ok().map(ipnet::IpNet::from))
                    })
                    .is_some_and(|net| {
                        [crate::domain_dns::IPV4_RANGE, "2001:2::/48"]
                            .iter()
                            .any(|range| {
                                let reserved: ipnet::IpNet = range.parse().unwrap();
                                net.prefix_len() >= reserved.prefix_len()
                                    && reserved.contains(&net.network())
                            })
                    })
            })
            .count();
        if collisions > 0 {
            report.add("fakeip", Status::Warning, "Конфликт диапазона виртуальных адресов", format!("Обнаружено сторонних маршрутов в диапазоне FakeIP: {collisions}."), "Если маршрут относится к серверу другого VPN, задайте реальный адрес его сервера в сетевом выходе.", Some(Action::OpenRoutes));
        }
    } else {
        report.add(
            "policy",
            Status::Unknown,
            "Политики ядра",
            "Не все таблицы и правила доступны; влияние другого VPN неизвестно.",
            "Повторите проверку с доступным iproute2.",
            None,
        );
    }
}

pub(super) fn dns(ctx: &Context, snapshot: &Snapshot, request: &Request, report: &mut Report) {
    let nameservers: Vec<IpAddr> = snapshot
        .resolv
        .as_ref()
        .ok()
        .into_iter()
        .flat_map(|s| s.lines())
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next()? == "nameserver")
                .then(|| words.next()?.parse().ok())
                .flatten()
        })
        .collect();
    let stub = nameservers.iter().any(|ip| {
        ["127.0.0.53", "127.0.0.54"]
            .iter()
            .any(|s| s.parse::<IpAddr>() == Ok(*ip))
    });
    let service_ok = if stub {
        ctx.system("systemctl", &["is-active", "systemd-resolved.service"])
            .is_ok_and(|s| s.trim() == "active")
    } else {
        true
    };
    let (status, detail) = if snapshot.dangling_resolv {
        (
            Status::Error,
            "Ссылка /etc/resolv.conf указывает на отсутствующий файл.",
        )
    } else if snapshot.resolv.is_err() {
        (Status::Unknown, "Не удалось прочитать /etc/resolv.conf.")
    } else if nameservers.is_empty() {
        (
            Status::Warning,
            "В /etc/resolv.conf нет DNS-серверов. NSS может использовать другой механизм; сетевой тест требуется отдельно.",
        )
    } else if !service_ok {
        (
            Status::Error,
            "Системный DNS указывает на локальный stub, но служба systemd-resolved не подтвердила активность.",
        )
    } else {
        (
            Status::Pass,
            "Файл системного DNS читается; локальная конфигурация проверена. Ответы DNS ещё не подтверждены.",
        )
    };
    report.add("resolver", status, "Системный DNS", detail, "Проверьте службу DNS и настройки активного сетевого подключения. Произвольный публичный DNS не подставляется.", None);
    for link in snapshot
        .links
        .iter()
        .filter(|link| link.physical && link.interface.up && link.carrier)
        .take(8)
    {
        if ctx.stopped() {
            break;
        }
        let runtime = snapshot
            .dns
            .as_ref()
            .map_err(Clone::clone)
            .and_then(|value| runtime_dns(value, &link.interface.name));
        let nm = snapshot
            .nm_dns
            .iter()
            .find(|(interface, _)| interface == &link.interface.name)
            .map(|(_, result)| result.clone())
            .unwrap_or_else(|| Err("Нет снимка DNS NetworkManager.".into()));
        let can_repair = !request.connected
            && !request.busy
            && !snapshot.links.iter().any(|l| {
                [crate::platform::TUN_NAME, "eivro0", "velum0"].contains(&l.interface.name.as_str())
            });
        dns_evidence(&link.interface.name, &runtime, &nm, can_repair, report);
        if let Ok(addresses) = runtime {
            for ip in addresses.into_iter().filter(|ip| !ip.is_loopback()).take(2) {
                route_to(ctx, ip, "dns_route", "Маршрут к DNS", false, report);
            }
        }
    }
}

fn dns_evidence(
    interface: &str,
    runtime: &Result<Vec<IpAddr>>,
    nm: &Result<Vec<IpAddr>>,
    can_repair: bool,
    report: &mut Report,
) {
    match (runtime, nm) {
            (Ok(current), Ok(candidate)) if current.is_empty() => {
                report.add("nm_dns", Status::Error, "DNS активного подключения потерян", format!("У {interface} нет DNS в systemd-resolved. NetworkManager сообщает DNS активного подключения: {}. Эти адреса предлагаются для восстановления.", candidate.iter().map(IpAddr::to_string).collect::<Vec<_>>().join(", ")), "Можно восстановить только DNS этого активного подключения. Изменение требует отдельного подтверждения и повторной проверки состояния.", can_repair.then(|| Action::RestoreDns { interface: interface.into() }));
            }
            (Ok(current), Ok(candidate)) if current != candidate => report.add("nm_dns", Status::Warning, "DNS источников различается", format!("Для {interface} DNS systemd-resolved отличается от DNS активного подключения NetworkManager. Это бывает намеренным при VPN и split DNS."), "Проверьте владельца DNS и домены маршрутизации. Настроенный DNS автоматически не заменяется.", None),
            (Ok(current), _) if !current.is_empty() => report.add("nm_dns", Status::Pass, "DNS интерфейса задан", format!("Для {interface} в systemd-resolved заданы DNS-серверы: {}.", current.len()), "Доступность сервера проверяется отдельно.", None),
            _ => report.add("nm_dns", Status::Unknown, "Нет полного сравнения DNS", format!("Для {interface} недоступны подтверждённые сведения NetworkManager или systemd-resolved."), "Автоматическое восстановление DNS не предлагается без достоверного источника.", None),
        }
}

pub(super) fn route_to(
    ctx: &Context,
    ip: IpAddr,
    id: &str,
    title: &str,
    transport: bool,
    report: &mut Report,
) {
    let result = ctx.system(
        "ip",
        &[
            "-j",
            if ip.is_ipv4() { "-4" } else { "-6" },
            "route",
            "get",
            &ip.to_string(),
        ],
    );
    match result.ok().and_then(|raw| serde_json::from_str::<Value>(&raw).ok()).and_then(|rows| rows.as_array().and_then(|a| a.first().cloned())) {
        Some(row) if !blocked(&row) && row["dev"].as_str().is_some() => {
            let dev = row["dev"].as_str().unwrap();
            let tunnel = transport && dev == crate::platform::TUN_NAME;
            report.add(id, if tunnel { Status::Unknown } else { Status::Pass }, title, format!("Ядро выбирает {dev} для {ip}. Это маршрут обычного процесса без меток VPN, а не проверка доступности."), if tunnel { "Ядро Eivro привязывает внешний сокет к интерфейсу или метке. Этот обычный lookup не подтверждает его путь; результат HTTPS проверяется отдельно." } else { "При отсутствии ответа проверьте соседний маршрутизатор и фильтрацию; маршрут сам по себе не доказывает доступность." }, None);
        }
        _ => report.add(id, Status::Warning, title, format!("Ядро не подтвердило обычный маршрут к {ip}; возможен запрет политики или отсутствие маршрута."), "Сопоставьте семейство адреса, таблицы маршрутизации и политики другого VPN.", Some(Action::OpenRoutes)),
    }
}

pub(super) fn target_kernel_allowed(request: &Request) -> bool {
    !request.connected
        || request.settings.mode == Mode::Tun
        || (request.direct_test && !request.settings.kill_switch)
}

pub(super) fn target_route(ctx: &Context, snapshot: &Snapshot, ip: IpAddr, report: &mut Report) {
    let result = super::linux::system_binary("ip").and_then(|path| {
        ctx.command(
            &path,
            &[
                "-j",
                if ip.is_ipv4() { "-4" } else { "-6" },
                "route",
                "get",
                &ip.to_string(),
            ],
            Duration::from_secs(2),
            false,
        )
    });
    let routes = if ip.is_ipv4() {
        &snapshot.routes4
    } else {
        &snapshot.routes6
    };
    let (status, detail) = target_route_evidence(ip, result.as_ref().ok(), routes);
    report.add("target_route", status, "Маршрут проблемного адреса", detail,
        "Это маршрут обычного процесса, без меток и привязки ядра VPN. В TUN маршрут виртуального адреса через Eivro ожидаем; при прокси фактический выход дополнительно определяется профилем.",
        (status == Status::Error || status == Status::Warning).then_some(Action::OpenRoutes));
}

fn target_route_evidence(
    ip: IpAddr,
    output: Option<&super::https::Output>,
    routes: &Result<Value>,
) -> (Status, String) {
    let Some(output) = output else {
        return (
            Status::Unknown,
            "Не удалось выполнить ограниченный запрос маршрута. Отсутствие маршрута не доказано."
                .into(),
        );
    };
    if output.code == Some(0) {
        let row = serde_json::from_str::<Value>(&output.text)
            .ok()
            .and_then(|rows| rows.as_array().and_then(|rows| rows.first().cloned()));
        if let Some(row) = row {
            if blocked(&row) {
                return (
                    Status::Error,
                    format!("Ядро выбрало запрещающий маршрут к {ip}."),
                );
            }
            if let Some(device) = row["dev"].as_str() {
                return (
                    Status::Pass,
                    format!(
                        "Для {ip} ядро выбирает интерфейс {device}. Наличие маршрута не доказывает доступность адреса."
                    ),
                );
            }
        }
        return (
            Status::Unknown,
            "Ответ ядра не содержит распознаваемого маршрута; результат неизвестен.".into(),
        );
    }
    // A failed lookup alone is also consistent with permissions/tool failures.
    // Correlate only the best main-table match; arbitrary policy tables are not
    // evidence that this ordinary destination would actually be rejected.
    let best = rows(routes)
        .into_iter()
        .flatten()
        .filter(|row| {
            row.get("table")
                .is_none_or(|table| table == "main" || table == "254" || table == 254)
        })
        .filter_map(|row| {
            let destination = row["dst"].as_str()?;
            let net = if destination == "default" {
                if ip.is_ipv4() { "0.0.0.0/0" } else { "::/0" }
                    .parse::<ipnet::IpNet>()
                    .ok()?
            } else {
                destination
                    .parse::<ipnet::IpNet>()
                    .ok()
                    .or_else(|| destination.parse::<IpAddr>().ok().map(ipnet::IpNet::from))?
            };
            net.contains(&ip).then_some((
                net.prefix_len(),
                std::cmp::Reverse(row["metric"].as_u64().unwrap_or(0)),
                row,
            ))
        })
        .max_by_key(|(prefix, metric, _)| (*prefix, *metric));
    if best.is_some_and(|(_, _, row)| blocked(row)) {
        return (
            Status::Error,
            format!(
                "Запрос маршрута к {ip} отклонён; в основной таблице подтверждён подходящий blackhole/unreachable/prohibit. Такой маршрут запрещает обычный выход к адресу."
            ),
        );
    }
    (
        Status::Unknown,
        format!(
            "Маршрут к {ip} не подтверждён, но подходящего запрещающего маршрута в снимке нет. Возможны отсутствие маршрута, ограничения чтения или недоступность утилиты; причина неизвестна."
        ),
    )
}

pub(super) fn profile(
    request: &Request,
    snapshot: &Snapshot,
    report: &mut Report,
) -> Option<String> {
    if !request.connected && !request.busy {
        let tun_present = snapshot.links.iter().any(|link| {
            [crate::platform::TUN_NAME, "eivro0", "velum0"].contains(&link.interface.name.as_str())
        });
        let reserved_rules = [&snapshot.rules4, &snapshot.rules6]
            .into_iter()
            .filter_map(rows)
            .flatten()
            .any(|row| {
                row["priority"]
                    .as_u64()
                    .or_else(|| row["priority"].as_str()?.parse().ok())
                    .is_some_and(|priority| (9000..=9010).contains(&priority))
            });
        if tun_present || reserved_rules {
            report.add("policy", Status::Warning, "TUN или его приоритеты заняты при отключённом Eivro", "Обнаружен интерфейс Eivro либо правила в диапазоне 9000–9010. Это может быть остаточное состояние, другая программа или другой экземпляр; владелец не установлен.", "Проверьте другие подключения и их владельца. Новый TUN может не запуститься; чужие интерфейсы и правила автоматически не удаляются.", Some(Action::OpenRoutes));
        }
        if request.settings.mode == Mode::Tun {
            for finding in report
                .findings
                .iter_mut()
                .filter(|finding| finding.id == "fakeip")
            {
                finding.detail.push_str(" При таком конфликте диапазонов новое подключение TUN будет отклонено; принадлежность сторонних маршрутов не установлена.");
            }
        }
    }
    if request.settings.validate().is_err() {
        report.add("profile", Status::Error, "Настройки подключения некорректны", "Выбранный профиль, сетевые выходы или параметры подключения не прошли проверку согласованности. Секретные параметры не включены в отчёт.", "Проверьте выбранный профиль маршрутизации, сетевые выходы и настройки подключения.", Some(Action::OpenSettings));
        return None;
    }
    let endpoint = request
        .settings
        .selected_profile()
        .and_then(|profile| crate::import::parse_uri(&profile.uri).ok());
    report.add("profile", if endpoint.is_some() { Status::Pass } else { Status::Warning }, "Выбранный сервер", if endpoint.is_some() { "Параметры выбранного сервера разбираются. Это не проверка действительности ключа или доступности сервера." } else { "Нет корректно выбранного сервера. Проверить соединение Eivro пока нельзя." }, "При необходимости выберите или заново импортируйте сервер.", Some(Action::OpenSettings));
    let mut interfaces: Vec<_> = snapshot
        .links
        .iter()
        .map(|link| link.interface.clone())
        .collect();
    if let Ok(dns) = &snapshot.dns {
        crate::network::apply_dns(dns.to_string().as_bytes(), &mut interfaces);
    }
    if let Some(profile) = request
        .settings
        .routing_profiles
        .get(request.settings.selected_routing)
    {
        for connection in &request.settings.connections {
            if !profile.rules.iter().any(|rule| {
                rule.enabled && rule.action == policy::Action::Connection(connection.id)
            }) {
                continue;
            }
            let available = connection.servers(&interfaces).is_some();
            report.add("exit", if available { Status::Pass } else { Status::Error }, "Сетевой выход профиля", format!("Выход на {}: {}. DNS этого выхода применяется к адресным правилам; правила приложения не задают отдельную область DNS.", connection.interface, if available { "интерфейс и DNS доступны в локальном снимке" } else { "нет активного интерфейса или пригодного DNS; соответствующий трафик будет отклонён" }), "Проверьте интерфейс и DNS сетевого выхода; скрытого перехода на другой выход нет.", Some(Action::OpenRoutes));
            if connection
                .gateway
                .as_deref()
                .and_then(|host| host.parse::<IpAddr>().ok())
                .is_some_and(crate::domain_dns::gateways::synthetic)
            {
                report.add(
                    "fakeip",
                    Status::Error,
                    "У сервера другого VPN виртуальный адрес",
                    "Транспорт другого VPN задан адресом из диапазона FakeIP.",
                    "Задайте реальный адрес или точное имя сервера VPN и переподключите его.",
                    Some(Action::OpenRoutes),
                );
            }
        }
        if let Some(address) = request.address.as_deref().filter(|s| !s.trim().is_empty()) {
            match super::probe::target(address) {
                Ok(address) => {
                    let action = profile.matches(&address);
                    let route_label = match action {
                        policy::Action::Connection(id) => request.settings.connections.iter().find(|connection| connection.id == id)
                            .map(|connection| format!("выход «{}» через {}", connection.name, connection.interface))
                            .unwrap_or_else(|| "недоступный сетевой выход".into()),
                        _ => action.label().into(),
                    };
                    let application = profile.rules.iter().any(|rule| rule.enabled && matches!(rule.target, policy::Target::Application(_)));
                    report.add("rule", if application { Status::Warning } else { Status::Pass }, "Правило проблемного адреса", format!("Сохранённый выбранный профиль «{}», адрес {address}: {route_label}. {}", profile.name, if application { "Профиль также содержит правила приложений; без процесса нельзя полностью предсказать выход." } else { "Учтён первый совпавший адресный маршрут и встроенный набор правил." }), "Для домена DNS следует адресному правилу. Для IP используется готовый адрес; правила приложений не меняют область DNS.", Some(Action::OpenRoutes));
                }
                Err(_) => report.add("rule", Status::Error, "Неверный адрес проверки", "Допустим один точный домен или IP; URL, путь, порт, маска и wildcard не принимаются.", "Введите только домен или IP.", None),
            }
        }
        if request.settings.mode != Mode::Tun
            && profile
                .rules
                .iter()
                .any(|r| r.enabled && matches!(r.target, policy::Target::Application(_)))
        {
            report.add(
                "rule",
                Status::Warning,
                "Правила приложений требуют TUN",
                "В локальном и системном прокси правила отдельных приложений не применяются.",
                "Для маршрутизации по приложению выберите TUN.",
                Some(Action::OpenSettings),
            );
        }
    }
    endpoint.map(|parsed| parsed.host)
}

// Query only routing fields. list-recursively also returns stored proxy passwords.
fn proxy_settings(ctx: &Context) -> Result<String> {
    let mut values = String::new();
    for (schema, key) in [
        ("org.gnome.system.proxy", "mode"),
        ("org.gnome.system.proxy.http", "host"),
        ("org.gnome.system.proxy.http", "port"),
        ("org.gnome.system.proxy.https", "host"),
        ("org.gnome.system.proxy.https", "port"),
        ("org.gnome.system.proxy.socks", "host"),
        ("org.gnome.system.proxy.socks", "port"),
    ] {
        let value = ctx.system("gsettings", &["get", schema, key])?;
        values.push_str(&format!("{schema} {key} {}\n", value.trim()));
    }
    Ok(values)
}

pub(super) fn local(ctx: &Context, request: &Request, report: &mut Report) {
    match ctx.system("ss", &["-H", "-ltn"]) {
        Ok(text) => {
            let port = request.settings.port;
            let listening = text
                .lines()
                .filter_map(|l| l.split_whitespace().nth(3))
                .any(|s| {
                    s.rsplit_once(':')
                        .is_some_and(|(_, p)| p.parse::<u16>() == Ok(port))
                });
            let (status, detail) = match (request.connected, listening) {
                (true, true) => (
                    Status::Pass,
                    "Локальный TCP-порт слушает. Активный HTTPS-тест может проверить работу прокси, но не доказывает принадлежность процесса Eivro.",
                ),
                (true, false) => (
                    Status::Error,
                    "Приложение подключено, но локальный TCP-порт не слушает.",
                ),
                (false, true) => (
                    Status::Warning,
                    "Порт занят при отключённом Eivro; это может быть другая программа или оставшееся ядро.",
                ),
                (false, false) => (
                    Status::Pass,
                    "Локальный порт не занят при отключённом Eivro.",
                ),
            };
            report.add("proxy_port", status, "Локальный прокси", detail, "При конфликте выберите свободный порт. При потере соединения переподключите Eivro.", (status != Status::Pass).then_some(if request.connected { Action::Reconnect } else { Action::OpenSettings }));
        }
        Err(_) => report.add(
            "proxy_port",
            Status::Unknown,
            "Локальный прокси",
            "Не удалось прочитать слушающие TCP-порты.",
            "Для проверки нужен системный ss.",
            None,
        ),
    }
    match proxy_settings(ctx) {
        Ok(text) => {
            let get = |schema: &str, key: &str| {
                text.lines().find_map(|line| {
                    let mut fields = line.splitn(3, ' ');
                    (fields.next()? == schema && fields.next()? == key).then(|| {
                        fields
                            .next()
                            .unwrap_or("")
                            .trim()
                            .trim_matches('\'')
                            .to_owned()
                    })
                })
            };
            let mode = get("org.gnome.system.proxy", "mode");
            let matches = ["http", "https", "socks"].iter().all(|kind| {
                let schema = format!("org.gnome.system.proxy.{kind}");
                get(&schema, "host").as_deref() == Some("127.0.0.1")
                    && get(&schema, "port")
                        .is_some_and(|s| s.parse::<u16>() == Ok(request.settings.port))
            });
            let stale = !request.connected && mode.as_deref() == Some("manual") && matches;
            let mismatch = request.connected
                && request.settings.mode == Mode::Proxy
                && (mode.as_deref() != Some("manual") || !matches);
            let recoverable = stale && proxy_recovery_available();
            if !stale
                && !mismatch
                && (mode.as_deref() == Some("auto")
                    || (mode.as_deref() == Some("manual") && !matches))
            {
                report.add("system_proxy", Status::Warning, "Система использует другой прокси",
                    "Приложения, учитывающие настройки GNOME, могут направлять запросы через другой прокси или PAC. Проверка HTTPS через Eivro не подтверждает работу этого отдельного пути.",
                    "Это может быть намеренной настройкой. Проверьте системный прокси и настройки браузера; чужая конфигурация автоматически не меняется.", None);
            } else {
                report.add("system_proxy", if stale || mismatch { Status::Warning } else if mode.is_some() { Status::Pass } else { Status::Unknown }, "Системный прокси GNOME", if stale { "GNOME направляет трафик на порт Eivro, хотя приложение отключено." } else if mismatch { "Настройки GNOME не совпадают с активным системным прокси Eivro." } else { "Конфликт с ожидаемым режимом Eivro не обнаружен. Другие среды рабочего стола и настройки браузеров не проверялись." }, if stale && !recoverable { "Нет доступного частного журнала восстановления Eivro. Проверьте настройки прокси GNOME вручную; совпадение порта не доказывает принадлежность настроек." } else { "Восстановление меняет только настройки, принадлежащие сохранённой аренде Eivro; чужие параметры не сбрасываются." }, if recoverable { Some(Action::RecoverProxy) } else if mismatch { Some(Action::Reconnect) } else { None });
            }
        }
        Err(_) => report.add(
            "system_proxy",
            Status::Unknown,
            "Системный прокси GNOME",
            "Настройки GNOME недоступны; возможно используется другая среда рабочего стола.",
            "Проверьте прокси в настройках системы и браузера.",
            None,
        ),
    }
    component(
        ctx,
        report,
        ("core", "Ядро sing-box"),
        crate::process::core_path().ok().as_deref(),
        "version",
        &format!("sing-box version {}", crate::CORE_VERSION),
        false,
    );
    if request
        .settings
        .selected_profile()
        .and_then(|p| crate::import::parse_uri(&p.uri).ok())
        .is_some_and(|p| p.engine == crate::import::EngineKind::Xray)
    {
        component(
            ctx,
            report,
            ("xray", "Ядро Xray"),
            crate::process::xray_path().ok().as_deref(),
            "version",
            &format!("Xray {} ", crate::xray::VERSION),
            true,
        );
    }
    if request.settings.mode == Mode::Tun {
        let path = Path::new(crate::process::HELPER);
        component(
            ctx,
            report,
            ("helper", "Помощник TUN"),
            crate::process::trusted_binary(path).then_some(path),
            "--version",
            &format!("Eivro TUN {}", env!("CARGO_PKG_VERSION")),
            false,
        );
        if !Path::new("/dev/net/tun").exists() {
            report.add(
                "helper",
                Status::Error,
                "Устройство TUN отсутствует",
                "Не найдено /dev/net/tun.",
                "Проверьте поддержку TUN ядром или настройками виртуальной машины.",
                None,
            );
        }
    }
}

fn proxy_recovery_available() -> bool {
    crate::storage::default_path().ok().is_some_and(|settings| {
        let path = settings.with_file_name("proxy-recovery.json");
        let private = |metadata: std::fs::Metadata| {
            metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0
        };
        std::fs::symlink_metadata(&path)
            .is_ok_and(|metadata| metadata.is_file() && private(metadata))
            && path.parent().is_some_and(|parent| {
                std::fs::symlink_metadata(parent)
                    .is_ok_and(|metadata| metadata.is_dir() && private(metadata))
            })
    })
}

fn component(
    ctx: &Context,
    report: &mut Report,
    label: (&str, &str),
    path: Option<&Path>,
    argument: &str,
    expected: &str,
    prefix: bool,
) {
    let result = path.and_then(|path| {
        ctx.command(path, &[argument], Duration::from_secs(2), false)
            .ok()
    });
    let ok = result.as_ref().is_some_and(|o| {
        o.code == Some(0)
            && o.text.lines().next().is_some_and(|line| {
                if prefix {
                    line.starts_with(expected)
                } else {
                    line == expected
                }
            })
    });
    report.add(label.0, if ok { Status::Pass } else if ctx.stopped() || (path.is_some() && result.is_none()) { Status::Unknown } else { Status::Error }, label.1, if ok { "Компонент доступен, версия совпадает с приложением." } else { "Не подтверждено наличие и совместимая версия компонента. Проверка не устанавливает пакеты и не запускает подключение." }, "При несовпадении обновите приложение и его системные компоненты из одной сборки.", Some(Action::OpenSettings));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn target_route_needs_matching_evidence_before_calling_a_failed_lookup_blocked() {
        let ip: IpAddr = "192.0.2.123".parse().unwrap();
        let failed = super::super::https::Output {
            code: Some(2),
            text: String::new(),
        };
        let routes = Ok(json!([{ "type":"blackhole", "dst":"192.0.2.123/32", "table":"main" }]));
        assert_eq!(
            target_route_evidence(ip, Some(&failed), &routes).0,
            Status::Error
        );
        assert_eq!(
            target_route_evidence("192.0.2.124".parse().unwrap(), Some(&failed), &routes).0,
            Status::Unknown
        );
        assert_eq!(target_route_evidence(ip, None, &routes).0, Status::Unknown);
        let malformed = super::super::https::Output {
            code: Some(0),
            text: "unexpected output".into(),
        };
        assert_eq!(
            target_route_evidence(ip, Some(&malformed), &routes).0,
            Status::Unknown
        );
        let fakeip = super::super::https::Output {
            code: Some(0),
            text: json!([{ "dev":crate::platform::TUN_NAME, "dst":"198.18.1.1" }]).to_string(),
        };
        assert_eq!(
            target_route_evidence("198.18.1.1".parse().unwrap(), Some(&fakeip), &routes).0,
            Status::Pass
        );
        let mut request = Request {
            settings: Default::default(),
            connected: true,
            busy: false,
            network_tests: true,
            direct_test: false,
            address: None,
        };
        assert!(!target_kernel_allowed(&request));
        request.settings.mode = Mode::Tun;
        assert!(target_kernel_allowed(&request));
    }
    #[test]
    fn orphan_rules_and_invalid_selected_profile_are_reported_without_mutation() {
        let snapshot = Snapshot {
            links: vec![],
            routes4: Ok(json!([])),
            routes6: Ok(json!([])),
            rules4: Ok(json!([{"priority":9000,"table":2022}])),
            rules6: Ok(json!([])),
            dns: Ok(json!([])),
            domains: Ok(json!([])),
            nm_dns: Vec::new(),
            resolv: Ok(String::new()),
            resolv_link: None,
            dangling_resolv: false,
        };
        let mut request = Request {
            settings: Default::default(),
            connected: false,
            busy: false,
            network_tests: false,
            direct_test: false,
            address: None,
        };
        let mut report = Report::default();
        profile(&request, &snapshot, &mut report);
        assert!(report.findings.iter().any(|finding| finding.id == "policy"
            && finding.status == Status::Warning
            && finding.action == Some(Action::OpenRoutes)));
        request.busy = true;
        report.findings.clear();
        profile(&request, &snapshot, &mut report);
        assert!(!report.findings.iter().any(|finding| finding.id == "policy"));
        request.settings.selected_routing = usize::MAX;
        report.findings.clear();
        assert!(profile(&request, &snapshot, &mut report).is_none());
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.id == "profile" && finding.status == Status::Error)
        );
    }
    #[test]
    fn missing_bridge_dns_has_a_scoped_repair_but_custom_dns_does_not() {
        let nm =
            nm_dns("GENERAL.TYPE:bridge\nGENERAL.STATE:100 (connected)\nIP4.DNS[1]:192.168.0.1\n");
        let missing = runtime_dns(&json!([{ "ifname":"br0", "servers":null }]), "br0");
        let mut report = Report::default();
        dns_evidence("br0", &missing, &nm, true, &mut report);
        assert_eq!(report.findings[0].status, Status::Error);
        assert!(report.findings[0].detail.contains("192.168.0.1"));
        assert!(!report.sanitized_text().contains("192.168.0.1"));
        assert_eq!(
            report.findings[0].action,
            Some(Action::RestoreDns {
                interface: "br0".into()
            })
        );
        report.findings.clear();
        dns_evidence("br0", &missing, &nm, false, &mut report);
        assert!(report.findings[0].action.is_none());
        report.findings.clear();
        let custom = runtime_dns(
            &json!([{ "ifname":"br0", "servers":[{"addressString":"10.0.0.53"}] }]),
            "br0",
        );
        dns_evidence("br0", &custom, &nm, true, &mut report);
        assert_eq!(report.findings[0].status, Status::Warning);
        assert!(report.findings[0].action.is_none());
        report.findings.clear();
        dns_evidence("br0", &Err("unavailable".into()), &nm, true, &mut report);
        assert_eq!(report.findings[0].status, Status::Unknown);
        assert!(report.findings[0].action.is_none());
    }
    #[test]
    fn nm_candidate_is_only_active_physical_ipv4_dns() {
        let data = "GENERAL.TYPE:ethernet\nGENERAL.STATE:100 (connected)\nIP4.DNS[1]:192.0.2.53\n";
        assert_eq!(
            nm_dns(data).unwrap(),
            vec!["192.0.2.53".parse::<IpAddr>().unwrap()]
        );
        for invalid in [
            data.replace("100", "30"),
            data.replace("ethernet", "tun"),
            data.replace("192.0.2.53", "127.0.0.1"),
            data.replace("192.0.2.53", "198.18.0.8"),
            data.replace("192.0.2.53", "255.255.255.255"),
            data.replace("192.0.2.53", "2001:db8::1"),
        ] {
            assert!(nm_dns(&invalid).is_err());
        }
    }
    #[test]
    fn unavailable_dns_is_not_treated_as_empty() {
        assert!(runtime_dns(&json!([]), "eth0").is_err());
        assert!(runtime_dns(&json!([{ "ifname":"eth0" }]), "eth0").is_err());
        assert!(runtime_dns(&json!([{ "ifname":"eth0", "servers":"unknown" }]), "eth0").is_err());
        assert!(
            runtime_dns(&json!([{ "ifname":"eth0", "servers":null }]), "eth0")
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            runtime_dns(&json!([{ "ifname":"eth0", "servers":[] }]), "eth0").unwrap(),
            Vec::<IpAddr>::new()
        );
        assert!(runtime_dns(&json!([{ "ifname":"eth0", "servers":[{"addressString":"192.0.2.53", "port":853, "accessible":false}] }]), "eth0").is_err());
    }
    #[test]
    fn blocked_default_does_not_count_as_connectivity() {
        assert!(!default_route(
            &json!({"dst":"default", "type":"blackhole"})
        ));
        assert!(blocked(&json!({"action":"prohibit"})));
        assert!(default_route(&json!({"dst":"default", "dev":"eth0"})));
    }
    #[test]
    fn absent_ipv6_default_is_not_a_fault() {
        let snapshot = Snapshot {
            links: vec![],
            routes4: Ok(json!([{ "dst":"default", "dev":"eth0" }])),
            routes6: Ok(json!([])),
            rules4: Ok(json!([])),
            rules6: Ok(json!([])),
            dns: Ok(json!([])),
            domains: Ok(json!([])),
            nm_dns: Vec::new(),
            resolv: Ok(String::new()),
            resolv_link: None,
            dangling_resolv: false,
        };
        let mut report = Report::default();
        network(&snapshot, &mut report);
        assert_eq!(
            report
                .findings
                .iter()
                .find(|f| f.id == "routes6")
                .unwrap()
                .status,
            Status::Unknown
        );
        assert_eq!(
            report
                .findings
                .iter()
                .find(|f| f.id == "routes4")
                .unwrap()
                .status,
            Status::Pass
        );
    }
}
