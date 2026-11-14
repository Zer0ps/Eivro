use super::Status;
use crate::{Result, routing::Rule};
use std::net::IpAddr;

pub(super) struct Output {
    pub code: Option<i32>,
    pub text: String,
}
pub(crate) fn synthetic(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let o = ip.octets();
            o[0] == 198 && matches!(o[1], 18 | 19)
        }
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or_else(
            || ip.segments()[..3] == [0x2001, 2, 0],
            |v| synthetic(IpAddr::V4(v)),
        ),
    }
}
pub(super) fn target(input: &str) -> Result<String> {
    let value = input.trim();
    if value.is_empty() || value.len() > 253 || value.chars().any(char::is_control) {
        return Err("Нужен точный домен или IP.".into());
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        if probe_address(ip) {
            return Ok(ip.to_string());
        }
        return Err("Нужен реальный адрес вне loopback и служебных диапазонов.".into());
    }
    match Rule::parse(value)? {
        Rule::Exact(host) => {
            if host.parse::<IpAddr>().is_ok_and(|ip| !probe_address(ip)) {
                return Err("Нужен реальный адрес вне loopback и служебных диапазонов.".into());
            }
            Ok(host)
        }
        _ => Err("Нужен точный домен без URL, маски и wildcard.".into()),
    }
}

pub(super) fn probe_address(ip: IpAddr) -> bool {
    if let IpAddr::V6(v) = ip
        && let Some(v) = v.to_ipv4_mapped()
    {
        return probe_address(IpAddr::V4(v));
    }
    !ip.is_loopback()
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !matches!(ip, IpAddr::V4(ip) if ip.is_broadcast() || ip.is_link_local() || ip.octets()[0] == 0 || ip.octets()[0] >= 240)
        && !matches!(ip, IpAddr::V6(ip) if ip.is_unicast_link_local())
        && !synthetic(ip)
        && ![
            "172.31.250.1",
            "172.31.250.2",
            "fdfe:5645:4c55::1",
            "fdfe:5645:4c55::2",
        ]
        .iter()
        .any(|s| s.parse::<IpAddr>() == Ok(ip))
}

pub(super) fn curl_arguments(
    host: &str,
    proxy: Option<u16>,
    interface: Option<&str>,
    address: Option<IpAddr>,
) -> Vec<String> {
    // --disable must be first: no ~/.curlrc, credentials, redirects or user proxy env.
    let mut args: Vec<String> = [
        "--disable",
        "--silent",
        "--head",
        "--globoff",
        "--proto",
        "=https",
        "--connect-timeout",
        "3",
        "--max-time",
        "6",
        "--max-redirs",
        "0",
        "--output",
        if cfg!(windows) { "NUL" } else { "/dev/null" },
        "--write-out",
        "%{http_code} %{remote_ip}",
        "--user-agent",
        "Eivro diagnostic",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    if let Some(port) = proxy {
        args.extend([
            "--proxy".into(),
            format!("http://127.0.0.1:{port}"),
            "--noproxy".into(),
            "".into(),
        ]);
    } else {
        args.extend(["--proxy".into(), "".into(), "--noproxy".into(), "*".into()]);
    }
    if let Some(interface) = interface {
        args.extend(["--interface".into(), format!("if!{interface}")]);
    }
    if let Some(address) = address {
        args.push(
            if address.is_ipv4() {
                "--ipv4"
            } else {
                "--ipv6"
            }
            .into(),
        );
        if host.parse::<IpAddr>().is_err() {
            args.extend([
                "--resolve".into(),
                format!(
                    "{host}:443:{}",
                    if address.is_ipv6() {
                        format!("[{address}]")
                    } else {
                        address.to_string()
                    }
                ),
            ]);
        }
    }
    let authority = match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{host}]"),
        _ => host.into(),
    };
    args.extend(["--url".into(), format!("https://{authority}/")]);
    args
}

pub(super) fn classify(output: &Output, proxy: bool, system_tun: bool) -> (Status, &'static str) {
    match output.code {
        Some(0) => {
            let mut fields = output.text.split_whitespace();
            let code = fields.next().and_then(|s| s.parse::<u16>().ok());
            let remote = fields.next().and_then(|s| s.parse::<IpAddr>().ok());
            if !proxy
                && !remote.is_some_and(|ip| probe_address(ip) || (system_tun && synthetic(ip)))
            {
                return (
                    Status::Warning,
                    "HTTPS завершился на локальном или служебном адресе; доступность внешней сети не подтверждена.",
                );
            }
            match code {
                Some(200..=299) => (
                    Status::Pass,
                    "Получен успешный HTTPS-ответ с проверенным TLS-сертификатом.",
                ),
                Some(300..=399) => (
                    Status::Warning,
                    "TLS установлен, сервер вернул перенаправление. Переход не выполнялся; конечная страница не проверена.",
                ),
                Some(400..=599) => (
                    Status::Warning,
                    "TLS установлен, но сервер вернул HTTP-ошибку. Это не доказывает сбой сети или неверный ключ VPN.",
                ),
                _ => (Status::Unknown, "HTTPS не вернул распознаваемый статус."),
            }
        }
        Some(5) => (Status::Error, "Не разрешён адрес прокси."),
        Some(6) => (Status::Error, "Не разрешено имя назначения."),
        Some(7) => (
            Status::Error,
            "Не удалось установить TCP-соединение на выбранном пути.",
        ),
        Some(28) => (
            Status::Warning,
            "Истёк срок DNS, TCP или TLS; точный этап не подтверждён.",
        ),
        Some(35) => (
            Status::Error,
            "Не завершено TLS-рукопожатие. Причина блокировки или ошибка ключа не установлены.",
        ),
        Some(60 | 51) => (
            Status::Error,
            "TLS-сертификат не прошёл проверку. Проверьте часы системы, доверенные сертификаты и адрес.",
        ),
        Some(97) => (Status::Error, "Прокси отклонил установку туннеля."),
        Some(52 | 56) => (
            Status::Warning,
            "Соединение закрыто или сброшено без полноценного HTTPS-ответа; причина неизвестна.",
        ),
        Some(45) => (
            Status::Unknown,
            "Не удалось привязать проверку к физическому интерфейсу; обходной запрос не выполнен.",
        ),
        _ => (
            Status::Unknown,
            "Сетевая проверка не завершена; нет достаточных данных для определения причины.",
        ),
    }
}
