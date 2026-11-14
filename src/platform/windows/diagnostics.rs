use crate::{
    config::Mode,
    diagnostics::{Report, Request, Status},
};
pub(crate) fn inspect(request: &Request, report: &mut Report) {
    if let Ok(links) = super::network::adapters(false, true) {
        let tunnel = links
            .iter()
            .any(|l| l.up && l.name.eq_ignore_ascii_case(crate::platform::TUN_NAME));
        let active = request.connected && request.settings.mode == Mode::Tun;
        if active || tunnel {
            report.add(
                "tun",
                if active == tunnel {
                    Status::Pass
                } else {
                    Status::Warning
                },
                "Адаптер TUN Windows",
                match (active, tunnel) {
                    (true, true) => "Система видит активный адаптер Eivro.",
                    (true, false) => "При активном сеансе система не обнаружила адаптер Eivro.",
                    _ => "Windows видит активный адаптер Eivro после отключения сеанса.",
                },
                "",
                None,
            );
        }
        let dns = links.iter().filter(|l| l.up).any(|l| !l.dns.is_empty());
        report.add(
            "resolver",
            if dns { Status::Pass } else { Status::Unknown },
            "DNS активных адаптеров",
            if dns {
                "IP Helper вернул DNS-серверы активного подключения."
            } else {
                "У активных адаптеров отсутствуют сведения о DNS."
            },
            "",
            None,
        );
    }
    if request.connected && request.settings.mode == Mode::Proxy {
        let (status, detail) = match crate::system_proxy::active_for(request.settings.port) {
            Ok(true) => (Status::Pass, "WinINET использует адреса прокси Eivro."),
            Ok(false) => (
                Status::Warning,
                "Настройки WinINET изменились после подключения.",
            ),
            Err(_) => (
                Status::Unknown,
                "Не удалось прочитать настройки WinINET текущего пользователя.",
            ),
        };
        report.add(
            "system_proxy",
            status,
            "Системный прокси Windows",
            detail,
            "",
            None,
        );
    }
    if let Some(ip) = request.address.as_deref().and_then(|s| s.parse().ok()) {
        let detail = match super::network::uplink(ip) {
            Ok(name) => format!("Windows выбрала интерфейс {name}."),
            Err(_) => {
                report.add(
                    "target_route",
                    Status::Unknown,
                    "Маршрут Windows",
                    "Внешний интерфейс для адреса не определён. Маршрут может использовать TUN.",
                    "",
                    None,
                );
                return;
            }
        };
        report.add(
            "target_route",
            Status::Pass,
            "Маршрут Windows",
            detail,
            "",
            None,
        );
    }
}
