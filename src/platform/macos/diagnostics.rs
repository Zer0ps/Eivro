//! Effective macOS settings read from SystemConfiguration when the user runs a check.
use crate::{
    config::Mode,
    diagnostics::{Report, Request, Status},
};
use serde::Deserialize;

#[derive(Default, Deserialize)]
pub(super) struct NetworkState {
    uplink: Option<String>,
    scoped_interface: Option<String>,
    dns_count: Option<usize>,
    tun_dns: Option<bool>,
    tun_present: bool,
    proxy_enabled: Option<bool>,
    proxy_local: Option<bool>,
}

pub(crate) fn inspect(request: &Request, report: &mut Report) {
    let target = request.address.as_deref().and_then(|s| {
        if let Ok(crate::routing::Rule::Exact(host)) = crate::routing::Rule::parse(s) {
            Some(host)
        } else {
            None
        }
    });
    match super::native::diagnostic_settings(request.settings.port, target.as_deref()) {
        Ok(state) => {
            state.inspect(request.connected.then_some(request.settings.mode), report);
            if let Some(host) = target
                && let Some(profile) = request
                    .settings
                    .routing_profiles
                    .get(request.settings.selected_routing)
                && let crate::policy::Action::Connection(id) = profile.matches(&host)
                && let Some(exit) = request
                    .settings
                    .connections
                    .iter()
                    .find(|exit| exit.id == id)
            {
                state.inspect_scope(&exit.interface, report);
            }
        }
        Err(_) => report.add(
            "scope",
            Status::Unknown,
            "Сетевые настройки macOS недоступны",
            "SystemConfiguration не вернула снимок сети.",
            "Повторите проверку после смены подключения.",
            None,
        ),
    }
}

impl NetworkState {
    fn inspect_scope(&self, expected: &str, report: &mut Report) {
        let (status, detail) = match self.scoped_interface.as_deref() {
            Some(interface) if interface == expected => (
                Status::Pass,
                "Самая точная область DNS сетевого сервиса совпадает с интерфейсом правила.",
            ),
            Some(_) => (
                Status::Unknown,
                "macOS указывает другой сервис DNS для этого домена. Eivro может отдельно направлять запросы на DNS выбранного выхода.",
            ),
            None => (
                Status::Unknown,
                "Для домена нет однозначного совпадения области DNS сетевого сервиса macOS.",
            ),
        };
        report.add(
            "dns_route",
            status,
            "Область DNS для домена",
            detail,
            "",
            None,
        );
    }

    fn inspect(&self, mode: Option<Mode>, report: &mut Report) {
        match &self.uplink {
            Some(name) => report.add(
                "uplink",
                Status::Pass,
                "Основное подключение macOS",
                format!("Активный интерфейс: {name}."),
                "",
                None,
            ),
            None => report.add(
                "uplink",
                Status::Unknown,
                "Основной интерфейс не определён",
                "В SystemConfiguration отсутствует выбранное подключение IPv4/IPv6.",
                "Проверьте состояние сети в системных настройках.",
                None,
            ),
        }
        // Presence of a utun with our usual name does not establish ownership.
        // Only compare with a session the caller knows is running.
        if mode == Some(Mode::Tun) && !self.tun_present {
            report.add(
                "uplink",
                Status::Error,
                "Туннель Eivro отсутствует",
                "Сеанс TUN активен, но macOS не видит его сетевой интерфейс.",
                "Повторно подключите Eivro.",
                None,
            );
        }
        let (status, text) = match (self.tun_dns, self.dns_count, mode) {
            (Some(true), _, Some(Mode::Tun)) => {
                (Status::Pass, "Основной сервис использует DNS туннеля.")
            }
            (Some(true), _, _) if !self.tun_present => (
                Status::Error,
                "Основной сервис указывает на DNS Eivro при отсутствующем интерфейсе туннеля.",
            ),
            (Some(false), _, Some(Mode::Tun)) => (
                Status::Warning,
                "Основной сервис использует другие DNS при работающем TUN. Проверьте также настройки другого VPN.",
            ),
            (_, Some(n), _) if n > 0 => {
                (Status::Pass, "У основного сетевого сервиса настроен DNS.")
            }
            _ => (
                Status::Unknown,
                "Основной сервис не сообщает адреса DNS. У macOS могут быть отдельные DNS для приложений и VPN.",
            ),
        };
        report.add(
            "resolver",
            status,
            "DNS основного подключения",
            text,
            "",
            None,
        );
        let (status, text) = match (self.proxy_enabled, self.proxy_local, mode) {
            (_, None, _) => (
                Status::Unknown,
                "Не удалось получить активные параметры прокси.",
            ),
            (_, Some(true), Some(Mode::Proxy)) => (
                Status::Pass,
                "HTTP, HTTPS и SOCKS направлены на порт Eivro.",
            ),
            (_, Some(false), Some(Mode::Proxy)) => (
                Status::Warning,
                "Активный системный прокси отличается от порта Eivro. Проверьте настройки сети и другого прокси.",
            ),
            (_, Some(true), _) => (
                Status::Warning,
                "Системный прокси указывает на локальный порт Eivro вне режима «Прокси». Проверьте, какая программа использует порт.",
            ),
            (Some(true), _, _) => (
                Status::Unknown,
                "Включён другой системный прокси или автоматическая настройка прокси.",
            ),
            _ => (Status::Pass, "Системный прокси выключен."),
        };
        report.add(
            "system_proxy",
            status,
            "Системный прокси macOS",
            text,
            "",
            None,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corporate_resolver_evidence_is_tied_to_the_selected_exit() {
        let state = NetworkState {
            scoped_interface: Some("utun8".into()),
            ..Default::default()
        };
        for (interface, status) in [("utun8", Status::Pass), ("en0", Status::Unknown)] {
            let mut report = Report::default();
            state.inspect_scope(interface, &mut report);
            assert_eq!(report.findings[0].status, status);
            assert!(report.findings[0].action.is_none());
        }
    }

    #[test]
    fn detects_mismatch_and_preserves_uncertainty_for_scoped_resolvers() {
        let mut state = NetworkState {
            uplink: Some("en0".into()),
            scoped_interface: None,
            dns_count: Some(1),
            tun_dns: Some(true),
            tun_present: false,
            proxy_enabled: Some(true),
            proxy_local: Some(false),
        };
        let mut report = Report::default();
        state.inspect(Some(Mode::Proxy), &mut report);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.id == "resolver" && f.status == Status::Error)
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.id == "system_proxy" && f.status == Status::Warning)
        );
        state.tun_dns = None;
        state.dns_count = None;
        state.tun_present = true;
        let mut report = Report::default();
        state.inspect(Some(Mode::Tun), &mut report);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.id == "resolver" && f.status == Status::Unknown)
        );
        assert!(!report.findings.iter().any(|f| f.status == Status::Error));
    }
}
