//! Explicit, read-only troubleshooting. Nothing is logged or saved by this module.
use crate::storage::Settings;
use std::sync::{Arc, atomic::AtomicBool};

#[cfg(target_os = "linux")]
mod analysis;
#[cfg(target_os = "linux")]
mod environment;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod probe;
#[cfg(target_os = "linux")]
pub mod repair;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Pass,
    Warning,
    Error,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    FlushDns,
    RecoverProxy,
    Reconnect,
    OpenRoutes,
    OpenSettings,
    RestoreDns { interface: String },
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub id: String,
    pub status: Status,
    pub title: String,
    pub detail: String,
    pub advice: String,
    pub action: Option<Action>,
}

#[derive(Clone, Debug, Default)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub cancelled: bool,
    pub network_fingerprint: String,
}

impl Report {
    /// Export an allowlisted summary, never a best-effort scrub of local evidence.
    /// Even a malicious hostname/profile name cannot enter this output.
    pub fn sanitized_text(&self) -> String {
        let mut text = format!(
            "Eivro {} — диагностика без сетевых адресов\n",
            env!("CARGO_PKG_VERSION")
        );
        for finding in &self.findings {
            let label = match finding.id.as_str() {
                "uplink" => "Физическое подключение",
                "routes4" => "Маршруты IPv4",
                "routes6" => "Маршруты IPv6",
                "policy" => "Политики ядра",
                "resolver" => "Системный DNS",
                "nm_dns" => "DNS активного подключения",
                "dns_route" => "Маршрут к DNS",
                "target_route" => "Маршрут проблемного адреса",
                "settings_file" => "Сохранённые настройки",
                "subscription" => "Последние данные подписки",
                "firewall" => "Область проверки сетевого фильтра",
                "endpoint" => "Адрес сервера VPN",
                "endpoint_route" => "Маршрут к серверу VPN",
                "fakeip" => "Виртуальный адрес сервера VPN",
                "profile" => "Профиль Eivro",
                "exit" => "Сетевой выход",
                "rule" => "Правила выбранного адреса",
                "proxy_port" => "Локальный прокси",
                "system_proxy" => "Системный прокси",
                "core" => "Ядро",
                "helper" => "Помощник TUN",
                "xray" => "Ядро Xray",
                "dns_probe" => "Проверка разрешения имени",
                "https" => "Проверка HTTPS",
                "direct" => "Проверка физического выхода",
                "scope" => "Область проверки",
                "state" => "Состояние диагностики",
                _ => "Дополнительная проверка",
            };
            let status = match finding.status {
                Status::Pass => "OK",
                Status::Warning => "Внимание",
                Status::Error => "Ошибка",
                Status::Unknown => "Не проверено",
            };
            text.push_str(&format!("[{status}] {label}\n"));
        }
        if self.cancelled {
            text.push_str("Проверка отменена; результаты неполные.\n");
        }
        text.push_str(
            "Детали, адреса, интерфейсы, имена профилей и параметры доступа исключены.\n",
        );
        text
    }

    pub(super) fn add(
        &mut self,
        id: &str,
        status: Status,
        title: &str,
        detail: impl Into<String>,
        advice: &str,
        action: Option<Action>,
    ) {
        self.findings.push(Finding {
            id: id.into(),
            status,
            title: title.into(),
            detail: detail.into(),
            advice: advice.into(),
            action,
        });
    }
}

#[derive(Clone)]
pub struct Request {
    pub settings: Settings,
    pub connected: bool,
    pub busy: bool,
    pub network_tests: bool,
    pub direct_test: bool,
    pub address: Option<String>,
}

pub fn run(request: Request, cancel: Arc<AtomicBool>, progress: impl Fn(&str)) -> Report {
    #[cfg(target_os = "linux")]
    {
        linux::run(request, cancel, progress)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (request, cancel, progress);
        let mut report = Report::default();
        report.add(
            "scope",
            Status::Unknown,
            "Диагностика Linux",
            "Глубокая диагностика пока доступна только в Linux.",
            "Используйте штатные средства диагностики системы.",
            None,
        );
        report
    }
}

pub fn fingerprint() -> crate::Result<String> {
    #[cfg(target_os = "linux")]
    {
        linux::fingerprint()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("Диагностика доступна только в Linux.".into())
    }
}

pub fn fingerprint_cancelled(cancel: Arc<AtomicBool>) -> crate::Result<String> {
    #[cfg(target_os = "linux")]
    {
        linux::fingerprint_cancelled(cancel)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cancel;
        Err("Диагностика доступна только в Linux.".into())
    }
}

#[cfg(target_os = "linux")]
pub fn restore_dns_candidate(interface: &str) -> crate::Result<Vec<std::net::IpAddr>> {
    linux::restore_dns_candidate(interface)
}

#[cfg(target_os = "linux")]
pub(crate) fn runtime_dns(interface: &str) -> crate::Result<Vec<std::net::IpAddr>> {
    linux::runtime_dns(interface)
}

#[cfg(target_os = "linux")]
pub(crate) fn dns_repair_interface_allowed(interface: &str) -> crate::Result<()> {
    linux::dns_repair_interface_allowed(interface)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn export_never_copies_any_local_evidence_or_dynamic_id() {
        let secret = "client-secret vpn.corp.test 192.0.2.8 2001:db8::1 eth-secret";
        let mut report = Report {
            network_fingerprint: secret.into(),
            ..Default::default()
        };
        report.add(
            secret,
            Status::Error,
            secret,
            secret,
            secret,
            Some(Action::RestoreDns {
                interface: secret.into(),
            }),
        );
        report.add("resolver", Status::Warning, secret, secret, secret, None);
        let text = report.sanitized_text();
        for token in secret.split_whitespace() {
            assert!(!text.contains(token));
        }
        assert!(text.contains("Системный DNS"));
    }
}
