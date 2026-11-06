//! Read-only evidence about persisted configuration and local filter coverage.
use super::{Report, Request, Status, linux::Context};
use serde_json::Value;
use std::{fs, os::unix::fs::MetadataExt, path::Path};

#[derive(Debug, PartialEq, Eq)]
enum DiskState {
    Missing,
    Unavailable,
    Unsafe,
    Invalid,
    Valid,
}

fn disk_state(path: &Path) -> DiskState {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return DiskState::Missing,
        Err(_) => return DiskState::Unavailable,
    };
    // Avoid opening symlinks and special files. load() independently rechecks
    // ownership, permissions, size and schema on its actual file descriptor.
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return DiskState::Unsafe;
    }
    if metadata.len() > 16 * 1024 * 1024 {
        return DiskState::Invalid;
    }
    match crate::storage::load(path) {
        Ok(_) => DiskState::Valid,
        Err(_) => DiskState::Invalid,
    }
}

fn disk_finding(state: DiskState, report: &mut Report) {
    let (status, detail) = match state {
        DiskState::Missing => (
            Status::Unknown,
            "Файл настроек ещё не существует. Настройки в памяти не подтверждают наличие сохранённой конфигурации.",
        ),
        DiskState::Unavailable => (
            Status::Unknown,
            "Не удалось прочитать сведения о файле настроек. Его содержимое и возможность загрузки не подтверждены.",
        ),
        DiskState::Unsafe => (
            Status::Error,
            "Файл настроек не является обычным частным файлом текущего пользователя: возможны ссылка, чужой владелец или доступ других пользователей.",
        ),
        DiskState::Invalid => (
            Status::Error,
            "Файл настроек не удалось безопасно загрузить: возможны ошибка чтения, повреждение JSON, неподдерживаемая схема или несогласованные параметры. Файл не изменялся.",
        ),
        DiskState::Valid => (
            Status::Pass,
            "Сохранённый файл настроек прочитан и прошёл штатную проверку приватности, формата и согласованности. Изменения из памяти не сохранялись.",
        ),
    };
    report.add("settings_file", status, "Сохранённые настройки", detail, "При ошибке сохраните резервную копию и проверьте файл и его права вручную; диагностика ничего не переписывает.", None);
}

#[derive(Debug, PartialEq, Eq)]
struct Limits {
    expired: Option<bool>,
    exhausted: Option<bool>,
}
fn limits(metadata: &crate::catalog::Metadata, now: u64) -> Limits {
    Limits {
        expired: metadata
            .expires
            .filter(|expires| *expires > 0)
            .map(|expires| expires <= now),
        exhausted: metadata.total.filter(|total| *total > 0).and_then(|total| {
            Some(u128::from(metadata.upload?) + u128::from(metadata.download?) >= u128::from(total))
        }),
    }
}

fn subscription(request: &Request, report: &mut Report) {
    let Some(subscription) = request.settings.current() else {
        return;
    };
    let limits = limits(&subscription.metadata, crate::catalog::now());
    let warning = limits.expired == Some(true) || limits.exhausted == Some(true);
    let known = limits.expired.is_some() || limits.exhausted.is_some();
    let expiration = match limits.expired {
        Some(true) => "сохранённый срок подписки истёк",
        Some(false) => "сохранённый срок подписки ещё не истёк",
        None => "срок неизвестен",
    };
    let quota = match limits.exhausted {
        Some(true) => "сохранённая квота исчерпана",
        Some(false) => "сохранённая квота не исчерпана",
        None => "остаток квоты неизвестен",
    };
    report.add("subscription", if warning { Status::Warning } else if known { Status::Pass } else { Status::Unknown }, "Последние данные поставщика подписки", format!("{expiration}; {quota}. Это последние сохранённые данные поставщика, которые могли устареть; они не доказывают действительность или недействительность ключа."), "Сверьте срок и трафик с поставщиком или обновите подписку вручную. Диагностика не обращалась к её адресу.", None);
}

#[derive(Debug, PartialEq, Eq)]
enum GuardState {
    Unknown,
    Absent,
    Foreign,
    Owned,
}
fn guard_state(value: &Value, require_owner: bool) -> GuardState {
    let Some(rows) = value["nftables"].as_array() else {
        return GuardState::Unknown;
    };
    let table = rows
        .iter()
        .find(|row| row["table"]["family"] == "inet" && row["table"]["name"] == "velum_guard");
    match table {
        None => GuardState::Absent,
        Some(row) if row["table"]["comment"] == "Velum connection guard v1" => GuardState::Owned,
        Some(_) if require_owner => GuardState::Foreign,
        Some(_) => GuardState::Unknown,
    }
}

fn firewall(ctx: &Context, request: &Request, report: &mut Report) {
    let list = ctx
        .system("nft", &["-j", "list", "tables"])
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok());
    let state = match list {
        Some(value) if guard_state(&value, false) == GuardState::Absent => GuardState::Absent,
        Some(value)
            if value["nftables"].as_array().is_some_and(|rows| {
                rows.iter().any(|row| {
                    row["table"]["family"] == "inet" && row["table"]["name"] == "velum_guard"
                })
            }) =>
        {
            ctx.system("nft", &["-j", "list", "table", "inet", "velum_guard"])
                .ok()
                .and_then(|text| serde_json::from_str::<Value>(&text).ok())
                .map_or(GuardState::Unknown, |value| guard_state(&value, true))
        }
        _ => GuardState::Unknown,
    };
    let expected = request.connected && request.settings.kill_switch;
    let (status, detail) = match state {
        GuardState::Owned if !expected && !request.busy => (
            Status::Warning,
            "Таблица с меткой защиты Eivro присутствует, хотя приложение отключено или kill switch выключен. Возможен другой владелец соединения или остаточное состояние; правила не изменялись.",
        ),
        GuardState::Absent if expected && !request.busy => (
            Status::Warning,
            "При включённом kill switch и подключённом Eivro его таблица защиты не найдена. Фактическая защита от утечки не подтверждена.",
        ),
        GuardState::Owned => (
            Status::Unknown,
            "Таблица с меткой защиты Eivro видна. Её присутствие не подтверждает полноту правил или отсутствие фильтрации другими таблицами.",
        ),
        GuardState::Absent => (
            Status::Unknown,
            "Таблица защиты Eivro отсутствует. Влияние остальных правил nftables, iptables, eBPF и сетевого оборудования не проверялось.",
        ),
        GuardState::Foreign => (
            Status::Warning,
            "Имя таблицы защиты Eivro занято без ожидаемой метки владельца. Эти правила считаются чужими; они не изменялись.",
        ),
        GuardState::Unknown => (
            Status::Unknown,
            "Правила nftables недоступны текущему пользователю, утилита отсутствует или чтение не завершилось. Влияние сетевого фильтра неизвестно; повышение прав не запрашивалось.",
        ),
    };
    report.add("firewall", status, "Область проверки сетевого фильтра", detail, "При подозрении на фильтрацию проверьте правила и их владельца штатными средствами системы. Диагностика не отключает защиту и не удаляет правила.", None);
}

pub(super) fn check(ctx: &Context, request: &Request, report: &mut Report) {
    let state =
        crate::storage::default_path().map_or(DiskState::Unavailable, |path| disk_state(&path));
    disk_finding(state, report);
    subscription(request, report);
    if !ctx.stopped() {
        firewall(ctx, request, report);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn disk_fixture_distinguishes_missing_invalid_and_unsafe_without_exporting_contents() {
        let directory = std::env::temp_dir().join(format!(
            "eivro-diagnostic-settings-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("settings.json");
        assert_eq!(disk_state(&path), DiskState::Missing);
        fs::write(
            &path,
            serde_json::to_vec(&crate::storage::Settings::default()).unwrap(),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(disk_state(&path), DiskState::Valid);
        fs::write(&path, b"broken-secret-vpn.example.test").unwrap();
        let mut report = Report::default();
        assert_eq!(disk_state(&path), DiskState::Invalid);
        disk_finding(disk_state(&path), &mut report);
        assert!(!report.findings[0].detail.contains("broken-secret"));
        assert!(!report.sanitized_text().contains("vpn.example.test"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(disk_state(&path), DiskState::Unsafe);
        let link = directory.join("link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(disk_state(&link), DiskState::Unsafe);
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn provider_limits_require_complete_counters_and_handle_large_values() {
        let mut metadata = crate::catalog::Metadata {
            expires: Some(100),
            total: Some(1000),
            upload: Some(800),
            download: Some(200),
            ..Default::default()
        };
        assert_eq!(
            limits(&metadata, 100),
            Limits {
                expired: Some(true),
                exhausted: Some(true)
            }
        );
        metadata.download = None;
        assert_eq!(limits(&metadata, 99).exhausted, None);
        metadata.download = Some(u64::MAX);
        metadata.upload = Some(u64::MAX);
        metadata.total = Some(u64::MAX);
        assert_eq!(limits(&metadata, 99).exhausted, Some(true));
        assert_eq!(
            limits(&Default::default(), 100),
            Limits {
                expired: None,
                exhausted: None
            }
        );
    }
    #[test]
    fn firewall_ownership_requires_exact_table_and_owner_marker() {
        assert_eq!(guard_state(&json!({}), true), GuardState::Unknown);
        assert_eq!(
            guard_state(&json!({"nftables":[]}), true),
            GuardState::Absent
        );
        assert_eq!(
            guard_state(
                &json!({"nftables":[{"table":{"family":"inet","name":"velum_guard","comment":"other owner"}}]}),
                true
            ),
            GuardState::Foreign
        );
        assert_eq!(
            guard_state(
                &json!({"nftables":[{"table":{"family":"inet","name":"velum_guard","comment":"Velum connection guard v1"}}]}),
                true
            ),
            GuardState::Owned
        );
        assert_eq!(
            guard_state(
                &json!({"nftables":[{"table":{"family":"ip","name":"velum_guard","comment":"Velum connection guard v1"}}]}),
                true
            ),
            GuardState::Absent
        );
    }
}
