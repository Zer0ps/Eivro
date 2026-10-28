use crate::{
    Result,
    config::Mode,
    import::{Profile, parse_uri},
    routing::parse_rules,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    #[default]
    Dark,
    Light,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub schema: u32,
    #[serde(skip_serializing)]
    pub profiles: Vec<Profile>,
    #[serde(skip_serializing)]
    pub selected: usize,
    pub subscriptions: Vec<crate::catalog::Subscription>,
    pub selected_subscription: usize,
    pub next_subscription_id: u64,
    #[serde(skip_serializing)]
    pub bypass: Vec<String>,
    pub routing_profiles: Vec<crate::policy::RoutingProfile>,
    pub selected_routing: usize,
    pub reconnect: bool,
    pub close_to_tray: bool,
    pub autoconnect: bool,
    pub kill_switch: bool,
    pub theme: Theme,
    pub accent: [u8; 3],
    pub mode: Mode,
    pub port: u16,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            schema: 3,
            routing_profiles: vec![Default::default()],
            selected_routing: 0,
            reconnect: true,
            close_to_tray: true,
            autoconnect: false,
            kill_switch: false,
            subscriptions: Vec::new(),
            selected_subscription: 0,
            next_subscription_id: 1,
            profiles: Vec::new(),
            selected: 0,
            bypass: Vec::new(),
            theme: Theme::Dark,
            accent: [151, 223, 190],
            mode: Mode::Proxy,
            port: 2080,
        }
    }
}

impl Settings {
    pub fn migrate(&mut self) -> Result<()> {
        if !(1..=3).contains(&self.schema) {
            return Err("Версия настроек не поддерживается.".into());
        }
        if !self.profiles.is_empty() {
            if !self.subscriptions.is_empty() {
                return Err("Смешаны форматы настроек.".into());
            }
            if self.selected >= self.profiles.len() {
                return Err("Некорректный выбранный сервер.".into());
            }
            self.subscriptions.push(crate::catalog::Subscription {
                id: 1,
                name: "Импортированные".into(),
                source: None,
                profiles: std::mem::take(&mut self.profiles),
                selected: self.selected,
                metadata: Default::default(),
                update: crate::catalog::UpdatePolicy::Manual,
                refreshed_at: None,
            });
            self.selected = 0;
            self.selected_subscription = 0;
            self.next_subscription_id = 2;
        }
        if self.schema < 3 {
            self.routing_profiles = vec![crate::policy::RoutingProfile {
                name: "Обычный".into(),
                rules: self
                    .bypass
                    .iter()
                    .map(|s| {
                        Ok(crate::policy::PolicyRule {
                            enabled: true,
                            target: crate::policy::Target::address(s)?,
                            action: crate::policy::Action::Direct,
                        })
                    })
                    .collect::<Result<_>>()?,
            }];
            self.bypass.clear();
            self.selected_routing = 0;
        }
        self.schema = 3;
        self.validate()
    }
    pub fn current(&self) -> Option<&crate::catalog::Subscription> {
        self.subscriptions.get(self.selected_subscription)
    }
    pub fn current_mut(&mut self) -> Option<&mut crate::catalog::Subscription> {
        self.subscriptions.get_mut(self.selected_subscription)
    }
    pub fn selected_profile(&self) -> Option<&Profile> {
        self.current()?.selected_profile()
    }
    pub fn apply_document(
        &mut self,
        target: Option<u64>,
        document: crate::catalog::Document,
    ) -> Result<()> {
        if document.profiles.is_empty() {
            return Err("В обновлении нет серверов; прежний список сохранён.".into());
        }
        let mut next = self.clone();
        let existing = match target {
            Some(id) => Some(
                next.subscriptions
                    .iter()
                    .position(|s| s.id == id)
                    .ok_or("Подписка уже удалена.")?,
            ),
            None => document.source.as_ref().and_then(|url| {
                next.subscriptions
                    .iter()
                    .position(|s| s.source.as_ref() == Some(url))
            }),
        };
        if let Some(index) = existing {
            next.subscriptions[index].replace(document, crate::catalog::now());
        } else {
            let id = next.next_subscription_id;
            next.next_subscription_id = id.checked_add(1).ok_or("Нет идентификатора подписки.")?;
            next.subscriptions.push(document.into_subscription(id));
            if next.subscriptions.len() == 1 {
                next.selected_subscription = 0;
            }
        }
        next.validate()?;
        *self = next;
        Ok(())
    }
    pub fn validate(&self) -> Result<()> {
        if self.schema != 3 {
            return Err("Версия настроек не поддерживается.".into());
        }
        if self.subscriptions.len() > 32
            || self
                .subscriptions
                .iter()
                .map(|s| s.profiles.len())
                .sum::<usize>()
                > 2048
        {
            return Err("Максимум 32 подписки и 2048 серверов.".into());
        }
        if self.port < 1024 {
            return Err("Локальный порт должен быть не меньше 1024.".into());
        }
        parse_rules(&self.bypass)?;
        if !self.bypass.is_empty() {
            return Err("Старые исключения требуют миграции в профиль.".into());
        }
        crate::policy::validate_profiles(&self.routing_profiles, self.selected_routing)?;
        let mut ids = std::collections::HashSet::new();
        for sub in &self.subscriptions {
            if sub.id == 0 || sub.id >= self.next_subscription_id || !ids.insert(sub.id) {
                return Err("Некорректный идентификатор подписки.".into());
            }
            if sub.name.trim().is_empty()
                || sub.name.chars().count() > 80
                || sub.name.chars().any(char::is_control)
            {
                return Err("Некорректное имя подписки.".into());
            }
            if sub
                .source
                .as_ref()
                .is_some_and(|s| crate::catalog::source_url(s).as_ref() != Ok(s))
            {
                return Err("Некорректный источник подписки.".into());
            }
            if matches!(sub.update,crate::catalog::UpdatePolicy::EveryHours(n) if !(1..=720).contains(&n))
            {
                return Err("Интервал: от 1 до 720 часов.".into());
            }
            sub.metadata.validate()?;
            if sub.profiles.len() > 256
                || (!sub.profiles.is_empty() && sub.selected >= sub.profiles.len())
            {
                return Err("Некорректный список серверов.".into());
            }
            for profile in &sub.profiles {
                if profile.name.chars().count() > 80 || profile.name.chars().any(char::is_control) {
                    return Err("Некорректное имя сервера.".into());
                }
                parse_uri(&profile.uri)?;
            }
        }
        if !self.subscriptions.is_empty() && self.selected_subscription >= self.subscriptions.len()
        {
            return Err("Некорректная выбранная подписка.".into());
        }
        Ok(())
    }
}

pub fn default_path() -> Result<PathBuf> {
    let base = if let Some(p) =
        std::env::var_os("XDG_CONFIG_HOME").filter(|p| Path::new(p).is_absolute())
    {
        PathBuf::from(p)
    } else {
        PathBuf::from(std::env::var_os("HOME").ok_or("Нет домашнего каталога.")?).join(".config")
    };
    Ok(base.join("velum/settings.json"))
}

pub fn load(path: &Path) -> Result<Settings> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Settings::default()),
        Err(_) => return Err("Не удалось открыть настройки.".into()),
    };
    let meta = file
        .metadata()
        .map_err(|_| "Не удалось проверить файл настроек.")?;
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err("Настройки должны принадлежать вам и иметь права 600.".into());
    }
    let mut data = Vec::new();
    file.take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut data)
        .map_err(|_| "Не удалось прочитать настройки.")?;
    if data.len() > 16 * 1024 * 1024 {
        return Err("Файл настроек слишком большой.".into());
    }
    let mut settings: Settings = serde_json::from_slice(&data)
        .map_err(|_| "Файл настроек повреждён. Он не будет перезаписан автоматически.")?;
    settings.migrate()?;
    Ok(settings)
}

pub fn save(path: &Path, settings: &Settings) -> Result<()> {
    settings.validate()?;
    let dir = path.parent().ok_or("Нет каталога настроек.")?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|_| "Не удалось создать каталог настроек.")?;
    let meta = fs::symlink_metadata(dir).map_err(|_| "Не удалось проверить каталог настроек.")?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
        return Err("Небезопасные права каталога настроек.".into());
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .map_err(|_| "Не удалось ограничить доступ к настройкам.")?;
    let temp = dir.join(format!(".settings-{}.tmp", std::process::id()));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp)
        .map_err(|_| "Не удалось создать временный файл настроек.")?;
    let result = (|| {
        let data =
            serde_json::to_vec_pretty(settings).map_err(|_| "Не удалось подготовить настройки.")?;
        if data.len() > 16 * 1024 * 1024 {
            return Err("Файл настроек слишком большой.".into());
        }
        f.write_all(&data)
            .map_err(|_| "Не удалось записать настройки.")?;
        f.sync_all()
            .map_err(|_| "Не удалось сохранить настройки.")?;
        backup_legacy(path, dir)?;
        fs::rename(&temp, path).map_err(|_| "Не удалось заменить настройки.")?;
        File::open(dir)
            .and_then(|f| f.sync_all())
            .map_err(|_| "Не удалось синхронизировать настройки.")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

// Keep one private rollback snapshot when replacing the old schema for the first time.
fn backup_legacy(path: &Path, dir: &Path) -> Result<()> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                || e.raw_os_error() == Some(libc::ELOOP) =>
        {
            return Ok(());
        }
        Err(_) => return Err("Не удалось проверить прежние настройки.".into()),
    };
    let m = file
        .metadata()
        .map_err(|_| "Не удалось проверить прежние настройки.")?;
    if !m.is_file() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        return Err("Небезопасные прежние настройки.".into());
    }
    let mut data = Vec::new();
    file.take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut data)
        .map_err(|_| "Не удалось прочитать прежние настройки.")?;
    if data.len() > 16 * 1024 * 1024 {
        return Err("Файл настроек слишком большой.".into());
    }
    let old: serde_json::Value = serde_json::from_slice(&data)
        .map_err(|_| "Прежние настройки повреждены; запись отменена.")?;
    let old_schema = old["schema"].as_u64().unwrap_or(0);
    if old_schema >= 3 {
        return Ok(());
    }
    let backup = dir.join(if old_schema == 1 {
        "settings-before-alpha.json"
    } else {
        "settings-before-alpha2.json"
    });
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&backup)
    {
        Ok(mut f) => {
            if f.write_all(&data).and_then(|_| f.sync_all()).is_err() {
                let _ = fs::remove_file(&backup);
                return Err("Не удалось сохранить настройки для отката.".into());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err("Не удалось сохранить настройки для отката.".into()),
    }
    Ok(())
}
