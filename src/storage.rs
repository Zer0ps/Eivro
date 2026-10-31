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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Colorway {
    #[default]
    Graphite,
    Sage,
    Sand,
    Ocean,
    Plum,
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
    pub connections: Vec<crate::network::Connection>,
    pub reconnect: bool,
    pub close_to_tray: bool,
    pub autoconnect: bool,
    pub kill_switch: bool,
    pub theme: Theme,
    pub accent: [u8; 3],
    pub colorway: Colorway,
    pub reduced_motion: bool,
    pub mode: Mode,
    pub port: u16,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            schema: 4,
            connections: Vec::new(),
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
            accent: [194, 205, 223],
            colorway: Colorway::Graphite,
            reduced_motion: false,
            mode: Mode::Proxy,
            port: 2080,
        }
    }
}

impl Settings {
    pub fn migrate(&mut self) -> Result<()> {
        if !(1..=4).contains(&self.schema) {
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
        self.schema = 4;
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
        if self.schema != 4 {
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
        if self.kill_switch
            && self.routing_profiles[self.selected_routing]
                .rules
                .iter()
                .any(|r| r.enabled && matches!(r.action, crate::policy::Action::Connection(_)))
        {
            return Err(
                "Отключите Kill switch перед применением правил с внешним сетевым выходом.".into(),
            );
        }
        crate::network::validate(&self.connections)?;
        for rule in self
            .routing_profiles
            .iter()
            .flat_map(|profile| &profile.rules)
        {
            if let crate::policy::Action::Connection(id) = rule.action
                && !self
                    .connections
                    .iter()
                    .any(|connection| connection.id == id)
            {
                return Err("Правило ссылается на удалённый сетевой выход.".into());
            }
        }
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

fn config_base() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("XDG_CONFIG_HOME").filter(|p| Path::new(p).is_absolute()) {
        Ok(PathBuf::from(p))
    } else {
        Ok(
            PathBuf::from(std::env::var_os("HOME").ok_or("Нет домашнего каталога.")?).join(
                if cfg!(target_os = "macos") {
                    "Library/Application Support"
                } else {
                    ".config"
                },
            ),
        )
    }
}

/// The stable scope coordinates old/new launchers before any directory is moved.
pub fn instance_scope() -> Result<PathBuf> {
    Ok(config_base()?.join("velum/settings.json"))
}

pub fn default_path() -> Result<PathBuf> {
    let base = config_base()?;
    let current = base.join("eivro/settings.json");
    let legacy = base.join("velum/settings.json");
    // Recovery subprocesses can still find a pre-migration proxy snapshot.
    Ok(if !current.exists() && legacy.exists() {
        legacy
    } else {
        current
    })
}

/// Called by the GUI only after it owns the cross-version instance lock.
pub fn prepare_config() -> Result<PathBuf> {
    migrate_config_at(&config_base()?)
}

fn migrate_config_at(base: &Path) -> Result<PathBuf> {
    let old = base.join("velum");
    let new = base.join("eivro");
    let path = new.join("settings.json");
    if path.exists() || !old.join("settings.json").exists() {
        return Ok(path);
    }
    if new.symlink_metadata().is_ok() {
        return Err("Каталог Eivro уже существует без настроек. Старые данные сохранены; объедините каталоги вручную.".into());
    }
    let meta =
        fs::symlink_metadata(&old).map_err(|_| "Не удалось проверить прежний каталог настроек.")?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
        return Err("Небезопасные права прежнего каталога настроек.".into());
    }
    load(&old.join("settings.json"))?;
    use std::os::unix::ffi::OsStrExt;
    let from = std::ffi::CString::new(old.as_os_str().as_bytes())
        .map_err(|_| "Некорректный путь настроек.")?;
    let to = std::ffi::CString::new(new.as_os_str().as_bytes())
        .map_err(|_| "Некорректный путь настроек.")?;
    // NOREPLACE protects an Eivro directory created concurrently. Rename preserves
    // private keys, backups and the proxy-recovery lock without copying secrets.
    #[cfg(target_os = "linux")]
    let renamed = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(target_os = "macos")]
    let renamed = unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) };
    if renamed != 0 {
        return Err(
            "Не удалось перенести настройки Velum в Eivro. Старые данные сохранены.".into(),
        );
    }
    File::open(base)
        .and_then(|f| f.sync_all())
        .map_err(|_| "Настройки перенесены, но синхронизация каталога не удалась.")?;
    Ok(path)
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
    if old_schema >= 4 {
        return Ok(());
    }
    let backup = dir.join(if old_schema == 3 {
        "settings-before-1.1.json"
    } else if old_schema == 1 {
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

#[cfg(test)]
mod rebrand_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let base = std::env::temp_dir().join(format!(
                "eivro-migrate-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&base).unwrap();
            save(&base.join("velum/settings.json"), &Settings::default()).unwrap();
            Self(base)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn rename_preserves_private_data_recovery_files_and_permissions() {
        let f = Fixture::new();
        let old = f.0.join("velum");
        fs::create_dir(old.join("imports")).unwrap();
        for name in [
            "imports/profile",
            "proxy-state.json",
            "proxy.lock",
            "settings-before-1.1.json",
        ] {
            fs::write(old.join(name), b"synthetic-private-data").unwrap();
            fs::set_permissions(old.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        let bytes = fs::read(old.join("settings.json")).unwrap();
        let inode = fs::metadata(&old).unwrap().ino();
        let path = migrate_config_at(&f.0).unwrap();
        assert!(!old.exists());
        assert_eq!(path, f.0.join("eivro/settings.json"));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(fs::metadata(path.parent().unwrap()).unwrap().ino(), inode);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        for name in [
            "imports/profile",
            "proxy-state.json",
            "proxy.lock",
            "settings-before-1.1.json",
        ] {
            let file = f.0.join("eivro").join(name);
            assert_eq!(fs::read(&file).unwrap(), b"synthetic-private-data");
            assert_eq!(fs::metadata(file).unwrap().mode() & 0o777, 0o600);
        }
        assert_eq!(migrate_config_at(&f.0).unwrap(), path);
    }

    #[test]
    fn existing_current_config_is_never_replaced_or_merged() {
        let f = Fixture::new();
        let path = f.0.join("eivro/settings.json");
        let settings = Settings {
            port: 2199,
            ..Settings::default()
        };
        save(&path, &settings).unwrap();
        assert_eq!(migrate_config_at(&f.0).unwrap(), path);
        assert_eq!(load(&path).unwrap().port, 2199);
        assert!(f.0.join("velum/settings.json").exists());
        fs::remove_file(&path).unwrap();
        assert!(migrate_config_at(&f.0).is_err());
        assert!(f.0.join("velum/settings.json").exists());
    }

    #[test]
    fn invalid_or_unsafe_legacy_config_is_left_intact() {
        let f = Fixture::new();
        let old = f.0.join("velum/settings.json");
        fs::set_permissions(&old, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(migrate_config_at(&f.0).is_err());
        fs::set_permissions(&old, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&old, b"invalid JSON").unwrap();
        assert!(migrate_config_at(&f.0).is_err());
        assert_eq!(fs::read(old).unwrap(), b"invalid JSON");
        assert!(!f.0.join("eivro").exists());
    }

    #[test]
    fn linked_legacy_directory_is_not_moved() {
        let f = Fixture::new();
        fs::rename(f.0.join("velum"), f.0.join("outside")).unwrap();
        std::os::unix::fs::symlink(f.0.join("outside"), f.0.join("velum")).unwrap();
        assert!(migrate_config_at(&f.0).is_err());
        assert!(f.0.join("outside/settings.json").exists());
        assert!(!f.0.join("eivro").exists());
    }
}
