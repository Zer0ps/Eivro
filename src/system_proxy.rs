//! GNOME proxy settings are leased to a connection and restored by a separate
//! process. The recovery file contains settings only, never traffic or history.
use crate::Result;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::process::CommandExt,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::PathBuf,
    process::{Command, Stdio},
};

const BUSY: &str = "Системным прокси уже управляет другое окно Eivro.";
const KEYS: &[(&str, &str)] = &[
    ("org.gnome.system.proxy", "mode"),
    ("org.gnome.system.proxy", "use-same-proxy"),
    ("org.gnome.system.proxy", "ignore-hosts"),
    ("org.gnome.system.proxy.http", "host"),
    ("org.gnome.system.proxy.http", "port"),
    ("org.gnome.system.proxy.http", "use-authentication"),
    ("org.gnome.system.proxy.https", "host"),
    ("org.gnome.system.proxy.https", "port"),
    ("org.gnome.system.proxy.ftp", "host"),
    ("org.gnome.system.proxy.ftp", "port"),
    ("org.gnome.system.proxy.socks", "host"),
    ("org.gnome.system.proxy.socks", "port"),
];

trait Backend {
    fn get(&self, index: usize) -> Result<String>;
    fn set(&self, index: usize, value: &str) -> Result<()>;
}
struct Gsettings;
fn command(args: &[&str]) -> Result<String> {
    let mut command = Command::new("/usr/bin/gsettings");
    // The guard consumes shutdown signals itself; its short-lived CLI children
    // should retain ordinary signal behavior.
    unsafe {
        command.pre_exec(|| {
            let mut mask = std::mem::zeroed();
            libc::sigemptyset(&mut mask);
            if libc::sigprocmask(libc::SIG_SETMASK, &mask, std::ptr::null_mut()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Нужен gsettings для системного прокси GNOME. Выберите «Локально» или TUN.")?;
    let pid = crate::process::pid_fd(&child)?;
    let mut fd = crate::process::pollfd(pid.as_raw_fd(), libc::POLLIN);
    if unsafe { libc::poll(&mut fd, 1, 2000) } <= 0 {
        let _ = child.kill();
        let _ = child.wait();
        return Err("GNOME не отвечает. Проверьте сеанс D-Bus.".into());
    }
    let output = child.wait_with_output().map_err(|_| "Ошибка gsettings.")?;
    if !output.status.success() || output.stdout.len() > 64 * 1024 {
        return Err("Системный прокси GNOME недоступен. Выберите «Локально» или TUN.".into());
    }
    String::from_utf8(output.stdout)
        .map(|s| s.trim().into())
        .map_err(|_| "Неверный ответ GNOME.".into())
}
impl Backend for Gsettings {
    fn get(&self, index: usize) -> Result<String> {
        let (schema, key) = KEYS[index];
        command(&["get", schema, key])
    }
    fn set(&self, index: usize, value: &str) -> Result<()> {
        let (schema, key) = KEYS[index];
        command(&["set", schema, key, value])?;
        if self.get(index)? != value {
            return Err("GNOME не сохранил настройки прокси.".into());
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    before: Vec<String>,
    applied: Vec<String>,
}
impl Snapshot {
    fn capture(backend: &impl Backend, port: u16) -> Result<Self> {
        let mut applied = vec![
            "'manual'".into(),
            "false".into(),
            "['localhost', '127.0.0.0/8', '::1']".into(),
        ];
        for (_, key) in &KEYS[3..] {
            applied.push(match *key {
                "host" => "'127.0.0.1'".into(),
                "port" => port.to_string(),
                _ => "false".into(),
            });
        }
        Ok(Self {
            before: (0..KEYS.len())
                .map(|i| backend.get(i))
                .collect::<Result<_>>()?,
            applied,
        })
    }
    fn apply(&self, backend: &impl Backend, alive: impl Fn() -> bool) -> Result<()> {
        // Activate last, after all endpoints have been written and read back.
        for i in (1..KEYS.len()).chain(std::iter::once(0)) {
            if !alive() {
                return Err("Подключение отменено.".into());
            }
            if self.before[i] != self.applied[i] {
                backend.set(i, &self.applied[i])?;
            }
        }
        Ok(())
    }
    fn restore(&self, backend: &impl Backend) -> Result<bool> {
        let current = (0..KEYS.len())
            .map(|i| backend.get(i))
            .collect::<Result<Vec<_>>>()?;
        // Mode and endpoints identify the owner. Editing bypass/authentication
        // preferences must not leave our stopped proxy active. Accept a mixture
        // of before/applied endpoints so an interrupted restore can be retried.
        if [0, 3, 4, 6, 7, 8, 9, 10, 11]
            .into_iter()
            .any(|i| current[i] != self.before[i] && current[i] != self.applied[i])
        {
            return Ok(false);
        }
        for i in (1..KEYS.len()).chain(std::iter::once(0)) {
            if current[i] == self.applied[i] && current[i] != self.before[i] {
                backend.set(i, &self.before[i])?;
            }
        }
        Ok(true)
    }
}
struct Store {
    path: PathBuf,
    _lock: File,
}
impl Store {
    fn open() -> Result<Self> {
        let dir = crate::storage::default_path()?
            .parent()
            .ok_or("Нет каталога настроек.")?
            .to_owned();
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(|_| "Нет доступа к настройкам прокси.")?;
        let meta = fs::symlink_metadata(&dir).map_err(|_| "Нет каталога настроек.")?;
        if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err("Каталог настроек Eivro должен иметь права 700.".into());
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(dir.join("proxy.lock"))
            .map_err(|_| "Не удалось заблокировать настройки прокси.")?;
        let meta = lock.metadata().map_err(|_| "Неверная блокировка прокси.")?;
        if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err("Небезопасный файл блокировки прокси.".into());
        }
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(BUSY.into());
        }
        Ok(Self {
            path: dir.join("proxy-recovery.json"),
            _lock: lock,
        })
    }
    fn save(&self, s: &Snapshot) -> Result<()> {
        let temp = self.path.with_extension("tmp");
        match fs::remove_file(&temp) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("Не удалось подготовить файл восстановления прокси.".into()),
        }
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)
            .map_err(|_| "Не удалось сохранить параметры восстановления прокси.")?;
        f.write_all(&serde_json::to_vec(s).map_err(|_| "Ошибка настроек прокси.")?)
            .and_then(|_| f.sync_all())
            .map_err(|_| "Не удалось сохранить параметры восстановления прокси.")?;
        fs::rename(temp, &self.path)
            .and_then(|_| File::open(self.path.parent().unwrap())?.sync_all())
            .map_err(|_| "Не удалось сохранить параметры восстановления прокси.".into())
    }
    fn recover(&self) -> Result<bool> {
        let f = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(_) => return Err("Не удалось открыть параметры восстановления прокси.".into()),
        };
        let meta = f
            .metadata()
            .map_err(|_| "Не удалось проверить параметры восстановления.")?;
        if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err("Небезопасный файл восстановления прокси.".into());
        }
        let mut data = Vec::new();
        f.take(128 * 1024 + 1)
            .read_to_end(&mut data)
            .map_err(|_| "Не удалось прочитать настройки прокси.")?;
        let s: Snapshot = serde_json::from_slice(&data)
            .map_err(|_| "Повреждены параметры восстановления прокси.")?;
        if data.len() > 128 * 1024 || s.before.len() != KEYS.len() || s.applied.len() != KEYS.len()
        {
            return Err("Неверные параметры восстановления прокси.".into());
        }
        let restored = s.restore(&Gsettings)?;
        // Errors retain the snapshot for retry. false means a new proxy owner
        // took over: retire our lease rather than reverting that owner later.
        fs::remove_file(&self.path).map_err(|_| "Не удалось завершить восстановление прокси.")?;
        Ok(restored)
    }
}

pub fn recover_stale() -> Result<()> {
    let path = crate::storage::default_path()?.with_file_name("proxy-recovery.json");
    if !path.exists() {
        return Ok(());
    }
    // An active guard retains the lock, so a second window must leave it alone.
    match Store::open() {
        Ok(store) => {
            store.recover()?;
        }
        Err(e) if e == BUSY => {}
        Err(e) => return Err(e),
    }
    Ok(())
}

pub fn guard(port: u16) -> Result<bool> {
    if port < 1024 {
        return Err("Неверный порт прокси.".into());
    }
    let signals = shutdown_signals()?;
    let store = Store::open()?;
    store.recover()?;
    let snapshot = Snapshot::capture(&Gsettings, port)?;
    for (schema, key) in KEYS {
        if command(&["writable", schema, key])? != "true" {
            return Err("Настройки прокси GNOME заблокированы администратором.".into());
        }
    }
    store.save(&snapshot)?;
    let alive = || {
        let mut fds = [
            crate::process::pollfd(0, libc::POLLIN),
            crate::process::pollfd(signals.as_raw_fd(), libc::POLLIN),
        ];
        (unsafe { libc::poll(fds.as_mut_ptr(), 2, 0) }) == 0
    };
    let result: Result<()> = (|| {
        snapshot.apply(&Gsettings, alive)?;
        std::io::stdout()
            .write_all(b"READY\n")
            .and_then(|_| std::io::stdout().flush())
            .map_err(|_| "Окно Eivro закрылось.")?;
        let mut fds = [
            crate::process::pollfd(0, libc::POLLIN),
            crate::process::pollfd(signals.as_raw_fd(), libc::POLLIN),
        ];
        crate::process::poll(&mut fds)?;
        Ok(())
    })();
    let restored = store.recover()?;
    if alive() {
        result?;
    }
    Ok(restored)
}

fn shutdown_signals() -> Result<OwnedFd> {
    unsafe {
        let mut mask = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            libc::sigaddset(&mut mask, signal);
        }
        if libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) != 0 {
            return Err("Не удалось настроить восстановление прокси при завершении.".into());
        }
        let fd = libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
        if fd < 0 {
            return Err("Не удалось настроить восстановление прокси при завершении.".into());
        }
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    struct Memory {
        values: RefCell<Vec<String>>,
        fail: RefCell<Option<usize>>,
    }
    impl Backend for Memory {
        fn get(&self, i: usize) -> Result<String> {
            Ok(self.values.borrow()[i].clone())
        }
        fn set(&self, i: usize, v: &str) -> Result<()> {
            if *self.fail.borrow() == Some(i) {
                return Err("write failed".into());
            }
            self.values.borrow_mut()[i] = v.into();
            Ok(())
        }
    }
    fn backend() -> Memory {
        Memory {
            values: RefCell::new(
                (0..KEYS.len())
                    .map(|i| {
                        if i == 0 {
                            "'auto'".into()
                        } else {
                            format!("previous-{i}")
                        }
                    })
                    .collect(),
            ),
            fail: RefCell::new(None),
        }
    }
    #[test]
    fn restores_previous_auto_proxy_and_all_endpoints() {
        let b = backend();
        let s = Snapshot::capture(&b, 2080).unwrap();
        s.apply(&b, || true).unwrap();
        assert_eq!(b.get(0).unwrap(), "'manual'");
        assert!(s.restore(&b).unwrap());
        assert_eq!(*b.values.borrow(), s.before);
    }
    #[test]
    fn partial_apply_rolls_back() {
        let b = backend();
        let s = Snapshot::capture(&b, 2080).unwrap();
        *b.fail.borrow_mut() = Some(6);
        assert!(s.apply(&b, || true).is_err());
        *b.fail.borrow_mut() = None;
        assert!(s.restore(&b).unwrap());
        assert_eq!(*b.values.borrow(), s.before);
    }
    #[test]
    fn another_clients_settings_are_preserved() {
        let b = backend();
        let s = Snapshot::capture(&b, 2080).unwrap();
        s.apply(&b, || true).unwrap();
        b.set(4, "10808").unwrap();
        let changed = b.values.borrow().clone();
        assert!(!s.restore(&b).unwrap());
        assert_eq!(*b.values.borrow(), changed);
    }

    #[test]
    fn edited_exceptions_survive_without_leaving_a_dead_proxy() {
        let b = backend();
        let s = Snapshot::capture(&b, 2080).unwrap();
        s.apply(&b, || true).unwrap();
        b.set(2, "['localhost', 'private.example']").unwrap();
        assert!(s.restore(&b).unwrap());
        let mut expected = s.before;
        expected[2] = "['localhost', 'private.example']".into();
        assert_eq!(*b.values.borrow(), expected);
    }

    #[test]
    fn failed_restore_can_be_retried_with_edited_exceptions() {
        let b = backend();
        let s = Snapshot::capture(&b, 2080).unwrap();
        s.apply(&b, || true).unwrap();
        b.set(2, "['private.example']").unwrap();
        *b.fail.borrow_mut() = Some(6);
        assert!(s.restore(&b).is_err());
        assert_eq!(b.get(0).unwrap(), "'manual'");
        *b.fail.borrow_mut() = None;
        assert!(s.restore(&b).unwrap());
        assert_eq!(b.get(0).unwrap(), s.before[0]);
        assert_eq!(b.get(4).unwrap(), s.before[4]);
        assert_eq!(b.get(2).unwrap(), "['private.example']");
    }
}
