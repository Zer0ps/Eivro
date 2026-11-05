//! Private tmpfs state. The identity marker is the atomic pointer to one of
//! two cache slots; an interrupted retirement never rewinds address allocation.
use crate::Result;
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

mod retire;
pub const MAX_BYTES: u64 = 32 * 1024 * 1024;
pub struct State {
    pub file: File,
    marker: File,
    directory: File,
    path: PathBuf,
    user: u32,
    slot: usize,
}

impl State {
    pub fn open() -> Result<Self> {
        Self::open_at(Path::new("/run/eivro-dns"), Self::owner()?)
    }
    pub fn open_existing() -> Result<Option<Self>> {
        let user = Self::owner()?;
        let directory = Path::new("/run/eivro-dns");
        let mut exists = false;
        for name in [
            format!("{user}.cache"),
            format!("{user}.cache.next"),
            format!("{user}.identity"),
            format!("{user}.identity.next"),
        ] {
            match fs::symlink_metadata(directory.join(name)) {
                Ok(_) => exists = true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("Не удалось проверить сохранённое состояние DNS.".into()),
            }
        }
        if exists {
            Self::open_at(directory, user).map(Some)
        } else {
            Ok(None)
        }
    }
    fn owner() -> Result<u32> {
        if unsafe { libc::geteuid() } != 0 {
            return Err("Состоянием DNS управляет системный помощник.".into());
        }
        std::env::var("PKEXEC_UID")
            .or_else(|_| std::env::var("SUDO_UID"))
            .unwrap_or_else(|_| "0".into())
            .parse::<u32>()
            .map_err(|_| "Не удалось определить владельца состояния DNS.".into())
    }

    fn open_at(path: &Path, user: u32) -> Result<Self> {
        match DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err("Не удалось подготовить память DNS.".into()),
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| "Небезопасный каталог состояния DNS.")?;
        let metadata = directory.metadata().map_err(|_| "Нет состояния DNS.")?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err("Небезопасные права состояния DNS.".into());
        }
        let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if unsafe { libc::fstatfs(directory.as_raw_fd(), filesystem.as_mut_ptr()) } != 0
            || unsafe { filesystem.assume_init() }.f_type != libc::TMPFS_MAGIC
        {
            return Err("Для состояния DNS требуется tmpfs в /run.".into());
        }
        let marker_path = path.join(format!("{user}.identity"));
        let saved = match private_open(&marker_path) {
            Ok(mut marker) => {
                if private_file(&marker)?.len() > 80 {
                    return Err("Состояние DNS повреждено.".into());
                }
                let mut text = String::new();
                (&mut marker)
                    .take(81)
                    .read_to_string(&mut text)
                    .map_err(|_| "Нет идентификатора DNS.")?;
                let slot = marker_slot(&text)?;
                Some((marker, text, slot))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err("Небезопасный идентификатор состояния DNS.".into()),
        };
        // A missing marker cannot turn a leftover alternate generation into a
        // fresh table. That would reuse addresses already held by applications.
        if saved.is_none()
            && [
                format!("{user}.cache.next"),
                format!("{user}.identity.next"),
            ]
            .iter()
            .any(|name| fs::symlink_metadata(path.join(name)).is_ok())
        {
            return Err("Идентификатор DNS потерян; требуется перезагрузка системы.".into());
        }
        let slot = saved.as_ref().map_or(0, |(_, _, slot)| *slot);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(saved.is_none())
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(cache_path(path, user, slot))
            .map_err(|_| "Состояние DNS потеряно; требуется перезагрузка системы.")?;
        let metadata = private_file(&file)?;
        if metadata.len() > MAX_BYTES {
            return Err("Память DNS заполнена; требуется перезагрузка системы.".into());
        }
        let identity = format!("{}:{}\n", metadata.dev(), metadata.ino());
        let marker = if let Some((marker, saved, _)) = saved {
            let body = if saved[1..].starts_with("v2:") {
                format!("v2:{slot}:{identity}")
            } else {
                identity
            };
            if saved != format!("0{body}") && saved != format!("1{body}") {
                return Err("Состояние DNS заменено; требуется перезагрузка системы.".into());
            }
            if saved.starts_with('1') && metadata.len() == 0 {
                return Err("Состояние DNS потеряно; требуется перезагрузка системы.".into());
            }
            marker
        } else {
            if metadata.len() != 0 {
                return Err("Неизвестное состояние DNS; требуется перезагрузка системы.".into());
            }
            let mut marker = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(marker_path)
                .map_err(|_| "Не удалось подготовить идентификатор DNS.")?;
            marker
                .write_all(format!("0{identity}").as_bytes())
                .map_err(|_| "Не удалось записать идентификатор DNS.")?;
            marker
        };
        let state = Self {
            file,
            marker,
            directory,
            path: path.into(),
            user,
            slot,
        };
        state.clean_inactive()?;
        Ok(state)
    }

    pub fn initialized(&self) -> Result<()> {
        self.marker
            .write_all_at(b"1", 0)
            .map_err(|_| "Не удалось сохранить идентификатор DNS.".into())
    }

    pub fn validate(&self) -> Result<()> {
        let dir = self
            .directory
            .metadata()
            .map_err(|_| "Нет каталога состояния DNS.")?;
        let named_dir =
            fs::symlink_metadata(&self.path).map_err(|_| "Каталог состояния DNS заменён.")?;
        if !named_dir.is_dir()
            || dir.dev() != named_dir.dev()
            || dir.ino() != named_dir.ino()
            || dir.uid() != unsafe { libc::geteuid() }
            || dir.mode() & 0o077 != 0
        {
            return Err("Небезопасный каталог состояния DNS.".into());
        }
        let info = private_file(&self.file)?;
        let marker_info = private_file(&self.marker)?;
        for (path, held) in [
            (cache_path(&self.path, self.user, self.slot), &info),
            (
                self.path.join(format!("{}.identity", self.user)),
                &marker_info,
            ),
        ] {
            let named = fs::symlink_metadata(path)
                .map_err(|_| "Состояние DNS потеряно; требуется перезагрузка системы.")?;
            if !named.is_file() || named.dev() != held.dev() || named.ino() != held.ino() {
                return Err("Состояние DNS заменено; требуется перезагрузка системы.".into());
            }
        }
        if info.len() > MAX_BYTES || marker_info.len() > 80 {
            return Err("Некорректный размер состояния DNS.".into());
        }
        let mut bytes = [0u8; 80];
        let length = marker_info.len() as usize;
        self.marker
            .read_exact_at(&mut bytes[..length], 0)
            .map_err(|_| "Нет идентификатора DNS.")?;
        let text =
            std::str::from_utf8(&bytes[..length]).map_err(|_| "Идентификатор DNS повреждён.")?;
        let slot = marker_slot(text)?;
        let identity = format!("{}:{}\n", info.dev(), info.ino());
        let body = if text[1..].starts_with("v2:") {
            format!("v2:{slot}:{identity}")
        } else {
            identity
        };
        if slot != self.slot || (text != format!("0{body}") && text != format!("1{body}")) {
            return Err("Состояние DNS заменено; требуется перезагрузка системы.".into());
        }
        if text.starts_with('1') && info.len() == 0 {
            return Err("Состояние DNS потеряно; требуется перезагрузка системы.".into());
        }
        Ok(())
    }
}

fn marker_slot(text: &str) -> Result<usize> {
    if text.len() > 80 || !matches!(text.as_bytes().first(), Some(b'0' | b'1')) {
        return Err("Состояние DNS повреждено; требуется перезагрузка системы.".into());
    }
    match text[1..].strip_prefix("v2:") {
        None => Ok(0),
        Some(body) => match body.split(':').next() {
            Some("0") => Ok(0),
            Some("1") => Ok(1),
            _ => Err("Неизвестное поколение состояния DNS.".into()),
        },
    }
}
fn cache_path(directory: &Path, user: u32, slot: usize) -> PathBuf {
    directory.join(if slot == 0 {
        format!("{user}.cache")
    } else {
        format!("{user}.cache.next")
    })
}
fn private_open(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}
fn private_file(file: &File) -> Result<std::fs::Metadata> {
    let metadata = file.metadata().map_err(|_| "Нет состояния DNS.")?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err("Небезопасный файл состояния DNS.".into());
    }
    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = PathBuf::from(format!(
                "/dev/shm/eivro-dns-test-{}-{nonce}",
                std::process::id()
            ));
            DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn state_survives_owner_restart_and_rejects_lost_or_replaced_data() {
        let fixture = Fixture::new();
        let mut first = State::open_at(&fixture.0, 42).unwrap();
        first.file.write_all(b"synthetic-state").unwrap();
        first.initialized().unwrap();
        let inode = first.file.metadata().unwrap().ino();
        drop(first);
        let next = State::open_at(&fixture.0, 42).unwrap();
        assert_eq!(next.file.metadata().unwrap().ino(), inode);
        assert_eq!(next.file.metadata().unwrap().len(), 15);
        drop(next);
        fs::rename(fixture.0.join("42.cache"), fixture.0.join("old.cache")).unwrap();
        assert!(State::open_at(&fixture.0, 42).is_err());
        let mut replacement = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(fixture.0.join("42.cache"))
            .unwrap();
        replacement.write_all(b"replacement").unwrap();
        assert!(State::open_at(&fixture.0, 42).is_err());
    }

    #[test]
    fn incomplete_first_start_is_retryable_but_initialized_empty_state_is_not() {
        let fixture = Fixture::new();
        drop(State::open_at(&fixture.0, 42).unwrap());
        let state = State::open_at(&fixture.0, 42).unwrap();
        state.initialized().unwrap();
        drop(state);
        assert!(State::open_at(&fixture.0, 42).is_err());
    }

    #[test]
    fn unsafe_permissions_and_links_are_rejected() {
        let fixture = Fixture::new();
        let state = State::open_at(&fixture.0, 42).unwrap();
        state
            .file
            .set_permissions(fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(State::open_at(&fixture.0, 42).is_err());
        state
            .file
            .set_permissions(fs::Permissions::from_mode(0o600))
            .unwrap();
        fs::hard_link(fixture.0.join("42.cache"), fixture.0.join("alias")).unwrap();
        assert!(State::open_at(&fixture.0, 42).is_err());
    }
}
