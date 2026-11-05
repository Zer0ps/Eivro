use super::*;
use std::{
    os::unix::process::CommandExt,
    process::Stdio,
    time::{Duration, Instant},
};

impl State {
    /// Only after the core has stopped, under the helper's exclusive lifetime lock.
    pub fn retire(&mut self, core: &Path) -> Result<()> {
        self.retire_with(|source, target| copy_cursor(core, source, target))
    }

    fn retire_with(&mut self, copy: impl FnOnce(&File, &File) -> Result<()>) -> Result<()> {
        self.validate()?;
        self.clean_inactive()?;
        if private_file(&self.file)?.len() == 0 {
            let mut flag = [0];
            self.marker
                .read_exact_at(&mut flag, 0)
                .map_err(|_| "Нет идентификатора DNS.")?;
            return if flag == *b"0" {
                Ok(())
            } else {
                Err("Состояние DNS потеряно; требуется перезагрузка системы.".into())
            };
        }
        let slot = 1 - self.slot;
        let target = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(cache_path(&self.path, self.user, slot))
            .map_err(|_| "Не удалось подготовить очистку DNS.")?;
        copy(&self.file, &target)?;
        let info = private_file(&target)?;
        if info.len() == 0 || info.len() > MAX_BYTES {
            return Err("Неверное состояние после очистки DNS.".into());
        }
        target
            .sync_all()
            .map_err(|_| "Не удалось сохранить счётчики DNS.")?;
        let marker = self.prepare_marker(&target, slot)?;
        self.publish(target, marker, slot)?;
        self.clean_inactive()?;
        self.directory
            .sync_all()
            .map_err(|_| "Не удалось завершить очистку DNS.".into())
    }

    fn prepare_marker(&self, target: &File, slot: usize) -> Result<File> {
        let info = private_file(target)?;
        let mut marker = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.path.join(format!("{}.identity.next", self.user)))
            .map_err(|_| "Не удалось подготовить указатель DNS.")?;
        marker
            .write_all(format!("1v2:{slot}:{}:{}\n", info.dev(), info.ino()).as_bytes())
            .and_then(|_| marker.sync_all())
            .map_err(|_| "Не удалось сохранить указатель DNS.")?;
        Ok(marker)
    }

    fn publish(&mut self, target: File, marker: File, slot: usize) -> Result<()> {
        fs::rename(
            self.path.join(format!("{}.identity.next", self.user)),
            self.path.join(format!("{}.identity", self.user)),
        )
        .map_err(|_| "Не удалось переключить состояние DNS.")?;
        // After the atomic rename, even a later fsync/unlink failure must leave
        // the in-memory owner on the published generation, never on the old one.
        self.file = target;
        self.marker = marker;
        self.slot = slot;
        self.directory
            .sync_all()
            .map_err(|_| "Не удалось подтвердить переключение DNS.".into())
    }

    pub(super) fn clean_inactive(&self) -> Result<()> {
        for path in [
            cache_path(&self.path, self.user, 1 - self.slot),
            self.path.join(format!("{}.identity.next", self.user)),
        ] {
            match private_open(&path) {
                Ok(file) => {
                    private_file(&file)?;
                    fs::remove_file(path).map_err(|_| "Не удалось удалить прежнюю таблицу DNS.")?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("Небезопасный временный файл состояния DNS.".into()),
            }
        }
        Ok(())
    }
}

fn copy_cursor(core: &Path, source: &File, target: &File) -> Result<()> {
    if !crate::process::trusted_binary(core) {
        return Err("Небезопасное ядро для очистки DNS.".into());
    }
    let fds = [source.as_raw_fd(), target.as_raw_fd()];
    let mut command = crate::process::child_command(core);
    command
        .args([
            "eivro-retire-fakeip",
            &fds[0].to_string(),
            &fds[1].to_string(),
        ])
        .stdin(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            for fd in fds {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            let limit = libc::rlimit {
                rlim_cur: MAX_BYTES,
                rlim_max: MAX_BYTES,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|_| "Не удалось запустить очистку DNS.")?;
    let result = (|| {
        let pid = crate::process::pid_fd(&child)?;
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            let timeout = end
                .saturating_duration_since(Instant::now())
                .as_millis()
                .min(i32::MAX as u128) as i32;
            if timeout == 0 {
                return Err("Истекло время очистки DNS.".into());
            }
            let mut fd = crate::process::pollfd(pid.as_raw_fd(), libc::POLLIN);
            let ready = unsafe { libc::poll(&mut fd, 1, timeout) };
            if ready < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err("Не удалось дождаться очистки DNS.".into());
            }
            if ready > 0 {
                break;
            }
        }
        if child
            .wait()
            .map_err(|_| "Не удалось завершить очистку DNS.")?
            .success()
        {
            Ok(())
        } else {
            Err("Ядро не смогло безопасно очистить таблицу DNS.".into())
        }
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = PathBuf::from(format!(
                "/dev/shm/eivro-retirement-{}-{nonce}",
                std::process::id()
            ));
            DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn state(&self) -> State {
            let mut state = State::open_at(&self.0, 42).unwrap();
            state
                .file
                .write_all(b"private-domain.test;cursor=42")
                .unwrap();
            state.initialized().unwrap();
            state
        }
        fn candidate(&self) -> File {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(self.0.join("42.cache.next"))
                .unwrap();
            file.write_all(b"cursor=42").unwrap();
            file
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn content(file: &File) -> Vec<u8> {
        let mut data = vec![0; file.metadata().unwrap().len() as usize];
        file.read_exact_at(&mut data, 0).unwrap();
        data
    }
    #[test]
    fn precommit_interruption_keeps_original_identity_and_reclaims_candidate() {
        let fixture = Fixture::new();
        let state = fixture.state();
        let candidate = fixture.candidate();
        let marker = state.prepare_marker(&candidate, 1).unwrap();
        drop((state, candidate, marker));
        let restored = State::open_at(&fixture.0, 42).unwrap();
        assert!(content(&restored.file).starts_with(b"private-domain"));
        assert_eq!(restored.slot, 0);
        assert!(!fixture.0.join("42.cache.next").exists());
        assert!(!fixture.0.join("42.identity.next").exists());
    }
    #[test]
    fn postcommit_interruption_keeps_new_cursor_and_removes_old_domain_pages() {
        let fixture = Fixture::new();
        let mut state = fixture.state();
        let candidate = fixture.candidate();
        let marker = state.prepare_marker(&candidate, 1).unwrap();
        state.publish(candidate, marker, 1).unwrap();
        assert!(fixture.0.join("42.cache").exists());
        drop(state);
        let restored = State::open_at(&fixture.0, 42).unwrap();
        assert_eq!(restored.slot, 1);
        assert_eq!(content(&restored.file), b"cursor=42");
        assert!(!fixture.0.join("42.cache").exists());
        restored.initialized().unwrap();
        drop(restored);
        assert!(State::open_at(&fixture.0, 42).is_ok());
    }
    #[test]
    fn lost_committed_file_is_not_replaced_by_older_state() {
        let fixture = Fixture::new();
        let mut state = fixture.state();
        let candidate = fixture.candidate();
        let marker = state.prepare_marker(&candidate, 1).unwrap();
        state.publish(candidate, marker, 1).unwrap();
        drop(state);
        fs::remove_file(fixture.0.join("42.cache.next")).unwrap();
        assert!(State::open_at(&fixture.0, 42).is_err());
        assert!(fixture.0.join("42.cache").exists());
    }
    #[test]
    fn copy_failure_never_changes_active_state_and_a_retry_can_retire_it() {
        let fixture = Fixture::new();
        let mut state = fixture.state();
        let before = fs::read(fixture.0.join("42.identity")).unwrap();
        assert!(
            state
                .retire_with(|_, new| {
                    new.write_all_at(b"partial", 0).unwrap();
                    Err("fixture failure".into())
                })
                .is_err()
        );
        assert_eq!(fs::read(fixture.0.join("42.identity")).unwrap(), before);
        assert!(content(&state.file).starts_with(b"private-domain"));
        state
            .retire_with(|_, new| new.write_all_at(b"cursor=42", 0).map_err(|e| e.to_string()))
            .unwrap();
        assert_eq!(content(&state.file), b"cursor=42");
        assert!(!fixture.0.join("42.cache").exists());
        state
            .retire_with(|_, new| new.write_all_at(b"cursor=42", 0).map_err(|e| e.to_string()))
            .unwrap();
        assert_eq!(state.slot, 0);
        assert!(!fixture.0.join("42.cache.next").exists());
    }
    #[test]
    fn missing_pointer_with_a_retained_alternate_is_not_fresh_state() {
        let fixture = Fixture::new();
        let mut state = fixture.state();
        let candidate = fixture.candidate();
        let marker = state.prepare_marker(&candidate, 1).unwrap();
        state.publish(candidate, marker, 1).unwrap();
        state.clean_inactive().unwrap();
        drop(state);
        fs::remove_file(fixture.0.join("42.identity")).unwrap();
        assert!(State::open_at(&fixture.0, 42).is_err());
        assert!(fixture.0.join("42.cache.next").exists());
    }
    #[test]
    fn renamed_or_replaced_live_files_are_never_retired_as_owned_state() {
        let fixture = Fixture::new();
        let mut state = fixture.state();
        fs::rename(
            fixture.0.join("42.cache"),
            fixture.0.join("external-backup"),
        )
        .unwrap();
        let mut replacement = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(fixture.0.join("42.cache"))
            .unwrap();
        replacement.write_all(b"external replacement").unwrap();
        assert!(state.validate().is_err());
        assert!(
            state
                .retire_with(|_, _| panic!("must reject before invoking the copier"))
                .is_err()
        );
        assert_eq!(
            fs::read(fixture.0.join("42.cache")).unwrap(),
            b"external replacement"
        );
        assert!(fixture.0.join("external-backup").exists());
    }
}
