//! Authorization UI lives in a disposable process so cancelling a connection or
//! quitting the GUI can dismiss it without blocking the application's thread.
use crate::{Result, process};
use std::{
    io::{Read, Write},
    os::{fd::AsRawFd, unix::net::UnixStream},
    process::{Child, Stdio},
    time::{Duration, Instant},
};
pub struct Grant {
    child: Child,
    token: [u8; 32],
}
impl Grant {
    pub fn acquire(watch: &UnixStream) -> Result<Option<Self>> {
        let child = process::child_command(&process::app_path()?)
            .arg("--authorize")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|_| "Не удалось запросить права macOS.")?;
        let mut grant = Self {
            child,
            token: [0; 32],
        };
        let mut output = grant.child.stdout.take().ok_or("Нет канала авторизации.")?;
        if unsafe { libc::fcntl(output.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
            return Err("Нет канала авторизации.".into());
        }
        let pid = process::pid_fd(&grant.child)?;
        let deadline = Instant::now() + Duration::from_secs(180);
        let mut offset = 0;
        while offset < 32 {
            let mut fds = [
                process::pollfd(watch.as_raw_fd(), libc::POLLIN),
                process::pollfd(output.as_raw_fd(), libc::POLLIN),
                process::pollfd(pid.as_raw_fd(), libc::POLLIN),
            ];
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("Истекло время запроса прав macOS.".into());
            }
            let result = unsafe {
                libc::poll(
                    fds.as_mut_ptr(),
                    3,
                    remaining.as_millis().min(i32::MAX as u128) as i32,
                )
            };
            if result < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err("Ошибка авторизации macOS.".into());
            }
            if fds[0].revents != 0 {
                return Ok(None);
            }
            if fds[2].revents != 0 {
                return Err("Доступ TUN отменён или права macOS не предоставлены.".into());
            }
            if fds[1].revents != 0 {
                match output.read(&mut grant.token[offset..]) {
                    Ok(0) => return Err("Доступ TUN отменён.".into()),
                    Ok(n) => offset += n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => return Err("Ошибка авторизации macOS.".into()),
                }
            }
        }
        Ok(Some(grant))
    }
    pub fn token(&self) -> [u8; 32] {
        self.token
    }
}
impl Drop for Grant {
    fn drop(&mut self) {
        self.child.stdin.take();
        process::terminate(&mut self.child);
        self.token.fill(0);
    }
}
pub fn worker() -> Result<()> {
    for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO] {
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } != 0
            || stat.st_mode & libc::S_IFMT != libc::S_IFIFO
        {
            return Err("Авторизация доступна только через приватный канал приложения.".into());
        }
    }
    crate::privacy::harden().map_err(|_| "Не удалось защитить процесс авторизации.")?;
    let authorization = super::native::Authorization::acquire()?;
    std::io::stdout()
        .write_all(&authorization.token())
        .map_err(|_| "Канал авторизации закрыт.")?;
    std::io::stdout()
        .flush()
        .map_err(|_| "Канал авторизации закрыт.")?;
    let mut byte = [0];
    let _ = std::io::stdin().read(&mut byte);
    Ok(())
}
