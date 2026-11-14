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
        Self::read_authorization(child, watch)
    }

    fn read_authorization(child: Child, watch: &UnixStream) -> Result<Option<Self>> {
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
        // An explicit decision byte distinguishes Cancel from a damaged worker
        // pipe. Read stdout before process exit when both become ready together.
        let mut response = [0u8; 33];
        let mut offset = 0;
        while offset < response.len() {
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
            if fds[1].revents != 0 {
                match output.read(&mut response[offset..]) {
                    Ok(0) => return Err(crate::tun::AUTHORIZATION_FAILED.into()),
                    Ok(n) => {
                        offset += n;
                        match response[0] {
                            b'C' => return Err(crate::tun::AUTHORIZATION_DENIED.into()),
                            b'G' => {}
                            _ => return Err(crate::tun::AUTHORIZATION_FAILED.into()),
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => return Err("Ошибка авторизации macOS.".into()),
                }
            }
            if fds[2].revents != 0 {
                return Err(crate::tun::AUTHORIZATION_FAILED.into());
            }
        }
        grant.token.copy_from_slice(&response[1..]);
        response.fill(0);
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
    let mut output = std::io::stdout().lock();
    let Some(authorization) = super::native::Authorization::acquire()? else {
        return output
            .write_all(b"C")
            .and_then(|_| output.flush())
            .map_err(|_| "Канал авторизации закрыт.".into());
    };
    output
        .write_all(b"G")
        .and_then(|_| output.write_all(&authorization.token()))
        .map_err(|_| "Канал авторизации закрыт.")?;
    output.flush().map_err(|_| "Канал авторизации закрыт.")?;
    let mut byte = [0];
    let _ = std::io::stdin().read(&mut byte);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_frame_survives_immediate_worker_exit_and_crashes_are_not_reported_as_user_cancel() {
        let (_cancel, watch) = UnixStream::pair().unwrap();
        for (script, expected) in [
            ("printf C", crate::tun::AUTHORIZATION_DENIED),
            ("exit 1", crate::tun::AUTHORIZATION_FAILED),
            ("printf Gshort", crate::tun::AUTHORIZATION_FAILED),
        ] {
            let child = std::process::Command::new("/bin/sh")
                .args(["-c", script])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let result = Grant::read_authorization(child, &watch);
            assert!(matches!(result, Err(ref e) if e == expected));
        }
        let child = std::process::Command::new("/bin/sh")
            .args([
                "-c",
                "printf G; printf '01234567890123456789012345678901'; read line",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let grant = Grant::read_authorization(child, &watch).unwrap().unwrap();
        assert_eq!(&grant.token(), b"01234567890123456789012345678901");
    }
}
