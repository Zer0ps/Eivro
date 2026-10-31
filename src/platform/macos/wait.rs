//! A kqueue becomes readable once the observed process exits. Existing Unix
//! supervision can poll that descriptor without a timer or a watcher thread.
use crate::Result;
use std::{
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    process::Child,
};
pub fn pid_fd(child: &Child) -> Result<OwnedFd> {
    process_fd(child.id() as libc::pid_t)
}
pub fn process_fd(pid: libc::pid_t) -> Result<OwnedFd> {
    let raw = unsafe { libc::kqueue() };
    if raw < 0 {
        return Err("Не удалось создать очередь событий процесса.".into());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    if unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err("Не удалось защитить дескриптор процесса.".into());
    }
    let event = libc::kevent {
        ident: pid as usize,
        filter: libc::EVFILT_PROC,
        flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT,
        fflags: libc::NOTE_EXIT,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    if unsafe {
        libc::kevent(
            fd.as_raw_fd(),
            &event,
            1,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    } < 0
    {
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
            return Err("Не удалось наблюдать за процессом.".into());
        }
        // A short-lived worker may have exited before registration. Preserve
        // readiness instead of turning a successful exit into a timeout.
        let (read, write) = std::os::unix::net::UnixStream::pair()
            .map_err(|_| "Не удалось получить завершение процесса.")?;
        drop(write);
        return Ok(read.into());
    }
    Ok(fd)
}
pub fn peer(fd: i32) -> std::io::Result<(u32, u32)> {
    let (mut uid, mut gid) = (0, 0);
    if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((uid, gid))
}

pub fn terminate(child: &mut Child) {
    if child.try_wait().ok().flatten().is_some() {
        return;
    }
    let exit = pid_fd(child).ok();
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    if let Some(exit) = exit {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut event = crate::process::pollfd(exit.as_raw_fd(), libc::POLLIN);
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let result =
                unsafe { libc::poll(&mut event, 1, remaining.as_millis().clamp(1, 3000) as i32) };
            if result > 0 {
                let _ = child.wait();
                return;
            }
            if result == 0
                || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
            {
                break;
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}
