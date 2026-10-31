use std::{fs::File, os::fd::AsRawFd};

pub fn harden() -> std::io::Result<()> {
    std::panic::set_hook(Box::new(|_| {}));
    // Process-local only: do not change the user's global crash/reporting policy.
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        #[cfg(target_os = "linux")]
        if libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn silence_stdio() -> std::io::Result<()> {
    let null = File::options().write(true).open("/dev/null")?;
    unsafe {
        if libc::dup2(null.as_raw_fd(), libc::STDOUT_FILENO) < 0
            || libc::dup2(null.as_raw_fd(), libc::STDERR_FILENO) < 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}
