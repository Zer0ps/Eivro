use eivro::{privacy, process};
use std::{
    fs::OpenOptions,
    io::Write,
    os::fd::AsRawFd,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

fn main() {
    if std::env::args()
        .collect::<Vec<_>>()
        .get(1)
        .is_some_and(|s| s == "--version")
    {
        println!("Eivro TUN {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if privacy::harden().is_err() {
        std::process::exit(1);
    }
    if run().is_err() {
        let _ = std::io::stdout().write_all(b"ERROR\n");
        std::process::exit(1);
    }
}

fn run() -> eivro::Result<()> {
    if unsafe { libc::geteuid() } != 0
        || !process::trusted_binary(Path::new(process::INSTALLED_CORE))
    {
        return Err("privilege".into());
    }
    let release = std::env::args()
        .collect::<Vec<_>>()
        .get(1)
        .is_some_and(|s| s == "--release");
    if std::env::args_os().count() != if release { 2 } else { 1 } {
        return Err("arguments".into());
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/run/velum-tun.lock")
        .map_err(|_| "lock")?;
    let metadata = lock.metadata().map_err(|_| "lock")?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
    {
        return Err("already running".into());
    }
    if release {
        return eivro::guard::Guard::clear_stale();
    }
    let input = std::fs::File::open("/dev/stdin").map_err(|_| "input")?;
    eivro::tun::serve_backend(
        input,
        std::io::stdout(),
        eivro::guard::SystemBackend::default(),
    )
}
