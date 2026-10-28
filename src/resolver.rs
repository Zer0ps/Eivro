//! libc/NSS resolution has no cancellable API. Keep it in a disposable process,
//! preserving the system resolver without accumulating blocked background threads.
use std::{
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    os::{fd::AsRawFd, unix::net::UnixStream},
    process::{Child, Command, Stdio},
    time::Instant,
};

const MAX_ADDRESSES: usize = 32;
const MAX_REPLY: u64 = 4096;

fn cancelled(watch: Option<&UnixStream>) -> io::Result<bool> {
    let Some(watch) = watch else { return Ok(false) };
    let mut fd = crate::process::pollfd(watch.as_raw_fd(), libc::POLLIN);
    let result = unsafe { libc::poll(&mut fd, 1, 0) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result > 0)
}

fn check_budget(deadline: Instant, watch: Option<&UnixStream>) -> io::Result<()> {
    if cancelled(watch)? {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "DNS cancelled"));
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "DNS timed out"));
    }
    Ok(())
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_:%".contains(&b))
}

/// The same absolute deadline is used across all subscription redirects.
pub fn resolve(
    netloc: &str,
    deadline: Instant,
    watch: Option<&UnixStream>,
) -> io::Result<Vec<SocketAddr>> {
    let (host, port) = netloc
        .rsplit_once(':')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid DNS endpoint"))?;
    let port = port
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid DNS port"))?;
    resolve_host(
        host.trim_start_matches('[').trim_end_matches(']'),
        port,
        deadline,
        watch,
    )
}

pub fn resolve_host(
    host: &str,
    port: u16,
    deadline: Instant,
    watch: Option<&UnixStream>,
) -> io::Result<Vec<SocketAddr>> {
    check_budget(deadline, watch)?;
    if !valid_host(host) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid DNS host",
        ));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let path = crate::process::app_path().map_err(io::Error::other)?;
    let mut command = crate::process::child_command(&path);
    command.arg("--resolve-system");
    resolve_with(&mut command, host, port, deadline, watch)
}

struct Worker(Child);
impl Drop for Worker {
    fn drop(&mut self) {
        // No persistent state needs flushing. Kill immediately even if libc/NSS
        // is stuck; wait reaps the process on success, failure and cancellation.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn resolve_with(
    command: &mut Command,
    host: &str,
    port: u16,
    deadline: Instant,
    watch: Option<&UnixStream>,
) -> io::Result<Vec<SocketAddr>> {
    check_budget(deadline, watch)?;
    let mut worker = Worker(
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let input = serde_json::to_vec(&(host, port))?;
    worker
        .0
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("Missing DNS pipe"))?
        .write_all(&input)?;
    let pid = crate::process::pid_fd(&worker.0).map_err(io::Error::other)?;
    let mut fds = [
        crate::process::pollfd(pid.as_raw_fd(), libc::POLLIN),
        crate::process::pollfd(watch.map_or(-1, AsRawFd::as_raw_fd), libc::POLLIN),
    ];
    loop {
        check_budget(deadline, watch)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        let millis = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        let result = unsafe { libc::poll(fds.as_mut_ptr(), 2, millis) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        check_budget(deadline, watch)?;
        if fds[0].revents != 0 {
            break;
        }
    }
    if !worker.0.wait()?.success() {
        return Err(io::Error::other("System DNS failed"));
    }
    let mut reply = Vec::new();
    worker
        .0
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("Missing DNS reply"))?
        .take(MAX_REPLY + 1)
        .read_to_end(&mut reply)?;
    let addresses: Vec<SocketAddr> =
        serde_json::from_slice(&reply).map_err(|_| io::Error::other("Invalid DNS reply"))?;
    if reply.len() > MAX_REPLY as usize
        || addresses.is_empty()
        || addresses.len() > MAX_ADDRESSES
        || addresses.iter().any(|a| a.port() != port)
    {
        return Err(io::Error::other("Invalid DNS reply"));
    }
    Ok(addresses)
}

/// Internal CLI worker: hostname travels through stdin, never argv or a file.
pub fn worker() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().take(1025).read_to_end(&mut input)?;
    let (host, port): (String, u16) = serde_json::from_slice(&input)?;
    if input.len() > 1024 || !valid_host(&host) {
        return Err(io::Error::other("Invalid DNS request"));
    }
    let mut addresses = Vec::new();
    for address in (host.as_str(), port).to_socket_addrs()? {
        if !addresses.contains(&address) {
            addresses.push(address);
        }
        if addresses.len() == MAX_ADDRESSES {
            break;
        }
    }
    if addresses.is_empty() {
        return Err(io::Error::other("No DNS addresses"));
    }
    let output = serde_json::to_vec(&addresses)?;
    io::stdout().write_all(&output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn slow_worker() -> Command {
        let mut cmd = Command::new("python3");
        cmd.args(["-c", "import sys,time; sys.stdin.read(); time.sleep(30)"]);
        cmd
    }

    #[test]
    fn timeout_reaps_a_blocking_resolver() {
        let start = Instant::now();
        let result = resolve_with(
            &mut slow_worker(),
            "example.invalid",
            443,
            start + Duration::from_millis(100),
            None,
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn cancellation_interrupts_dns_without_waiting_for_its_deadline() {
        let (stop, watch) = UnixStream::pair().unwrap();
        let cancel = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(stop);
        });
        let start = Instant::now();
        let result = resolve_with(
            &mut slow_worker(),
            "example.invalid",
            443,
            start + Duration::from_secs(30),
            Some(&watch),
        );
        cancel.join().unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn numeric_addresses_need_no_worker_but_still_honor_deadlines() {
        let deadline = Instant::now() + Duration::from_secs(1);
        assert_eq!(
            resolve("127.0.0.1:443", deadline, None).unwrap()[0].port(),
            443
        );
        assert_eq!(
            resolve("[::1]:80", deadline, None).unwrap()[0].ip(),
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        );
        assert_eq!(
            resolve("127.0.0.1:443", Instant::now(), None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }
}
