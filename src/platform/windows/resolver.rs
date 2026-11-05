//! The existing bounded resolver protocol, with Windows process/event handles.
use crate::platform::windows::native::{Event, raw, wait};
use std::{
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    process::Stdio,
    time::Instant,
};
pub fn resolve(
    netloc: &str,
    deadline: Instant,
    watch: Option<&Event>,
) -> io::Result<Vec<SocketAddr>> {
    let (host, port) = netloc.rsplit_once(':').ok_or(io::ErrorKind::InvalidInput)?;
    resolve_host(
        host.trim_start_matches('[').trim_end_matches(']'),
        port.parse().map_err(|_| io::ErrorKind::InvalidInput)?,
        deadline,
        watch,
    )
}
pub fn resolve_host(
    host: &str,
    port: u16,
    deadline: Instant,
    watch: Option<&Event>,
) -> io::Result<Vec<SocketAddr>> {
    if host.is_empty()
        || host.len() > 253
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_:%".contains(&b))
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    if watch.is_some_and(Event::signaled) {
        return Err(io::ErrorKind::Interrupted.into());
    }
    if Instant::now() >= deadline {
        return Err(io::ErrorKind::TimedOut.into());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let mut child =
        crate::process::child_command(&crate::process::app_path().map_err(io::Error::other)?)
            .arg("--resolve-system")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
    let result = (|| {
        child
            .stdin
            .take()
            .ok_or(io::ErrorKind::BrokenPipe)?
            .write_all(&serde_json::to_vec(&(host, port))?)?;
        let mut handles = vec![raw(&child)];
        if let Some(event) = watch {
            handles.push(event.handle());
        }
        match wait(
            &handles,
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis()
                .clamp(1, u32::MAX as u128 - 1) as u32,
        )? {
            None => return Err(io::ErrorKind::TimedOut.into()),
            Some(1) => return Err(io::ErrorKind::Interrupted.into()),
            _ => {}
        }
        if !child.wait()?.success() {
            return Err(io::ErrorKind::NotFound.into());
        }
        let mut bytes = Vec::new();
        child
            .stdout
            .take()
            .ok_or(io::ErrorKind::BrokenPipe)?
            .take(4097)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 4096 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let addresses: Vec<SocketAddr> = serde_json::from_slice(&bytes)?;
        if addresses.is_empty()
            || addresses.len() > 32
            || addresses.iter().any(|a| a.port() != port)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(addresses)
    })();
    let _ = child.kill();
    let _ = child.wait();
    result
}
pub fn worker() -> io::Result<()> {
    let mut bytes = Vec::new();
    io::stdin().take(1025).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let (host, port): (String, u16) = serde_json::from_slice(&bytes)?;
    if host.is_empty()
        || host.len() > 253
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_:%".contains(&b))
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut addresses = Vec::new();
    for address in (host.as_str(), port).to_socket_addrs()?.take(32) {
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    if addresses.is_empty() {
        return Err(io::ErrorKind::NotFound.into());
    }
    io::stdout().write_all(&serde_json::to_vec(&addresses)?)
}
