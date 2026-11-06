use eframe::egui;
use std::{
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        linux::net::SocketAddrExt,
        unix::net::{SocketAddr, UnixListener, UnixStream},
    },
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver},
    },
    thread::JoinHandle,
    time::Duration,
};

/// One instance per private settings location. Abstract sockets leave no files.
pub struct Instance {
    stop: Option<UnixStream>,
    worker: Option<JoinHandle<()>>,
    pub events: Receiver<()>,
    context: Arc<Mutex<Option<egui::Context>>>,
}
impl Instance {
    pub fn acquire(scope: &str, show: bool) -> std::io::Result<Option<Self>> {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            match Self::acquire_once(scope, show) {
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::BrokenPipe
                            | std::io::ErrorKind::UnexpectedEof
                    ) && std::time::Instant::now() < deadline =>
                {
                    // A closing instance (or a child between fork and exec)
                    // can briefly retain the abstract socket without a worker.
                    std::thread::sleep(Duration::from_millis(10));
                }
                result => return result,
            }
        }
    }
    fn acquire_once(scope: &str, show: bool) -> std::io::Result<Option<Self>> {
        let uid = unsafe { libc::geteuid() };
        let hash = scope.bytes().fold(0xcbf29ce484222325u64, |h, b| {
            (h ^ b as u64).wrapping_mul(0x100000001b3)
        });
        // Retain the pre-rename namespace to coordinate with a running Velum.
        let address = SocketAddr::from_abstract_name(format!("velum-{uid}-{hash:016x}"))?;
        let listener = match UnixListener::bind_addr(&address) {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                let mut stream = UnixStream::connect_addr(&address)?;
                if !same_user(&stream, uid) {
                    return Err(std::io::ErrorKind::PermissionDenied.into());
                }
                stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                stream.write_all(&[if show { b'S' } else { b'P' }])?;
                let mut ack = [0];
                stream.read_exact(&mut ack)?;
                if ack != *b"K" {
                    return Err(std::io::ErrorKind::InvalidData.into());
                }
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        listener.set_nonblocking(true)?;
        let (stop, watch) = UnixStream::pair()?;
        let (tx, events) = mpsc::channel();
        let context: Arc<Mutex<Option<egui::Context>>> = Arc::new(Mutex::new(None));
        let notify = context.clone();
        let worker = std::thread::spawn(move || {
            loop {
                let mut fds = [
                    eivro::process::pollfd(listener.as_raw_fd(), libc::POLLIN),
                    eivro::process::pollfd(watch.as_raw_fd(), libc::POLLIN),
                ];
                if eivro::process::poll(&mut fds).is_err() || fds[1].revents != 0 {
                    break;
                }
                if let Ok((mut stream, _)) = listener.accept() {
                    if !same_user(&stream, uid) {
                        continue;
                    }
                    // Match the launching client's budget: under CPU pressure
                    // it may be descheduled between connect and its one-byte send.
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let _ = stream.set_write_timeout(Some(Duration::from_millis(250)));
                    let mut command = [0];
                    if stream.read_exact(&mut command).is_ok() && b"SP".contains(&command[0]) {
                        if command[0] == b'S' {
                            let _ = tx.send(());
                            if let Ok(context) = notify.lock()
                                && let Some(ctx) = &*context
                            {
                                ctx.request_repaint();
                            }
                        }
                        let _ = stream.write_all(b"K");
                    }
                }
            }
        });
        Ok(Some(Self {
            stop: Some(stop),
            worker: Some(worker),
            events,
            context,
        }))
    }
    pub fn set_context(&self, ctx: egui::Context) {
        if let Ok(mut context) = self.context.lock() {
            *context = Some(ctx);
        }
    }
}
fn same_user(stream: &UnixStream, uid: u32) -> bool {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
    unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        ) == 0
            && cred.uid == uid
    }
}
impl Drop for Instance {
    fn drop(&mut self) {
        self.stop.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn activation_tolerates_a_delayed_client_after_connect() {
        let scope = format!("instance-delayed-{}", std::process::id());
        let first = Instance::acquire(&scope, true).unwrap().unwrap();
        let uid = unsafe { libc::geteuid() };
        let hash = scope.bytes().fold(0xcbf29ce484222325u64, |h, b| {
            (h ^ b as u64).wrapping_mul(0x100000001b3)
        });
        let address = SocketAddr::from_abstract_name(format!("velum-{uid}-{hash:016x}")).unwrap();
        let mut client = UnixStream::connect_addr(&address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        std::thread::sleep(Duration::from_millis(400));
        client.write_all(b"S").unwrap();
        let mut ack = [0];
        client.read_exact(&mut ack).unwrap();
        assert_eq!(ack, *b"K");
        first.events.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    #[test]
    fn second_launch_activates_existing_window_and_cleanup_releases_name() {
        let scope = format!("instance-test-{}", std::process::id());
        let first = Instance::acquire(&scope, true).unwrap().unwrap();
        assert!(Instance::acquire(&scope, true).unwrap().is_none());
        first.events.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(Instance::acquire(&scope, false).unwrap().is_none());
        assert!(first.events.try_recv().is_err());
        drop(first);
        assert!(Instance::acquire(&scope, true).unwrap().is_some());
    }
}
