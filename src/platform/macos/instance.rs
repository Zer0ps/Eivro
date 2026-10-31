use eframe::egui;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::PathBuf,
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver},
    },
    thread::JoinHandle,
    time::Duration,
};
struct Endpoint {
    path: PathBuf,
    _lock: File,
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
pub struct Instance {
    stop: Option<UnixStream>,
    worker: Option<JoinHandle<()>>,
    pub events: Receiver<()>,
    context: Arc<Mutex<Option<egui::Context>>>,
    _endpoint: Endpoint,
}
impl Instance {
    pub fn acquire(scope: &str, show: bool) -> std::io::Result<Option<Self>> {
        let uid = unsafe { libc::geteuid() };
        let hash = scope.bytes().fold(0xcbf29ce484222325u64, |h, b| {
            h.wrapping_mul(0x100000001b3) ^ b as u64
        });
        // AF_UNIX paths on Darwin are short. Keep the endpoint in a private,
        // owner-checked directory, rather than truncating a configuration path.
        let dir = PathBuf::from(format!("/tmp/eivro-{uid}"));
        match fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        let meta = fs::symlink_metadata(&dir)?;
        if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        let path = dir.join(format!("{hash:016x}.sock"));
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(dir.join(format!("{hash:016x}.lock")))?;
        let meta = lock.metadata()?;
        if !meta.is_file() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let mut stream = UnixStream::connect(&path)?;
            if eivro::platform::macos::wait::peer(stream.as_raw_fd())?.0 != uid {
                return Err(std::io::ErrorKind::PermissionDenied.into());
            }
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            stream.set_write_timeout(Some(Duration::from_secs(2)))?;
            stream.write_all(if show { b"S" } else { b"P" })?;
            let mut reply = [0];
            stream.read_exact(&mut reply)?;
            if reply != *b"K" {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            return Ok(None);
        }
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if !meta.file_type().is_socket() || meta.uid() != uid {
                return Err(std::io::ErrorKind::PermissionDenied.into());
            }
            fs::remove_file(&path)?;
        }
        let listener = UnixListener::bind(&path)?;
        listener.set_nonblocking(true)?;
        let endpoint = Endpoint { path, _lock: lock };
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
                if let Ok((mut client, _)) = listener.accept() {
                    if eivro::platform::macos::wait::peer(client.as_raw_fd())
                        .ok()
                        .map(|p| p.0)
                        != Some(uid)
                    {
                        continue;
                    }
                    let _ = client.set_read_timeout(Some(Duration::from_millis(250)));
                    let _ = client.set_write_timeout(Some(Duration::from_millis(250)));
                    let mut action = [0];
                    if client.read_exact(&mut action).is_ok() && b"SP".contains(&action[0]) {
                        if action[0] == b'S' {
                            let _ = tx.send(());
                            if let Ok(ctx) = notify.lock()
                                && let Some(ctx) = &*ctx
                            {
                                ctx.request_repaint();
                            }
                        }
                        let _ = client.write_all(b"K");
                    }
                }
            }
        });
        Ok(Some(Self {
            stop: Some(stop),
            worker: Some(worker),
            events,
            context,
            _endpoint: endpoint,
        }))
    }
    pub fn set_context(&self, ctx: egui::Context) {
        if let Ok(mut value) = self.context.lock() {
            *value = Some(ctx);
        }
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
