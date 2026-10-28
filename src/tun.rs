//! A privileged helper is authorized once per application lifetime. Its only
//! commands start/stop the pinned core with a validated typed request.
use crate::{Result, config::ConnectRequest, process};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    os::fd::{AsRawFd, OwnedFd},
    os::unix::net::UnixStream,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommandMessage {
    Start {
        request: ConnectRequest,
    },
    Stop {
        #[serde(default)]
        preserve_protection: bool,
    },
}
pub struct Running {
    pub primary: Child,
    pub secondary: Option<Child>,
}
impl Drop for Running {
    fn drop(&mut self) {
        process::terminate(&mut self.primary);
        if let Some(child) = &mut self.secondary {
            process::terminate(child);
        }
    }
}
pub trait Backend {
    fn start(&mut self, request: &ConnectRequest) -> Result<Running>;
    fn stop(&mut self, preserve_protection: bool) -> Result<()>;
}
struct LocalBackend<F>(F);
impl<F: FnMut(&ConnectRequest) -> Result<Child>> Backend for LocalBackend<F> {
    fn start(&mut self, request: &ConnectRequest) -> Result<Running> {
        Ok(Running {
            primary: (self.0)(request)?,
            secondary: None,
        })
    }
    fn stop(&mut self, _: bool) -> Result<()> {
        Ok(())
    }
}

/// Poll the pipe and core together so an idle/crashed GUI cannot leave a TUN.
/// The caller supplies the trusted launcher; the protocol accepts no executable paths.
pub fn serve(
    input: impl Read + AsRawFd,
    output: impl Write,
    start: impl FnMut(&ConnectRequest) -> Result<Child>,
) -> Result<()> {
    serve_backend(input, output, LocalBackend(start))
}

pub fn serve_backend(
    mut input: impl Read + AsRawFd,
    mut output: impl Write,
    mut backend: impl Backend,
) -> Result<()> {
    let mut core: Option<Running> = None;
    let mut pid: Option<OwnedFd> = None;
    let mut companion: Option<OwnedFd> = None;
    let mut pending = Vec::new();
    loop {
        let mut fds = [
            process::pollfd(input.as_raw_fd(), libc::POLLIN),
            process::pollfd(pid.as_ref().map_or(-1, AsRawFd::as_raw_fd), libc::POLLIN),
            process::pollfd(
                companion.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                libc::POLLIN,
            ),
        ];
        process::poll(&mut fds)?;
        if fds[1].revents != 0 || fds[2].revents != 0 {
            core.take();
            pid.take();
            companion.take();
            output
                .write_all(b"FAILED\n")
                .and_then(|_| output.flush())
                .map_err(|_| "reply")?;
        }
        if fds[0].revents != 0 {
            let mut buf = [0; 4096];
            let n = input.read(&mut buf).map_err(|_| "input")?;
            if n == 0 {
                return Ok(());
            }
            pending.extend_from_slice(&buf[..n]);
            while let Some(end) = pending.iter().position(|b| *b == b'\n') {
                if end > process::MAX_REQUEST {
                    return Err("size".into());
                }
                let message: CommandMessage =
                    serde_json::from_slice(&pending[..end]).map_err(|_| "request")?;
                pending.drain(..=end);
                core.take();
                pid.take();
                companion.take();
                let reply = match message {
                    CommandMessage::Stop {
                        preserve_protection,
                    } => {
                        if backend.stop(preserve_protection).is_ok() {
                            b"STOPPED\n".as_slice()
                        } else {
                            b"STOP_ERROR\n".as_slice()
                        }
                    }
                    CommandMessage::Start { request } => {
                        match backend.start(&request).and_then(|mut c| {
                            process::ready(&mut c.primary, request.port)?;
                            let p = process::pid_fd(&c.primary)?;
                            let companion =
                                c.secondary.as_ref().map(process::pid_fd).transpose()?;
                            Ok((c, p, companion))
                        }) {
                            Ok((c, p, secondary)) => {
                                companion = secondary;
                                core = Some(c);
                                pid = Some(p);
                                b"READY\n".as_slice()
                            }
                            Err(_) => b"START_ERROR\n".as_slice(),
                        }
                    }
                };
                output
                    .write_all(reply)
                    .and_then(|_| output.flush())
                    .map_err(|_| "reply")?;
            }
            if pending.len() > process::MAX_REQUEST {
                return Err("size".into());
            }
        }
    }
}

#[derive(Default)]
pub struct Controller {
    helper: Mutex<Option<Helper>>,
}
impl Controller {
    pub fn release(&self) -> Result<()> {
        let mut holder = self.helper.lock().map_err(|_| "Ошибка управления TUN.")?;
        if let Some(helper) = holder.as_mut() {
            helper.stop(false)?;
        }
        Ok(())
    }
    pub(crate) fn run(
        &self,
        req: &ConnectRequest,
        watch: &UnixStream,
        xray: i32,
        mut ready: impl FnMut(i32) -> Result<bool>,
    ) -> Result<()> {
        let mut holder = self.helper.lock().map_err(|_| "Ошибка управления TUN.")?;
        if holder
            .as_mut()
            .is_some_and(|h| h.child.try_wait().ok().flatten().is_some())
        {
            holder.take();
        }
        if holder.is_none() {
            *holder = Some(Helper::spawn()?);
        }
        let helper = holder.as_mut().unwrap();
        let mut started = false;
        let result = (|| {
            if !helper.start(req, watch, xray)? {
                return Ok(());
            }
            started = true;
            if !ready(helper.pid.as_raw_fd())? {
                return Ok(());
            }
            let mut fds = [
                process::pollfd(watch.as_raw_fd(), libc::POLLIN),
                process::pollfd(helper.pid.as_raw_fd(), libc::POLLIN),
                process::pollfd(helper.output.as_raw_fd(), libc::POLLIN),
                process::pollfd(xray, libc::POLLIN),
            ];
            process::poll(&mut fds)?;
            if fds[0].revents != 0 {
                Ok(())
            } else {
                Err("Соединение TUN остановлено: ядро завершилось.".into())
            }
        })();
        // Stop the core, keep the helper/authorization until the application closes.
        let preserve =
            req.kill_switch && (restart_requested(watch) || (result.is_err() && !cancelled(watch)));
        let stopped = if started || helper.request_sent {
            helper.stop(preserve)
        } else {
            Ok(())
        };
        if (!started && !helper.request_sent) || stopped.is_err() {
            holder.take();
        }
        result.and(stopped)
    }
}
fn cancelled(watch: &UnixStream) -> bool {
    let mut fd = process::pollfd(watch.as_raw_fd(), libc::POLLIN);
    unsafe { libc::poll(&mut fd, 1, 0) > 0 && fd.revents != 0 }
}
fn restart_requested(watch: &UnixStream) -> bool {
    let mut byte = 0u8;
    unsafe {
        libc::recv(
            watch.as_raw_fd(),
            (&mut byte as *mut u8).cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        ) == 1
            && byte == b'R'
    }
}
struct Helper {
    child: Child,
    input: Option<ChildStdin>,
    output: ChildStdout,
    pid: OwnedFd,
    pending: Vec<u8>,
    request_sent: bool,
}
impl Helper {
    fn spawn() -> Result<Self> {
        let child = Command::new("/usr/bin/pkexec")
            .arg(process::HELPER)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "Не удалось запросить права TUN.")?;
        Self::from_child(child)
    }
    fn from_child(mut child: Child) -> Result<Self> {
        let input = child.stdin.take().ok_or("Нет канала TUN.")?;
        let output = child.stdout.take().ok_or("Нет ответа TUN.")?;
        for fd in [input.as_raw_fd(), output.as_raw_fd()] {
            if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
                return Err("Нет канала TUN.".into());
            }
        }
        let pid = process::pid_fd(&child)?;
        Ok(Self {
            child,
            input: Some(input),
            output,
            pid,
            pending: Vec::new(),
            request_sent: false,
        })
    }
    fn read_lines(&mut self) -> Result<Vec<String>> {
        let mut b = [0; 128];
        match self.output.read(&mut b) {
            Ok(0) => return Err("Помощник TUN завершился.".into()),
            Ok(n) => self.pending.extend_from_slice(&b[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(vec![]),
            Err(_) => return Err("Ошибка ответа TUN.".into()),
        }
        if self.pending.len() > 256 {
            return Err("Неверный ответ TUN.".into());
        }
        let mut lines = vec![];
        while let Some(end) = self.pending.iter().position(|b| *b == b'\n') {
            lines.push(
                String::from_utf8(self.pending[..end].to_vec())
                    .map_err(|_| "Неверный ответ TUN.")?,
            );
            self.pending.drain(..=end);
        }
        Ok(lines)
    }
    fn start(&mut self, req: &ConnectRequest, watch: &UnixStream, xray: i32) -> Result<bool> {
        let mut data = serde_json::to_vec(&CommandMessage::Start {
            request: req.clone(),
        })
        .map_err(|_| "Ошибка настроек TUN.")?;
        data.push(b'\n');
        if data.len() > process::MAX_REQUEST {
            return Err("Слишком большая конфигурация TUN.".into());
        }
        self.request_sent = false;
        let mut offset = 0;
        loop {
            let input = self.input.as_mut().ok_or("Канал TUN закрыт.")?;
            let mut fds = [
                process::pollfd(watch.as_raw_fd(), libc::POLLIN),
                process::pollfd(self.pid.as_raw_fd(), libc::POLLIN),
                process::pollfd(
                    input.as_raw_fd(),
                    if offset < data.len() {
                        libc::POLLOUT
                    } else {
                        0
                    },
                ),
                process::pollfd(self.output.as_raw_fd(), libc::POLLIN),
                process::pollfd(xray, libc::POLLIN),
            ];
            process::poll(&mut fds)?;
            if fds[0].revents != 0 {
                return Ok(false);
            }
            if fds[1].revents != 0 {
                return Err("Доступ TUN отменён или помощник завершился.".into());
            }
            if fds[4].revents != 0 {
                return Err("Xray завершился во время запуска TUN.".into());
            }
            if fds[2].revents & libc::POLLOUT != 0 {
                match input.write(&data[offset..]) {
                    Ok(n) => {
                        offset += n;
                        self.request_sent = offset == data.len();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => return Err("Канал TUN закрыт.".into()),
                }
            }
            if fds[3].revents != 0 {
                let lines = self.read_lines()?;
                if lines
                    .iter()
                    .any(|s| s == "ERROR" || s == "START_ERROR" || s == "FAILED")
                {
                    return Err(
                        "Не удалось запустить TUN. Проверьте другой VPN и параметры сервера."
                            .into(),
                    );
                }
                if lines.len() == 1 && lines[0] == "READY" {
                    return Ok(true);
                }
                if !lines.is_empty() {
                    return Err("Неверный ответ TUN.".into());
                }
            }
        }
    }
    fn stop(&mut self, preserve_protection: bool) -> Result<()> {
        // A cancelled partial write cannot safely be followed by another JSON frame.
        // Closing the helper pipe in Drop remains the fallback for all protocol errors.
        let input = self.input.as_mut().ok_or("Канал TUN закрыт.")?;
        input
            .write_all(
                format!("{{\"command\":\"stop\",\"preserve_protection\":{preserve_protection}}}\n")
                    .as_bytes(),
            )
            .map_err(|_| "Не удалось остановить TUN.")?;
        let end = Instant::now() + Duration::from_secs(25);
        loop {
            let timeout = end
                .saturating_duration_since(Instant::now())
                .as_millis()
                .min(i32::MAX as u128) as i32;
            if timeout == 0 {
                return Err("Помощник TUN не ответил на остановку.".into());
            }
            let mut fds = [
                process::pollfd(self.output.as_raw_fd(), libc::POLLIN),
                process::pollfd(self.pid.as_raw_fd(), libc::POLLIN),
            ];
            if unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout) } < 0 {
                continue;
            }
            if fds[0].revents != 0 {
                let lines = self.read_lines()?;
                if lines.iter().any(|s| s == "STOP_ERROR" || s == "ERROR") {
                    return Err("Не удалось снять защиту TUN. Завершите Velum и используйте восстановление из README.".into());
                }
                if lines.iter().any(|s| s == "STOPPED") {
                    return Ok(());
                }
            }
            if fds[1].revents != 0 {
                return Err("Помощник TUN завершился.".into());
            }
        }
    }
}
impl Drop for Helper {
    fn drop(&mut self) {
        self.input.take(); // EOF releases root resources even when the GUI dies.
        // pkexec may still be waiting for authentication; this only succeeds while
        // it is unprivileged. An already-root helper exits via pipe EOF instead.
        let _ = self.child.kill();
        let mut fd = process::pollfd(self.pid.as_raw_fd(), libc::POLLIN);
        if unsafe { libc::poll(&mut fd, 1, 6000) } > 0 {
            let _ = self.child.wait();
        } else {
            let _ = self.child.kill();
            let _ = self.child.try_wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reconnect_preserves_guard_but_explicit_stop_releases_it() {
        let code = "import sys,json\ni=0\nfor line in sys.stdin:\n c=json.loads(line)\n if c['command']=='start': print('READY',flush=True)\n else:\n  assert c['preserve_protection']==(i==0),c\n  i+=1\n  print('STOPPED',flush=True)\n";
        let child = Command::new("python3")
            .args(["-u", "-c", code])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let controller = Controller {
            helper: Mutex::new(Some(Helper::from_child(child).unwrap())),
        };
        let request = ConnectRequest {
            uri: "synthetic".into(),
            bypass: vec![],
            policies: vec![],
            kill_switch: true,
            port: 2080,
            bridge_port: None,
            probe_port: None,
        };
        let (mut stop, watch) = UnixStream::pair().unwrap();
        controller
            .run(&request, &watch, -1, |_| {
                stop.write_all(b"R").unwrap();
                Ok(true)
            })
            .unwrap();
        controller.release().unwrap();
    }
    #[test]
    fn controller_reuses_one_authorized_process_for_multiple_connections() {
        let code = "import sys,json\nfor line in sys.stdin:\n c=json.loads(line)\n print('READY' if c['command']=='start' else 'STOPPED',flush=True)\n";
        let child = Command::new("python3")
            .args(["-u", "-c", code])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let id = child.id();
        let helper = Helper::from_child(child).unwrap();
        let controller = Controller {
            helper: Mutex::new(Some(helper)),
        };
        let req = ConnectRequest {
            uri: "synthetic".into(),
            bypass: vec![],
            port: 2080,
            bridge_port: None,
            probe_port: None,
            policies: vec![],
            kill_switch: false,
        };
        for cancelled_during_check in [false, true, false] {
            let (stop, watch) = UnixStream::pair().unwrap();
            let mut stop = Some(stop);
            controller
                .run(&req, &watch, -1, |_| {
                    stop.take();
                    Ok(!cancelled_during_check)
                })
                .unwrap();
            assert_eq!(
                controller
                    .helper
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .child
                    .id(),
                id
            );
        }
    }
}
