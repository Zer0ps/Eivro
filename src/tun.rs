//! A privileged helper is authorized once per application lifetime. Its only
//! commands start/stop the pinned core with a validated typed request.
use crate::{Result, config::ConnectRequest, process};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    os::fd::{AsRawFd, OwnedFd},
    os::unix::net::UnixStream,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommandMessage {
    Retire {},
    Start {
        request: ConnectRequest,
    },
    Stop {
        #[serde(default)]
        preserve_protection: bool,
        #[serde(default)]
        preserve_dns: bool,
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
    fn preflight(&self, _request: &ConnectRequest) -> Result<()> {
        Ok(())
    }
    fn start(&mut self, request: &ConnectRequest) -> Result<Running>;
    fn stop(&mut self, preserve_protection: bool, preserve_dns: bool) -> Result<()>;
    fn retire(&mut self) -> Result<()> {
        Ok(())
    }
}
struct LocalBackend<F>(F);
impl<F: FnMut(&ConnectRequest) -> Result<Child>> Backend for LocalBackend<F> {
    fn start(&mut self, request: &ConnectRequest) -> Result<Running> {
        Ok(Running {
            primary: (self.0)(request)?,
            secondary: None,
        })
    }
    fn stop(&mut self, _: bool, _: bool) -> Result<()> {
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
    input: impl Read + AsRawFd,
    output: impl Write,
    backend: impl Backend,
) -> Result<()> {
    serve_backend_with_shutdown(input, output, backend, None)
}

/// The standalone helper supplies its signalfd; library callers keep their own
/// signal policy. The descriptor must remain open until this function returns.
pub fn serve_backend_with_shutdown(
    mut input: impl Read + AsRawFd,
    mut output: impl Write,
    mut backend: impl Backend,
    shutdown: Option<i32>,
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
            process::pollfd(shutdown.unwrap_or(-1), libc::POLLIN),
        ];
        process::poll(&mut fds)?;
        if fds[3].revents != 0 || fds[0].revents & libc::POLLHUP != 0 {
            // Stop the DNS-producing core before flushing its answers or
            // removing protection, including when a request is also pending.
            core.take();
            return backend.stop(false, false);
        }
        if fds[1].revents != 0 || fds[2].revents != 0 {
            core.take();
            pid.take();
            companion.take();
            // Flush stale answers even if the GUI cannot respond. A flush
            // failure must not drop the helper and its kill switch: report the
            // core failure and leave DNS cleanup pending for a later retry.
            let _ = backend.stop(true, false);
            output
                .write_all(b"FAILED\n")
                .and_then(|_| output.flush())
                .map_err(|_| "reply")?;
        }
        if fds[0].revents != 0 {
            let mut buf = [0; 4096];
            let n = input.read(&mut buf).map_err(|_| "input")?;
            if n == 0 {
                core.take();
                return backend.stop(false, false);
            }
            pending.extend_from_slice(&buf[..n]);
            while let Some(end) = pending.iter().position(|b| *b == b'\n') {
                if end > process::MAX_REQUEST {
                    return Err("size".into());
                }
                let message: CommandMessage =
                    serde_json::from_slice(&pending[..end]).map_err(|_| "request")?;
                pending.drain(..=end);
                // Reject predictable conflicts without dropping the current core.
                if let CommandMessage::Start { request } = &message
                    && let Err(error) = backend.preflight(request)
                {
                    let detail = if error.len() <= 384 && !error.chars().any(char::is_control) {
                        serde_json::to_string(&error).unwrap()
                    } else {
                        "\"Не удалось проверить настройки TUN.\"".to_owned()
                    };
                    writeln!(output, "START_ERROR {detail}")
                        .and_then(|_| output.flush())
                        .map_err(|_| "reply")?;
                    continue;
                }
                core.take();
                pid.take();
                companion.take();
                let mut failure = None;
                let mut failure_tag = "START_ERROR";
                let reply = match message {
                    CommandMessage::Retire {} => {
                        match backend.stop(false, false).and_then(|_| backend.retire()) {
                            Ok(()) => b"RETIRED\n".as_slice(),
                            Err(error) => {
                                failure = Some(error);
                                failure_tag = "RETIRE_ERROR";
                                b"RETIRE_ERROR\n".as_slice()
                            }
                        }
                    }
                    CommandMessage::Stop {
                        preserve_protection,
                        preserve_dns,
                    } => {
                        if backend.stop(preserve_protection, preserve_dns).is_ok() {
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
                            Err(error) => {
                                failure = Some(error);
                                b"START_ERROR\n".as_slice()
                            }
                        }
                    }
                };
                // A bounded, single-line reason is shown only in the local UI;
                // the helper still writes no diagnostic or traffic log.
                let detail = failure
                    .filter(|error| error.len() <= 384 && !error.chars().any(char::is_control))
                    .and_then(|error| serde_json::to_string(&error).ok())
                    .map(|error| format!("{failure_tag} {error}\n").into_bytes());
                let reply = detail.as_deref().unwrap_or(reply);
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
    authorization_denied: AtomicBool,
    cleanup_pending: AtomicBool,
}
pub const AUTHORIZATION_DENIED: &str = "Доступ TUN отменён.";
const CLEANUP_PENDING: &str = "Помощник TUN завершился без подтверждения очистки. Защита сети и память DNS могут остаться. Для восстановления доступа закройте Eivro и выполните pkexec /usr/libexec/eivro/eivro-tun --release (см. руководство). Очистку памяти DNS можно повторить после нового подключения TUN.";
impl Controller {
    pub fn authorization_denied(&self) -> bool {
        self.authorization_denied.load(Ordering::Acquire)
    }
    /// Only an explicit Connect action may permit a new authorization prompt.
    pub fn allow_authorization(&self) {
        self.authorization_denied.store(false, Ordering::Release);
    }
    pub fn retire(&self) -> Result<()> {
        let mut holder = self.helper.lock().map_err(|_| "Ошибка управления TUN.")?;
        self.remove_exited_helper(&mut holder);
        if let Some(helper) = holder.as_mut() {
            if let Err(error) = helper.retire() {
                self.remember_cleanup(helper);
                return Err(error);
            }
        } else if self.cleanup_pending.load(Ordering::Acquire) {
            return Err(CLEANUP_PENDING.into());
        }
        self.cleanup_pending.store(false, Ordering::Release);
        holder.take();
        Ok(())
    }
    pub fn release(&self) -> Result<()> {
        self.release_with_dns(false)
    }
    pub fn prepare(&self) -> Result<()> {
        self.release_with_dns(true)
    }
    fn release_with_dns(&self, preserve_dns: bool) -> Result<()> {
        let mut holder = self.helper.lock().map_err(|_| "Ошибка управления TUN.")?;
        self.remove_exited_helper(&mut holder);
        if let Some(helper) = holder.as_mut() {
            if let Err(error) = helper.stop(false, preserve_dns) {
                self.remember_cleanup(helper);
                return Err(error);
            }
            self.cleanup_pending.store(false, Ordering::Release);
        } else if !preserve_dns && self.cleanup_pending.load(Ordering::Acquire) {
            return Err(CLEANUP_PENDING.into());
        }
        Ok(())
    }
    fn remember_cleanup(&self, helper: &Helper) {
        // A complete Start can change DNS/firewall before READY is sent.
        // Confirmed pkexec refusal is the only case known not to have run it.
        if helper.was_ready || (helper.request_sent && !self.authorization_denied()) {
            self.cleanup_pending.store(true, Ordering::Release);
        }
    }
    fn remove_exited_helper(&self, holder: &mut Option<Helper>) {
        if holder
            .as_mut()
            .is_some_and(|helper| helper.child.try_wait().ok().flatten().is_some())
        {
            self.remember_cleanup(holder.as_ref().unwrap());
            holder.take();
        }
    }
    pub(crate) fn run(
        &self,
        req: &ConnectRequest,
        watch: &UnixStream,
        xray: i32,
        mut ready: impl FnMut(i32) -> Result<bool>,
    ) -> Result<()> {
        if self.authorization_denied() {
            return Err(AUTHORIZATION_DENIED.into());
        }
        let mut holder = self.helper.lock().map_err(|_| "Ошибка управления TUN.")?;
        self.remove_exited_helper(&mut holder);
        if holder.is_none() {
            *holder = Some(Helper::spawn()?);
        }
        let helper = holder.as_mut().unwrap();
        let mut started = false;
        let mut result = (|| {
            if !helper.start(req, watch, xray)? {
                return Ok(());
            }
            started = true;
            self.cleanup_pending.store(false, Ordering::Release);
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
        // pkexec may close stdout/its input before pidfd becomes readable.
        // Classify the exit status regardless of which pipe event won the race.
        if !started && result.is_err() {
            let mut fd = process::pollfd(helper.pid.as_raw_fd(), libc::POLLIN);
            unsafe {
                libc::poll(&mut fd, 1, 100);
            }
            if helper
                .child
                .try_wait()
                .ok()
                .flatten()
                .and_then(|s| s.code())
                .is_some_and(|code| code == 126 || code == 127)
            {
                self.authorization_denied.store(true, Ordering::Release);
                result = Err(AUTHORIZATION_DENIED.into());
            }
        }
        // Stop the core, keep the helper/authorization until the application closes.
        let reconnecting = restart_requested(watch) || (result.is_err() && !cancelled(watch));
        let preserve = req.kill_switch && reconnecting;
        let stopped = if started || helper.request_sent {
            helper.stop(preserve, reconnecting)
        } else {
            Ok(())
        };
        if (!started && !helper.request_sent) || stopped.is_err() {
            self.remember_cleanup(helper);
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
    was_ready: bool,
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
            was_ready: false,
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
        if self.pending.len() > 1024 {
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
                if let Some(detail) = lines
                    .iter()
                    .find_map(|line| line.strip_prefix("START_ERROR "))
                {
                    return Err(serde_json::from_str::<String>(detail)
                        .unwrap_or_else(|_| "Не удалось запустить TUN.".into()));
                }
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
                    self.was_ready = true;
                    return Ok(true);
                }
                if !lines.is_empty() {
                    return Err("Неверный ответ TUN.".into());
                }
            }
        }
    }
    fn retire(&mut self) -> Result<()> {
        self.command_reply(b"{\"command\":\"retire\"}\n", "RETIRED", "RETIRE_ERROR")
    }
    fn stop(&mut self, preserve_protection: bool, preserve_dns: bool) -> Result<()> {
        self.command_reply(format!("{{\"command\":\"stop\",\"preserve_protection\":{preserve_protection},\"preserve_dns\":{preserve_dns}}}\n").as_bytes(), "STOPPED", "STOP_ERROR")
    }
    fn command_reply(&mut self, message: &[u8], success: &str, failure: &str) -> Result<()> {
        // A cancelled partial write cannot safely be followed by another JSON frame.
        // Closing the helper pipe in Drop remains the fallback for all protocol errors.
        let input = self.input.as_mut().ok_or("Канал TUN закрыт.")?;
        input
            .write_all(message)
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
                if let Some(detail) = lines
                    .iter()
                    .find_map(|line| line.strip_prefix(&format!("{failure} ")))
                    .and_then(|detail| serde_json::from_str::<String>(detail).ok())
                {
                    return Err(detail);
                }
                if lines.iter().any(|s| s == failure || s == "ERROR") {
                    if failure == "RETIRE_ERROR" {
                        return Err("Не удалось безопасно очистить память DNS.".into());
                    }
                    return Err("Не удалось снять защиту TUN. Завершите Eivro и используйте восстановление из README.".into());
                }
                if lines.iter().any(|s| s == success) {
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
    fn helper_loss_before_ready_requires_cleanup_confirmation() {
        let child = Command::new("python3")
            .args(["-c", "import sys; sys.stdin.readline(); sys.exit(1)"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let controller = Controller {
            helper: Mutex::new(Some(Helper::from_child(child).unwrap())),
            ..Default::default()
        };
        let req: ConnectRequest =
            serde_json::from_str(r#"{"uri":"synthetic","bypass":[],"port":2080}"#).unwrap();
        let (_stop, watch) = UnixStream::pair().unwrap();
        assert!(
            controller
                .run(&req, &watch, -1, |_| panic!("not ready"))
                .is_err()
        );
        assert!(controller.release().is_err());
        assert!(controller.retire().is_err());
        assert!(controller.prepare().is_ok());
    }
    #[test]
    fn shutdown_precedes_pending_requests_and_reports_cleanup_failure() {
        struct Cleanup;
        impl Backend for Cleanup {
            fn start(&mut self, _: &ConnectRequest) -> Result<Running> {
                panic!("shutdown must take priority over requests");
            }
            fn stop(&mut self, protection: bool, dns: bool) -> Result<()> {
                assert!(!protection && !dns);
                Err("fixture cleanup failure".into())
            }
        }
        let (mut client, input) = UnixStream::pair().unwrap();
        client.write_all(b"invalid pending request\n").unwrap();
        let (mut signal, shutdown) = UnixStream::pair().unwrap();
        signal.write_all(b"S").unwrap();
        assert_eq!(
            serve_backend_with_shutdown(
                input,
                std::io::sink(),
                Cleanup,
                Some(shutdown.as_raw_fd()),
            )
            .unwrap_err(),
            "fixture cleanup failure"
        );
    }

    #[test]
    fn gui_eof_reports_cleanup_failure() {
        struct Cleanup;
        impl Backend for Cleanup {
            fn start(&mut self, _: &ConnectRequest) -> Result<Running> {
                panic!("EOF must not launch a core");
            }
            fn stop(&mut self, protection: bool, dns: bool) -> Result<()> {
                assert!(!protection && !dns);
                Err("fixture cleanup failure".into())
            }
        }
        let (client, input) = UnixStream::pair().unwrap();
        drop(client);
        assert_eq!(
            serve_backend(input, std::io::sink(), Cleanup).unwrap_err(),
            "fixture cleanup failure"
        );
    }

    #[test]
    fn closed_gui_pipe_cannot_start_its_buffered_request() {
        struct Cleanup;
        impl Backend for Cleanup {
            fn start(&mut self, _: &ConnectRequest) -> Result<Running> {
                panic!("a disconnected GUI must not start a core");
            }
            fn stop(&mut self, protection: bool, dns: bool) -> Result<()> {
                assert!(!protection && !dns);
                Ok(())
            }
        }
        let (mut client, input) = UnixStream::pair().unwrap();
        client.write_all(b"{\"command\":\"start\",\"request\":{\"uri\":\"synthetic\",\"port\":2080,\"bypass\":[],\"policies\":[],\"kill_switch\":false,\"connections\":[]}}\n").unwrap();
        // Parallel subprocess tests can briefly inherit a CLOEXEC descriptor
        // between fork and exec. Shut down the socket endpoint, not just this
        // reference, so the fixture really represents a hung-up channel.
        client.shutdown(std::net::Shutdown::Both).unwrap();
        drop(client);
        serve_backend(input, std::io::sink(), Cleanup).unwrap();
    }

    #[test]
    fn cancelled_authorization_is_latched_across_pipe_exit_races() {
        for code in [126, 127] {
            let child = Command::new("python3")
                .args(["-c", &format!("import os,time; time.sleep(.02); os.close(0); os.close(1); time.sleep(.02); os._exit({code})")])
                .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
            let controller = Controller {
                helper: Mutex::new(Some(Helper::from_child(child).unwrap())),
                ..Default::default()
            };
            let request = ConnectRequest {
                uri: "synthetic".into(),
                port: 2080,
                bypass: vec!["x".repeat(2048); 16],
                ru_preset: None,
                bridge_port: None,
                probe_port: None,
                policies: vec![],
                kill_switch: false,
                connections: vec![],
            };
            let (_stop, watch) = UnixStream::pair().unwrap();
            assert_eq!(
                controller
                    .run(&request, &watch, -1, |_| panic!("No authorization"))
                    .unwrap_err(),
                AUTHORIZATION_DENIED
            );
            assert!(controller.authorization_denied());
            for _ in 0..3 {
                assert_eq!(
                    controller
                        .run(&request, &watch, -1, |_| panic!("No retry"))
                        .unwrap_err(),
                    AUTHORIZATION_DENIED
                );
            }
            controller.allow_authorization();
            assert!(!controller.authorization_denied());
            assert!(controller.release().is_ok());
            assert!(controller.retire().is_ok());
        }
    }

    #[test]
    fn lost_ready_helper_keeps_cleanup_pending_until_a_successful_reconnect() {
        let spawn = |code: &str| {
            Helper::from_child(
                Command::new("python3")
                    .args(["-u", "-c", code])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()
                    .unwrap(),
            )
            .unwrap()
        };
        let controller = Controller {
            helper: Mutex::new(Some(spawn(
                "import sys,json\nfor line in sys.stdin:\n c=json.loads(line)\n if c['command']=='start': print('READY',flush=True)\n else: sys.exit(0)\n",
            ))),
            ..Default::default()
        };
        let request = ConnectRequest {
            uri: "synthetic".into(),
            port: 2080,
            bypass: vec![],
            ru_preset: None,
            bridge_port: None,
            probe_port: None,
            policies: vec![],
            kill_switch: true,
            connections: vec![],
        };
        let (stop, watch) = UnixStream::pair().unwrap();
        let mut stop = Some(stop);
        assert!(
            controller
                .run(&request, &watch, -1, |_| {
                    stop.take();
                    Ok(true)
                })
                .is_err()
        );
        assert!(controller.helper.lock().unwrap().is_none());
        assert_eq!(controller.release().unwrap_err(), CLEANUP_PENDING);
        assert_eq!(controller.retire().unwrap_err(), CLEANUP_PENDING);
        assert!(controller.prepare().is_ok());
        assert!(controller.helper.lock().unwrap().is_none());

        *controller.helper.lock().unwrap() = Some(spawn(
            "import sys,json\nfor line in sys.stdin:\n c=json.loads(line)\n print({'start':'READY','stop':'STOPPED','retire':'RETIRED'}[c['command']],flush=True)\n",
        ));
        let (stop, watch) = UnixStream::pair().unwrap();
        let mut stop = Some(stop);
        controller
            .run(&request, &watch, -1, |_| {
                stop.take();
                Ok(true)
            })
            .unwrap();
        assert!(!controller.cleanup_pending.load(Ordering::Acquire));
        controller.release().unwrap();
        controller.retire().unwrap();
    }

    #[test]
    fn idle_helper_exit_does_not_silently_release_saved_dns_state() {
        let mut helper = Helper::from_child(
            Command::new("true")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        )
        .unwrap();
        helper.was_ready = true;
        helper.child.wait().unwrap();
        let controller = Controller {
            helper: Mutex::new(Some(helper)),
            ..Default::default()
        };
        assert_eq!(controller.retire().unwrap_err(), CLEANUP_PENDING);
        assert_eq!(controller.release().unwrap_err(), CLEANUP_PENDING);
        assert!(controller.prepare().is_ok());
    }

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
            ..Default::default()
        };
        let request = ConnectRequest {
            ru_preset: None,
            connections: vec![],
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
            ..Default::default()
        };
        let req = ConnectRequest {
            ru_preset: None,
            connections: vec![],
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
