//! Confirmed, narrowly scoped repairs. DNS servers are never supplied by the UI.
use super::Action;
use crate::Result;
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    net::IpAddr,
    os::fd::AsRawFd,
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

const STALE: &str = "Сеть изменилась. Повторите диагностику перед исправлением.";
const CANCELLED: &str = "Исправление отменено.";
const FAILED: &str = "Исправление не выполнено. Повторите диагностику.";
const VERIFY_FAILED: &str = "Не удалось подтвердить DNS после исправления. Повторите диагностику; чужие изменения не отменяются.";
const AUTH_FAILED: &str =
    "Запрос прав отменён или помощник недоступен. Автоматического повтора не будет.";
const MAX_MESSAGE: usize = 512;

/// Only call after the user has confirmed the displayed action and its scope.
pub fn apply(action: &Action, expected_fingerprint: &str, cancel: Arc<AtomicBool>) -> Result<()> {
    apply_with(
        &System(Some(cancel.clone())),
        action,
        expected_fingerprint,
        &cancel,
    )
}

trait Actions {
    fn fingerprint(&self) -> Result<String>;
    fn flush(&self, cancel: &AtomicBool) -> Result<()>;
    fn recover_proxy(&self, cancel: &AtomicBool) -> Result<()>;
    fn restore_dns(&self, interface: &str, fingerprint: &str, cancel: &AtomicBool) -> Result<()>;
}

fn apply_with(
    backend: &impl Actions,
    action: &Action,
    expected: &str,
    cancel: &AtomicBool,
) -> Result<()> {
    check_cancel(cancel)?;
    if !matches!(
        action,
        Action::FlushDns | Action::RecoverProxy | Action::RestoreDns { .. }
    ) {
        return Err("Это действие выполняется в окне приложения.".into());
    }
    if expected.is_empty() || backend.fingerprint()? != expected {
        return Err(STALE.into());
    }
    check_cancel(cancel)?;
    match action {
        Action::FlushDns => backend.flush(cancel),
        Action::RecoverProxy => backend.recover_proxy(cancel),
        Action::RestoreDns { interface } => backend.restore_dns(interface, expected, cancel),
        _ => unreachable!(),
    }
}

struct System(Option<Arc<AtomicBool>>);
impl Actions for System {
    fn fingerprint(&self) -> Result<String> {
        match &self.0 {
            Some(cancel) => super::fingerprint_cancelled(cancel.clone()),
            None => super::fingerprint(),
        }
    }
    fn flush(&self, cancel: &AtomicBool) -> Result<()> {
        run_resolvectl(&["flush-caches"], Some(cancel))
    }
    fn recover_proxy(&self, cancel: &AtomicBool) -> Result<()> {
        // The existing recovery process retains its lock, ownership checks and
        // recovery journal if interrupted. It cannot overwrite another owner.
        let exe = std::env::current_exe().map_err(|_| FAILED)?;
        let mut command = Command::new(exe);
        command.arg("--recover-proxy");
        run_command(command, Duration::from_secs(45), Some(cancel))
    }
    fn restore_dns(&self, interface: &str, fingerprint: &str, cancel: &AtomicBool) -> Result<()> {
        super::dns_repair_interface_allowed(interface)?;
        super::restore_dns_candidate(interface)?;
        check_cancel(cancel)?;
        authorized_restore(interface, fingerprint, cancel)
    }
}

fn check_cancel(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(CANCELLED.into())
    } else {
        Ok(())
    }
}

fn run_command(mut command: Command, timeout: Duration, cancel: Option<&AtomicBool>) -> Result<()> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| FAILED)?;
    let end = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    Ok(())
                } else {
                    Err(FAILED.into())
                };
            }
            Ok(None) => {}
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(FAILED.into());
            }
        }
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) || Instant::now() >= end {
            let _ = child.kill();
            let _ = child.wait();
            return Err(if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                CANCELLED
            } else {
                FAILED
            }
            .into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn run_resolvectl(args: &[&str], cancel: Option<&AtomicBool>) -> Result<()> {
    let program = ["/usr/bin/resolvectl", "/bin/resolvectl"]
        .into_iter()
        .find(|p| crate::process::trusted_binary(Path::new(p)))
        .ok_or(FAILED)?;
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .arg("--no-ask-password")
        .args(args);
    run_command(command, Duration::from_secs(3), cancel)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DnsRequest {
    interface: String,
    fingerprint: String,
}

fn validate_request(request: &DnsRequest) -> Result<()> {
    crate::network::validate_interface(&request.interface).map_err(|_| FAILED)?;
    if request.fingerprint.is_empty()
        || request.fingerprint.len() > 128
        || !request.fingerprint.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(FAILED.into());
    }
    Ok(())
}

struct Helper {
    child: Child,
    authorized: bool,
}
impl Drop for Helper {
    fn drop(&mut self) {
        // Closing the request channel cancels the root-side preparation. Killing
        // pkexec succeeds while authorization is still pending; never retry it.
        self.child.stdin.take();
        if !self.authorized {
            let _ = self.child.kill();
        }
        let end = Instant::now() + Duration::from_secs(20);
        while Instant::now() < end {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

fn authorized_restore(interface: &str, fingerprint: &str, cancel: &AtomicBool) -> Result<()> {
    let request = DnsRequest {
        interface: interface.into(),
        fingerprint: fingerprint.into(),
    };
    validate_request(&request)?;
    if !crate::process::trusted_binary(Path::new(crate::process::HELPER)) {
        return Err(AUTH_FAILED.into());
    }
    let mut helper = Helper {
        child: Command::new("/usr/bin/pkexec")
            .args([crate::process::HELPER, "--repair-dns"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| AUTH_FAILED)?,
        authorized: false,
    };
    let mut output = helper.child.stdout.take().ok_or(AUTH_FAILED)?;
    let alive = || check_cancel(cancel).is_ok();
    match read_line(&mut output, Duration::from_secs(120), &alive)?.as_str() {
        "READY" => {}
        "UNSUPPORTED_NAMESPACE" => return Err("Восстановление DNS недоступно из отдельного сетевого пространства. Запустите установленный Eivro в обычном сеансе системы.".into()),
        "BUSY" => {
            return Err(
                "Помощник TUN занят. Закройте другие окна Eivro и повторите диагностику.".into(),
            );
        }
        _ => return Err(AUTH_FAILED.into()),
    }
    helper.authorized = true;
    check_cancel(cancel)?;
    let input = helper.child.stdin.as_mut().ok_or(AUTH_FAILED)?;
    let mut data = serde_json::to_vec(&request).map_err(|_| FAILED)?;
    data.push(b'\n');
    input.write_all(&data).map_err(|_| AUTH_FAILED)?;
    if read_line(&mut output, Duration::from_secs(40), &alive)? != "PREPARED" {
        return Err(STALE.into());
    }
    check_cancel(cancel)?;
    input.write_all(b"COMMIT\n").map_err(|_| AUTH_FAILED)?;
    // The helper completes verification/conditional rollback after committing,
    // even if the UI closes. It never leaves a half-finished repair on purpose.
    match read_line(&mut output, Duration::from_secs(40), &alive) {
        Ok(reply) if reply == "DONE" => Ok(()),
        Err(error) if error == CANCELLED => Err(
            "Отмена запрошена; начатое изменение DNS могло завершиться. Повторите диагностику."
                .into(),
        ),
        _ => Err(VERIFY_FAILED.into()),
    }
}

fn read_line(
    reader: &mut (impl Read + AsRawFd),
    timeout: Duration,
    alive: &impl Fn() -> bool,
) -> Result<String> {
    let end = Instant::now() + timeout;
    let mut bytes = Vec::new();
    while Instant::now() < end {
        if !alive() {
            return Err(CANCELLED.into());
        }
        let mut fd = crate::process::pollfd(reader.as_raw_fd(), libc::POLLIN);
        let ready = unsafe { libc::poll(&mut fd, 1, 25) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(FAILED.into());
        }
        if ready == 0 {
            continue;
        }
        let mut byte = [0];
        if reader.read(&mut byte).map_err(|_| FAILED)? != 1 {
            return Err(AUTH_FAILED.into());
        }
        if byte[0] == b'\n' {
            return String::from_utf8(bytes).map_err(|_| FAILED.into());
        }
        bytes.push(byte[0]);
        if bytes.len() > MAX_MESSAGE {
            return Err(FAILED.into());
        }
    }
    Err("Истекло время ожидания исправления. Автоматического повтора не будет.".into())
}

fn channel_alive(fd: i32) -> bool {
    let mut fd = crate::process::pollfd(fd, libc::POLLIN);
    // With no expected message, either extra data or EOF invalidates consent.
    unsafe { libc::poll(&mut fd, 1, 0) == 0 }
}

/// Privileged entry point. The caller must own the global TUN helper lock.
/// Only a physical, active NM link with an empty runtime DNS list is accepted.
pub fn serve_dns_repair(mut input: std::fs::File, mut output: impl Write) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(FAILED.into());
    }
    // A shared pathname D-Bus socket does not share the caller's network
    // namespace. Never send a local ifindex to another namespace's resolver.
    if same_bus_network(Path::new("/run/dbus/system_bus_socket")).is_err() {
        let _ = output.write_all(b"UNSUPPORTED_NAMESPACE\n");
        let _ = output.flush();
        return Err(FAILED.into());
    }
    output
        .write_all(b"READY\n")
        .and_then(|()| output.flush())
        .map_err(|_| FAILED)?;
    let line = read_line(&mut input, Duration::from_secs(10), &|| true)?;
    let request: DnsRequest = serde_json::from_str(&line).map_err(|_| FAILED)?;
    validate_request(&request)?;
    let servers = prepare_dns(&System(None), &request.interface, &request.fingerprint)?;
    if !channel_alive(input.as_raw_fd()) {
        return Err(CANCELLED.into());
    }
    output
        .write_all(b"PREPARED\n")
        .and_then(|()| output.flush())
        .map_err(|_| FAILED)?;
    if read_line(&mut input, Duration::from_secs(10), &|| true)? != "COMMIT" {
        return Err(CANCELLED.into());
    }
    let result = commit_dns(
        &System(None),
        &request.interface,
        &request.fingerprint,
        &servers,
        &|| channel_alive(input.as_raw_fd()),
    );
    output
        .write_all(if result.is_ok() {
            b"DONE\n"
        } else {
            b"ERROR\n"
        })
        .and_then(|()| output.flush())
        .map_err(|_| FAILED)?;
    result
}

fn same_bus_network(path: &Path) -> Result<()> {
    use std::os::unix::{fs::MetadataExt, net::UnixStream};
    let socket = UnixStream::connect(path).map_err(|_| FAILED)?;
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&peer) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
        || peer.pid <= 0
    {
        return Err(FAILED.into());
    }
    let own = std::fs::metadata("/proc/self/ns/net").map_err(|_| FAILED)?;
    let remote = std::fs::metadata(format!("/proc/{}/ns/net", peer.pid)).map_err(|_| FAILED)?;
    if (own.dev(), own.ino()) != (remote.dev(), remote.ino()) {
        return Err(FAILED.into());
    }
    Ok(())
}

trait DnsBackend {
    fn fingerprint(&self) -> Result<String>;
    fn allowed(&self, interface: &str) -> Result<()>;
    fn candidate(&self, interface: &str) -> Result<Vec<IpAddr>>;
    fn current(&self, interface: &str) -> Result<Vec<IpAddr>>;
    fn set(&self, interface: &str, servers: &[IpAddr]) -> Result<()>;
}
impl DnsBackend for System {
    fn fingerprint(&self) -> Result<String> {
        super::fingerprint()
    }
    fn allowed(&self, interface: &str) -> Result<()> {
        super::dns_repair_interface_allowed(interface)
    }
    fn candidate(&self, interface: &str) -> Result<Vec<IpAddr>> {
        super::restore_dns_candidate(interface)
    }
    fn current(&self, interface: &str) -> Result<Vec<IpAddr>> {
        super::runtime_dns(interface)
    }
    fn set(&self, interface: &str, servers: &[IpAddr]) -> Result<()> {
        let mut values = servers.iter().map(ToString::to_string).collect::<Vec<_>>();
        // An empty dns value clears only this field (resolvectl >=239). `revert`
        // would also clear routing domains and other settings we do not own.
        if values.is_empty() {
            values.push(String::new());
        }
        let mut args = vec!["dns", interface];
        args.extend(values.iter().map(String::as_str));
        run_resolvectl(&args, None)
    }
}

fn prepare_dns(backend: &impl DnsBackend, interface: &str, expected: &str) -> Result<Vec<IpAddr>> {
    backend.allowed(interface)?;
    if expected.is_empty() || backend.fingerprint()? != expected {
        return Err(STALE.into());
    }
    let servers = backend.candidate(interface)?;
    if servers.is_empty() || !backend.current(interface)?.is_empty() {
        return Err(STALE.into());
    }
    Ok(servers)
}

fn commit_dns(
    backend: &impl DnsBackend,
    interface: &str,
    expected: &str,
    prepared: &[IpAddr],
    alive: &impl Fn() -> bool,
) -> Result<()> {
    if !alive() {
        return Err(CANCELLED.into());
    }
    // Authentication and confirmation can take time. Re-read NM and resolved,
    // including the empty baseline, immediately before the one permitted write.
    if prepare_dns(backend, interface, expected)? != prepared {
        return Err(STALE.into());
    }
    if !alive() {
        return Err(CANCELLED.into());
    }
    let written = backend.set(interface, prepared);
    let verified = backend.current(interface);
    if written.is_ok() && verified.as_ref().is_ok_and(|dns| dns == prepared) {
        return Ok(());
    }
    // A failed CLI may still have changed resolved. Undo only if a fresh read
    // proves our complete value is still present; never wipe a concurrent owner.
    if backend.allowed(interface).is_ok()
        && backend.current(interface).is_ok_and(|dns| dns == prepared)
    {
        let _ = backend.set(interface, &[]);
    }
    Err(VERIFY_FAILED.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    fn pipe() -> (std::fs::File, std::fs::File) {
        use std::os::fd::FromRawFd;
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        unsafe {
            (
                std::fs::File::from_raw_fd(fds[1]),
                std::fs::File::from_raw_fd(fds[0]),
            )
        }
    }

    #[derive(Default)]
    struct Mock {
        stale: Cell<bool>,
        denied: Cell<bool>,
        candidate_changed: Cell<bool>,
        current: RefCell<Vec<IpAddr>>,
        writes: RefCell<Vec<Vec<IpAddr>>>,
        fail_write: Cell<bool>,
        external_change: Cell<bool>,
        reads_fail: Cell<bool>,
    }
    fn server() -> Vec<IpAddr> {
        vec!["192.0.2.53".parse().unwrap()]
    }
    fn other() -> Vec<IpAddr> {
        vec!["192.0.2.54".parse().unwrap()]
    }
    impl DnsBackend for Mock {
        fn fingerprint(&self) -> Result<String> {
            Ok(if self.stale.get() {
                "changed"
            } else {
                "original"
            }
            .into())
        }
        fn allowed(&self, _: &str) -> Result<()> {
            if self.denied.get() {
                Err(FAILED.into())
            } else {
                Ok(())
            }
        }
        fn candidate(&self, _: &str) -> Result<Vec<IpAddr>> {
            Ok(if self.candidate_changed.get() {
                other()
            } else {
                server()
            })
        }
        fn current(&self, _: &str) -> Result<Vec<IpAddr>> {
            if self.reads_fail.get() && !self.writes.borrow().is_empty() {
                return Err(FAILED.into());
            }
            Ok(self.current.borrow().clone())
        }
        fn set(&self, _: &str, servers: &[IpAddr]) -> Result<()> {
            self.writes.borrow_mut().push(servers.to_vec());
            *self.current.borrow_mut() = if self.external_change.get() {
                other()
            } else {
                servers.to_vec()
            };
            if self.fail_write.get() {
                Err(FAILED.into())
            } else {
                Ok(())
            }
        }
    }
    fn commit(mock: &Mock) -> Result<()> {
        commit_dns(mock, "enp1s0", "original", &server(), &|| true)
    }

    #[test]
    fn stale_network_or_changed_nm_dns_prevents_any_write() {
        let mock = Mock::default();
        mock.stale.set(true);
        assert!(commit(&mock).is_err());
        assert!(mock.writes.borrow().is_empty());
        mock.stale.set(false);
        mock.candidate_changed.set(true);
        assert!(commit(&mock).is_err());
        assert!(mock.writes.borrow().is_empty());
    }
    #[test]
    fn existing_dns_or_unowned_interface_prevents_any_write() {
        let mock = Mock::default();
        *mock.current.borrow_mut() = other();
        assert!(commit(&mock).is_err());
        assert!(mock.writes.borrow().is_empty());
        mock.current.borrow_mut().clear();
        mock.denied.set(true);
        assert!(commit(&mock).is_err());
        assert!(mock.writes.borrow().is_empty());
    }
    #[test]
    fn cancellation_before_commit_prevents_any_write() {
        let mock = Mock::default();
        assert!(commit_dns(&mock, "enp1s0", "original", &server(), &|| false).is_err());
        assert!(mock.writes.borrow().is_empty());
        let checks = Cell::new(0);
        assert!(
            commit_dns(&mock, "enp1s0", "original", &server(), &|| {
                checks.set(checks.get() + 1);
                checks.get() == 1
            })
            .is_err()
        );
        assert!(mock.writes.borrow().is_empty());
    }
    #[test]
    fn successful_restore_uses_fresh_nm_values_once() {
        let mock = Mock::default();
        assert!(commit(&mock).is_ok());
        assert_eq!(*mock.writes.borrow(), vec![server()]);
    }
    #[test]
    fn failed_write_rolls_back_only_its_own_dns_field() {
        let mock = Mock::default();
        mock.fail_write.set(true);
        assert!(commit(&mock).is_err());
        assert_eq!(*mock.writes.borrow(), vec![server(), vec![]]);
    }
    #[test]
    fn concurrent_dns_change_or_unreadable_state_is_never_cleared() {
        let mock = Mock::default();
        mock.external_change.set(true);
        assert!(commit(&mock).is_err());
        assert_eq!(*mock.writes.borrow(), vec![server()]);
        let mock = Mock::default();
        mock.reads_fail.set(true);
        assert!(commit(&mock).is_err());
        assert_eq!(*mock.writes.borrow(), vec![server()]);
    }
    #[test]
    fn request_rejects_extra_fields_and_unsafe_interface() {
        assert!(
            serde_json::from_str::<DnsRequest>(
                r#"{"interface":"enp1s0","fingerprint":"abcd","servers":["192.0.2.53"]}"#
            )
            .is_err()
        );
        for interface in ["-i", "../eth0", "eth0;true", "eivro0", ""] {
            assert!(
                validate_request(&DnsRequest {
                    interface: interface.into(),
                    fingerprint: "abcd".into()
                })
                .is_err()
            );
        }
    }
    struct NoActions(Cell<usize>);
    impl Actions for NoActions {
        fn fingerprint(&self) -> Result<String> {
            Ok("new".into())
        }
        fn flush(&self, _: &AtomicBool) -> Result<()> {
            self.0.set(self.0.get() + 1);
            Ok(())
        }
        fn recover_proxy(&self, _: &AtomicBool) -> Result<()> {
            self.0.set(self.0.get() + 1);
            Ok(())
        }
        fn restore_dns(&self, _: &str, _: &str, _: &AtomicBool) -> Result<()> {
            self.0.set(self.0.get() + 1);
            Ok(())
        }
    }
    #[test]
    fn all_mutations_reject_stale_report_or_cancellation() {
        let mock = NoActions(Cell::new(0));
        for action in [
            Action::FlushDns,
            Action::RecoverProxy,
            Action::RestoreDns {
                interface: "enp1s0".into(),
            },
        ] {
            assert!(apply_with(&mock, &action, "old", &AtomicBool::new(false)).is_err());
            assert!(apply_with(&mock, &action, "new", &AtomicBool::new(true)).is_err());
        }
        assert_eq!(mock.0.get(), 0);
    }

    #[test]
    fn closed_or_extra_input_revokes_prepared_authorization() {
        let (mut sender, receiver) = pipe();
        assert!(channel_alive(receiver.as_raw_fd()));
        sender.write_all(b"unexpected").unwrap();
        assert!(!channel_alive(receiver.as_raw_fd()));
        let (sender, receiver) = pipe();
        drop(sender);
        assert!(!channel_alive(receiver.as_raw_fd()));
    }

    #[test]
    fn protocol_input_is_bounded_and_cancellable_without_system_access() {
        let (mut sender, mut receiver) = pipe();
        sender.write_all(&vec![b'x'; MAX_MESSAGE + 1]).unwrap();
        assert!(read_line(&mut receiver, Duration::from_secs(1), &|| true).is_err());
        let (_sender, mut receiver) = pipe();
        let start = Instant::now();
        assert!(read_line(&mut receiver, Duration::from_secs(30), &|| false).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
