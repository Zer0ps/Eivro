//! A session-scoped authorization and connection to the launchd-owned helper.
use crate::{
    Result,
    config::{ConnectRequest, Mode},
    platform::macos::{
        authorization::Grant,
        wait,
        wire::{self, Reply, Request},
    },
    process::{self, Event},
};
use std::{
    fs,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt},
            net::UnixStream,
        },
    },
    sync::Mutex,
    time::{Duration, Instant},
};
#[derive(Default)]
struct State {
    stream: Option<UnixStream>,
    grant: Option<Grant>,
}
#[derive(Default)]
pub struct Controller {
    state: Mutex<State>,
}
impl Controller {
    pub fn release(&self) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| "Помощник занят.")?;
        if let Some(mut stream) = state.stream.take() {
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .map_err(|_| "Канал помощника недоступен.")?;
            wire::send(&mut stream, &Request::Stop {})?;
            match wire::receive(&mut stream)? {
                Reply::Stopped => state.stream = Some(stream),
                Reply::Failed { message } => return Err(message),
                _ => return Err("Неверный ответ помощника.".into()),
            }
        }
        Ok(())
    }
    pub fn run_session(
        &self,
        request: &ConnectRequest,
        mode: Mode,
        watch: &UnixStream,
        notify: impl Fn(Event),
    ) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| "Помощник занят.")?;
        if mode != Mode::Local && state.grant.is_none() {
            notify(Event::Progress("Запрос прав macOS…"));
            let Some(grant) = Grant::acquire(watch)? else {
                return Ok(());
            };
            state.grant = Some(grant);
        }
        let mut stream = match state.stream.take() {
            Some(stream) => stream,
            None => connect()?,
        };
        let authorization = state.grant.as_ref().map(Grant::token);
        wire::send(
            &mut stream,
            &Request::Start {
                request: request.clone(),
                mode,
                authorization,
            },
        )?;
        let mut ready = false;
        let mut stopping = false;
        let mut deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let mut fds = [
                process::pollfd(if stopping { -1 } else { watch.as_raw_fd() }, libc::POLLIN),
                process::pollfd(stream.as_raw_fd(), libc::POLLIN),
            ];
            let timeout = if ready && !stopping {
                -1
            } else {
                deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis()
                    .clamp(1, i32::MAX as u128) as i32
            };
            let result = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout) };
            if result < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err("Ошибка ожидания помощника.".into());
            }
            if result == 0 || ((!ready || stopping) && Instant::now() >= deadline) {
                return Err("Истекло время ответа помощника. Соединение остановлено.".into());
            }
            if fds[0].revents != 0 {
                wire::send(&mut stream, &Request::Stop {})?;
                stopping = true;
                deadline = Instant::now() + Duration::from_secs(10);
            }
            if fds[1].revents != 0 {
                match wire::receive(&mut stream)? {
                    Reply::Checking => notify(Event::Progress("Проверка соединения…")),
                    Reply::Ready => {
                        ready = true;
                        if !stopping {
                            notify(Event::Running);
                        }
                    }
                    Reply::Stopped => {
                        state.stream = Some(stream);
                        return Ok(());
                    }
                    Reply::Denied => {
                        state.grant.take();
                        return Err(
                            "Права macOS больше не действуют. Повторите подключение.".into()
                        );
                    }
                    Reply::Failed { message } => {
                        return if stopping { Ok(()) } else { Err(message) };
                    }
                    _ => return Err("Неверный ответ помощника.".into()),
                }
            }
        }
    }
}
pub(crate) fn connect() -> Result<UnixStream> {
    let meta = fs::symlink_metadata(wire::SOCKET).map_err(|_| crate::platform::HELPER_HINT)?;
    if !meta.file_type().is_socket() || meta.uid() != 0 {
        return Err("Небезопасный канал системного помощника.".into());
    }
    let mut stream = UnixStream::connect(wire::SOCKET).map_err(|_| crate::platform::HELPER_HINT)?;
    if wait::peer(stream.as_raw_fd())
        .map_err(|_| "Не удалось проверить помощника.")?
        .0
        != 0
    {
        return Err("Неверный владелец системного помощника.".into());
    }
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| "Канал помощника недоступен.")?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| "Канал помощника недоступен.")?;
    match wire::receive(&mut stream)? {
        Reply::Hello { version } if version == env!("CARGO_PKG_VERSION") => Ok(stream),
        _ => Err("Версия системного помощника не совпадает. Обновите Eivro.pkg.".into()),
    }
}
