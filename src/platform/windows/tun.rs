use crate::platform::windows::{native::Event, pipe::Pipe};
use crate::{
    Result,
    config::{ConnectRequest, Mode},
    platform::wire::{self, Reply, Request},
    process::Event as ProcessEvent,
};
use std::sync::Mutex;
#[derive(Default)]
pub struct Controller {
    state: Mutex<()>,
}
impl Controller {
    pub fn release(&self) -> Result<()> {
        Ok(())
    }
    pub fn run_session(
        &self,
        request: &ConnectRequest,
        mode: Mode,
        cancel: &Event,
        notify: impl Fn(ProcessEvent),
    ) -> Result<()> {
        let _lock = self.state.lock().map_err(|_| "Помощник занят.")?;
        let mut pipe = Pipe::client_with_cancel(cancel).map_err(|error| {
            if cancel.signaled() {
                return "Подключение отменено.";
            }
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                "Служба TUN недоступна для этой учётной записи Windows."
            } else if error.kind() == std::io::ErrorKind::TimedOut
                || error.raw_os_error()
                    == Some(windows_sys::Win32::Foundation::ERROR_PIPE_BUSY as i32)
            {
                "Служба TUN ещё занята предыдущим соединением. Повторите подключение."
            } else {
                crate::platform::HELPER_HINT
            }
        })?;
        pipe.cancel = Some(cancel.clone());
        match wire::receive(&mut pipe)? {
            Reply::Hello { version } if version == env!("CARGO_PKG_VERSION") => {}
            _ => return Err("Обновите системного помощника Eivro до этой версии.".into()),
        }
        wire::send(
            &mut pipe,
            &Request::Start {
                request: request.clone(),
                mode,
                authorization: None,
            },
        )?;
        pipe.timeout = 60000;
        loop {
            let reply = wire::receive::<Reply>(&mut pipe);
            if cancel.signaled() {
                // A cancelled read may have consumed part of a frame. Closing
                // the lease cancels the service without trying to resync it.
                drop(pipe);
                if unsafe {
                    windows_sys::Win32::System::Pipes::WaitNamedPipeW(
                        crate::platform::windows::native::wide(
                            crate::platform::windows::pipe::NAME,
                        )
                        .as_ptr(),
                        10000,
                    )
                } == 0
                {
                    return Err("Помощник ещё завершает соединение. Повторите попытку.".into());
                }
                return Ok(());
            }
            match reply? {
                Reply::Checking => notify(ProcessEvent::Progress("Проверка соединения…")),
                Reply::Ready => {
                    notify(ProcessEvent::Running);
                    pipe.timeout = u32::MAX;
                }
                Reply::Stopped => return Ok(()),
                Reply::Failed { message } => return Err(message),
                _ => return Err("Некорректный ответ помощника Windows.".into()),
            }
        }
    }
}
