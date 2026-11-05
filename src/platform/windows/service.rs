//! SCM-owned tunnel supervisor. The installer is the only elevated UI action.
//! Clients can supply validated connection policy, never paths or raw core JSON.
use super::{
    native::{self, Event, wide},
    pipe::Pipe,
};
use crate::{
    Result,
    config::Mode,
    platform::wire::{self, Reply, Request},
};
use std::{
    ptr,
    sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};
use windows_sys::Win32::{
    Foundation::*,
    System::{Services::*, Threading::*},
};
const NAME: &str = "EivroTunnel";
const AUTH_KEY: &str = r"SOFTWARE\Eivro\Tunnel";

pub fn authorized_user() -> Result<String> {
    use windows_sys::Win32::{
        Security::Authorization::ConvertStringSidToSidW, System::Registry::*,
    };
    let mut bytes = [0u16; 256];
    let mut length = std::mem::size_of_val(&bytes) as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            wide(AUTH_KEY).as_ptr(),
            wide("AllowedUserSid").as_ptr(),
            RRF_RT_REG_SZ,
            ptr::null_mut(),
            bytes.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if status != 0 || length < 4 || length as usize > std::mem::size_of_val(&bytes) {
        return Err("Установщик не разрешил доступ к TUN.".into());
    }
    let value = String::from_utf16(&bytes[..length as usize / 2 - 1])
        .map_err(|_| "Некорректный пользователь TUN.")?;
    if !value
        .bytes()
        .all(|b| b.is_ascii_digit() || b == b'S' || b == b'-')
    {
        return Err("Некорректный пользователь TUN.".into());
    }
    let mut sid = ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(wide(&value).as_ptr(), &mut sid) } == 0 {
        return Err("Некорректный пользователь TUN.".into());
    }
    unsafe {
        LocalFree(sid);
    }
    Ok(value)
}
fn authorize_installer() -> Result<()> {
    use windows_sys::Win32::System::Registry::*;
    if authorized_user().is_ok() {
        return Ok(());
    }
    let sid = native::installation_user_sid()
        .map_err(|_| "Не удалось определить пользователя установки.")?;
    let mut key = ptr::null_mut();
    if unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            wide(AUTH_KEY).as_ptr(),
            0,
            ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            ptr::null(),
            &mut key,
            ptr::null_mut(),
        )
    } != 0
    {
        return Err("Не удалось разрешить пользователю TUN.".into());
    }
    let value = wide(sid);
    let status = unsafe {
        RegSetValueExW(
            key,
            wide("AllowedUserSid").as_ptr(),
            0,
            REG_SZ,
            value.as_ptr().cast(),
            (value.len() * 2) as u32,
        )
    };
    unsafe {
        RegCloseKey(key);
    }
    if status != 0 {
        return Err("Не удалось сохранить разрешение TUN.".into());
    }
    Ok(())
}
static STOP: OnceLock<Event> = OnceLock::new();
static STATUS: AtomicUsize = AtomicUsize::new(0);
struct ServiceHandle(SC_HANDLE);
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}
fn open(access: u32) -> std::io::Result<ServiceHandle> {
    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let manager = ServiceHandle(manager);
    let service = unsafe { OpenServiceW(manager.0, wide(NAME).as_ptr(), access) };
    if service.is_null() {
        // Capture before the manager handle is dropped: CloseServiceHandle can
        // otherwise overwrite the error used to recognize a missing service.
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ServiceHandle(service))
    }
}
pub fn is_service_process(pid: u32) -> bool {
    let Ok(service) = open(SERVICE_QUERY_STATUS) else {
        return false;
    };
    let mut status: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
    let mut size = 0;
    unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            std::mem::size_of_val(&status) as u32,
            &mut size,
        ) != 0
            && status.dwProcessId == pid
            && status.dwCurrentState == SERVICE_RUNNING
    }
}
pub fn installed_version_matches() -> bool {
    let Ok(dir) = native::installed_dir() else {
        return false;
    };
    let binary = dir.join("eivro-tun.exe");
    if !native::protected_binary(&binary) || open(SERVICE_QUERY_STATUS).is_err() {
        return false;
    }
    crate::process::child_command(&binary)
        .arg("--version")
        .stdout(std::process::Stdio::piped())
        .output()
        .is_ok_and(|out| {
            out.status.success()
                && out.stdout == format!("Eivro TUN {}\n", env!("CARGO_PKG_VERSION")).as_bytes()
        })
}
fn set_status(state: u32, error: u32) {
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: error,
        dwServiceSpecificExitCode: u32::from(error == ERROR_SERVICE_SPECIFIC_ERROR),
        dwCheckPoint: 0,
        dwWaitHint: if state == SERVICE_STOP_PENDING {
            15000
        } else {
            0
        },
    };
    let handle = STATUS.load(Ordering::Acquire) as SERVICE_STATUS_HANDLE;
    if !handle.is_null() {
        unsafe {
            SetServiceStatus(handle, &status);
        }
    }
}
unsafe extern "system" fn control(
    code: u32,
    _event: u32,
    _data: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
) -> u32 {
    if code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN {
        set_status(SERVICE_STOP_PENDING, 0);
        if let Some(stop) = STOP.get() {
            stop.set();
        }
    }
    0
}
unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let handle =
        unsafe { RegisterServiceCtrlHandlerExW(wide(NAME).as_ptr(), Some(control), ptr::null()) };
    if handle.is_null() {
        return;
    }
    STATUS.store(handle as usize, Ordering::Release);
    let outcome = std::panic::catch_unwind(|| {
        let stop = Event::new().map_err(|_| "Нет события службы.")?;
        let _ = STOP.set(stop.clone());
        crate::privacy::harden().map_err(|_| "Не удалось защитить службу.")?;
        super::network_lease::recover()?;
        let dir = native::installed_dir().map_err(|_| "Нет каталога службы.")?;
        if ![
            "eivro-tun.exe",
            "sing-box.exe",
            "xray.exe",
            "wintun.dll",
            "libcronet.dll",
        ]
        .iter()
        .all(|name| native::protected_binary(&dir.join(name)))
        {
            return Err("Небезопасная установка службы.".into());
        }
        let mut pipe = Pipe::server().map_err(|_| "Не удалось создать защищённый канал службы.")?;
        set_status(SERVICE_RUNNING, 0);
        while !stop.signaled() {
            pipe.cancel = Some(stop.clone());
            pipe.finished = None;
            pipe.timeout = INFINITE;
            if pipe.connect().is_err() {
                if stop.signaled() {
                    break;
                }
                return Err("Ошибка канала службы.".into());
            }
            pipe.timeout = 10000;
            pipe.deadline = Some(std::time::Instant::now() + std::time::Duration::from_secs(10));
            let _ = serve(&mut pipe, &stop);
            // Also catches cleanup from a failed startup. Never accept another
            // lease while restoration of a previous connection is incomplete.
            super::network_lease::recover()?;
            pipe.deadline = None;
            pipe.disconnect();
        }
        Ok::<(), String>(())
    });
    set_status(
        SERVICE_STOPPED,
        if matches!(outcome, Ok(Ok(()))) {
            0
        } else {
            ERROR_SERVICE_SPECIFIC_ERROR
        },
    );
}
fn serve(pipe: &mut Pipe, stop: &Event) -> Result<()> {
    wire::send(
        pipe,
        &Reply::Hello {
            version: env!("CARGO_PKG_VERSION").into(),
        },
    )?;
    let Request::Start {
        request,
        mode,
        authorization,
    } = wire::receive(pipe)?
    else {
        return Err("Ожидалось начало соединения.".into());
    };
    if mode != Mode::Tun || authorization.is_some() {
        wire::send(pipe, &Reply::Denied)?;
        return Err("Недопустимая команда службы.".into());
    }
    crate::config::generate(&request, mode)?;
    pipe.deadline = None;
    let cancel = Event::new().map_err(|_| "Нет события соединения.")?;
    let finished = Event::new().map_err(|_| "Нет события завершения.")?;
    let mut output = pipe.writer().map_err(|_| "Нет канала ответа.")?;
    let signal = cancel.clone();
    let done = finished.clone();
    let worker = std::thread::spawn(move || {
        let result: Result<()> = (|| {
            let mut running = crate::process::start_cores(&request, mode, &signal, true)?;
            wire::send(&mut output, &Reply::Checking)?;
            if !crate::process::check_connection(
                &running,
                request.probe_port.unwrap_or(request.port),
                &signal,
            )? {
                running.shutdown()?;
                return Ok(());
            }
            if signal.signaled() {
                running.shutdown()?;
                return Ok(());
            }
            wire::send(&mut output, &Reply::Ready)?;
            let mut handles = vec![signal.handle(), native::raw(&running.primary)];
            if let Some(child) = &running.secondary {
                handles.push(native::raw(child));
            }
            let event = native::wait(&handles, INFINITE).map_err(|_| "Ошибка ожидания ядра.")?;
            running.shutdown()?;
            if event == Some(0) {
                Ok(())
            } else {
                Err("Ядро остановилось. Соединение закрыто.".into())
            }
        })();
        let reply = match &result {
            Ok(()) => Reply::Stopped,
            Err(message) if signal.signaled() && message == "Подключение отменено." => {
                Reply::Stopped
            }
            Err(message) => Reply::Failed {
                message: message.clone(),
            },
        };
        let _ = wire::send(&mut output, &reply);
        done.set();
        result
    });
    pipe.timeout = INFINITE;
    pipe.cancel = Some(stop.clone());
    pipe.finished = Some(finished);
    // EOF, stop, service shutdown and worker failure all converge on one cleanup.
    let _ = wire::receive::<Request>(pipe);
    cancel.set();
    worker
        .join()
        .map_err(|_| "Помощник не завершил соединение.")?
}
fn install() -> Result<()> {
    let path = std::env::current_exe().map_err(|_| "Нет пути службы.")?;
    if !native::protected_binary(&path) {
        return Err("Установите пакет в Program Files\\Eivro с защищёнными правами.".into());
    }
    authorize_installer()?;
    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CREATE_SERVICE) };
    if manager.is_null() {
        return Err("Для установки службы нужны права администратора.".into());
    }
    let manager = ServiceHandle(manager);
    let image = wide(format!("\"{}\" --service", path.display()));
    let created = unsafe {
        CreateServiceW(
            manager.0,
            wide(NAME).as_ptr(),
            wide("Eivro Tunnel").as_ptr(),
            SERVICE_START | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            image.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
        )
    };
    let service = if created.is_null() {
        if unsafe { GetLastError() } != ERROR_SERVICE_EXISTS {
            return Err("Не удалось зарегистрировать службу Eivro.".into());
        }
        let service = open(SERVICE_START | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS)
            .map_err(|_| "Не удалось открыть службу Eivro для обновления.")?;
        if unsafe {
            ChangeServiceConfigW(
                service.0,
                SERVICE_NO_CHANGE,
                SERVICE_AUTO_START,
                SERVICE_NO_CHANGE,
                image.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
            )
        } == 0
        {
            return Err("Не удалось обновить службу Eivro.".into());
        }
        service
    } else {
        ServiceHandle(created)
    };
    let mut actions = [
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 1000,
        },
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 5000,
        },
        SC_ACTION {
            Type: SC_ACTION_NONE,
            Delay: 0,
        },
    ];
    let failure = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: 86400,
        lpRebootMsg: ptr::null_mut(),
        lpCommand: ptr::null_mut(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
    };
    if unsafe {
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            (&failure as *const SERVICE_FAILURE_ACTIONSW).cast(),
        )
    } == 0
    {
        return Err("Не удалось настроить восстановление службы.".into());
    }
    if unsafe { StartServiceW(service.0, 0, ptr::null()) } == 0
        && unsafe { GetLastError() } != ERROR_SERVICE_ALREADY_RUNNING
    {
        return Err("Служба установлена, но запуск не удался.".into());
    }
    wait_state(&service, SERVICE_RUNNING)
}
fn wait_state(service: &ServiceHandle, desired: u32) -> Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    loop {
        if unsafe { QueryServiceStatus(service.0, &mut status) } == 0 {
            return Err("Не удалось проверить состояние службы.".into());
        }
        if status.dwCurrentState == desired {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline
            || (desired == SERVICE_RUNNING && status.dwCurrentState == SERVICE_STOPPED)
        {
            return Err("Служба не достигла ожидаемого состояния. Повторите установку.".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
fn stop_installed(remove: bool) -> Result<()> {
    close_installed_gui()?;
    let service = match open(
        SERVICE_START
            | SERVICE_STOP
            | SERVICE_QUERY_STATUS
            | if remove {
                windows_sys::Win32::Storage::FileSystem::DELETE
            } else {
                0
            },
    ) {
        Ok(service) => service,
        Err(e) if e.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) => return Ok(()),
        Err(_) => return Err("Не удалось открыть службу Eivro для остановки.".into()),
    };
    let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    if unsafe { QueryServiceStatus(service.0, &mut status) } == 0 {
        return Err("Не удалось проверить состояние службы.".into());
    }
    // An upgrade must be able to repair a stopped, failing old version. The new
    // service recovers its SYSTEM-owned journal before accepting any client.
    if status.dwCurrentState == SERVICE_STOPPED && !remove {
        return Ok(());
    }
    // Removal has no successor: recover in SYSTEM's identity before deleting it.
    if status.dwCurrentState == SERVICE_STOPPED {
        if unsafe { StartServiceW(service.0, 0, ptr::null()) } == 0 {
            return Err("Не удалось запустить восстановление сети перед удалением.".into());
        }
        wait_state(&service, SERVICE_RUNNING)?;
    }
    if status.dwCurrentState != SERVICE_STOP_PENDING
        && unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) } == 0
    {
        return Err("Не удалось остановить службу Eivro.".into());
    }
    wait_state(&service, SERVICE_STOPPED)?;
    if remove {
        if unsafe { DeleteService(service.0) } == 0 {
            return Err("Не удалось удалить службу Eivro.".into());
        }
        use windows_sys::Win32::System::Registry::*;
        let status = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, wide(AUTH_KEY).as_ptr()) };
        if status != 0 && status != ERROR_FILE_NOT_FOUND {
            return Err("Служба удалена, но не удалось убрать её разрешение.".into());
        }
    }
    Ok(())
}
fn close_installed_gui() -> Result<()> {
    use windows_sys::Win32::System::RestartManager::*;
    let path = native::installed_dir()
        .map_err(|_| "Нет каталога установки Eivro.")?
        .join("eivro.exe");
    if !path.exists() {
        return Ok(());
    }
    struct RestartSession(u32);
    impl Drop for RestartSession {
        fn drop(&mut self) {
            unsafe { RmEndSession(self.0) };
        }
    }
    let mut session = 0;
    let mut key = [0u16; 33];
    if unsafe { RmStartSession(&mut session, 0, key.as_mut_ptr()) } != ERROR_SUCCESS {
        return Err(
            "Не удалось подготовить завершение Eivro. Закройте приложение через трей.".into(),
        );
    }
    let session = RestartSession(session);
    let path = wide(path);
    let registered = unsafe {
        RmRegisterResources(session.0, 1, &path.as_ptr(), 0, ptr::null(), 0, ptr::null())
    };
    // Do not force termination or cross user sessions. Failure must precede
    // any service/file changes, leaving the existing installation usable.
    if registered != ERROR_SUCCESS || unsafe { RmShutdown(session.0, 0, None) } != ERROR_SUCCESS {
        return Err(
            "Закройте Eivro через трей во всех сеансах Windows и повторите установку или удаление."
                .into(),
        );
    }
    Ok(())
}
fn resume_installed() -> Result<()> {
    let service = open(SERVICE_START | SERVICE_QUERY_STATUS)
        .map_err(|_| "Не удалось открыть службу Eivro.")?;
    if unsafe { StartServiceW(service.0, 0, ptr::null()) } == 0
        && unsafe { GetLastError() } != ERROR_SERVICE_ALREADY_RUNNING
    {
        return Err("Не удалось восстановить работу службы Eivro.".into());
    }
    wait_state(&service, SERVICE_RUNNING)
}
pub fn main() {
    if crate::privacy::harden().is_err() {
        std::process::exit(1);
    }
    let args = std::env::args().collect::<Vec<_>>();
    let result = match args.get(1).map(String::as_str) {
        Some("--version") => {
            println!("Eivro TUN {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("--resolve-system") => crate::resolver::worker().map_err(|_| "Ошибка DNS.".into()),
        Some("--check-connection") => args
            .get(2)
            .and_then(|p| p.parse::<u16>().ok())
            .ok_or_else(|| "Нет порта проверки.".into())
            .and_then(crate::connectivity::check),
        Some("--stop-core") => {
            if args
                .get(2)
                .and_then(|value| value.parse().ok())
                .is_some_and(super::core_child::signal_worker)
            {
                Ok(())
            } else {
                Err("Не удалось завершить ядро.".into())
            }
        }
        Some("--install") => install(),
        Some("--stop") => stop_installed(false),
        Some("--resume") => resume_installed(),
        Some("--uninstall") => stop_installed(true),
        Some("--service") => {
            let name = wide(NAME);
            let table = [
                SERVICE_TABLE_ENTRYW {
                    lpServiceName: name.as_ptr().cast_mut(),
                    lpServiceProc: Some(service_main),
                },
                SERVICE_TABLE_ENTRYW {
                    lpServiceName: ptr::null_mut(),
                    lpServiceProc: None,
                },
            ];
            if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
                Err("Запустите помощник через службу Windows.".into())
            } else {
                Ok(())
            }
        }
        _ => Err("Неизвестная команда помощника.".into()),
    };
    if result.is_err() {
        std::process::exit(1);
    }
}
