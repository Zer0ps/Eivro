//! Go cores need a console control event for graceful Windows teardown. Each
//! core gets a hidden console and an explicit inherited-handle list. It is put
//! in the owning Job before its first instruction; configurations use stdin.
use super::native::{self, Job, owned, raw, wide};
use crate::Result;
use std::{
    fs::File,
    io::{self, Write},
    os::windows::io::{AsRawHandle, OwnedHandle, RawHandle},
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::*,
    System::{Console::*, Pipes::*, SystemInformation::GetWindowsDirectoryW, Threading::*},
    UI::WindowsAndMessaging::SW_HIDE,
};
pub struct CoreChild {
    process: OwnedHandle,
    pid: u32,
    stopped: bool,
}
impl AsRawHandle for CoreChild {
    fn as_raw_handle(&self) -> RawHandle {
        raw(&self.process)
    }
}
struct Attributes {
    _buffer: Vec<usize>,
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.list);
        }
    }
}
impl CoreChild {
    pub fn spawn(path: &Path, args: &[&str], config: &[u8], job: &Job) -> Result<Self> {
        // All arguments are fixed application-owned tokens, never URI content.
        if !path.is_absolute()
            || path.to_string_lossy().contains(['"', '\0'])
            || args.iter().any(|arg| {
                !arg.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_:".contains(&b))
            })
        {
            return Err("Некорректная команда ядра.".into());
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: ptr::null_mut(),
            bInheritHandle: 1,
        };
        let mut input = ptr::null_mut();
        let mut writer = ptr::null_mut();
        if unsafe { CreatePipe(&mut input, &mut writer, &sa, 0) } == 0 {
            return Err("Не удалось создать канал ядра.".into());
        }
        let input = unsafe { owned(input) }.map_err(|_| "Нет входа ядра.")?;
        let writer = unsafe { owned(writer) }.map_err(|_| "Нет канала конфигурации.")?;
        if unsafe { SetHandleInformation(raw(&writer), HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err("Не удалось ограничить наследование канала.".into());
        }
        let null = unsafe {
            owned(CreateFileW(
                wide("NUL").as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &sa,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            ))
        }
        .map_err(|_| "Не удалось отключить журналы ядра.")?;
        let mut size = 0;
        unsafe {
            InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut size);
        }
        let mut buffer = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
        let list = buffer.as_mut_ptr().cast();
        if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) } == 0 {
            return Err("Не удалось подготовить процесс ядра.".into());
        }
        let attributes = Attributes {
            _buffer: buffer,
            list,
        };
        let handles = [raw(&input), raw(&null)];
        if unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                std::mem::size_of_val(&handles),
                ptr::null_mut(),
                ptr::null(),
            )
        } == 0
        {
            return Err("Не удалось ограничить дескрипторы ядра.".into());
        }
        let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        startup.StartupInfo.cb = std::mem::size_of_val(&startup) as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        startup.StartupInfo.wShowWindow = SW_HIDE as u16;
        startup.StartupInfo.hStdInput = raw(&input);
        startup.StartupInfo.hStdOutput = raw(&null);
        startup.StartupInfo.hStdError = raw(&null);
        startup.lpAttributeList = attributes.list;
        let mut windows = [0u16; 32768];
        let count =
            unsafe { GetWindowsDirectoryW(windows.as_mut_ptr(), windows.len() as u32) } as usize;
        if count == 0 || count >= windows.len() {
            return Err("Не найден системный каталог Windows.".into());
        }
        let windows = String::from_utf16_lossy(&windows[..count]);
        let environment: Vec<u16> =
            format!("PATH={windows}\\System32\0SystemRoot={windows}\0WINDIR={windows}\0\0")
                .encode_utf16()
                .collect();
        let mut command = wide(format!("\"{}\" {}", path.display(), args.join(" ")));
        let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let directory = wide(path.parent().ok_or("Нет каталога ядра.")?);
        if unsafe {
            CreateProcessW(
                wide(path).as_ptr(),
                command.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                1,
                CREATE_NEW_CONSOLE
                    | CREATE_SUSPENDED
                    | CREATE_UNICODE_ENVIRONMENT
                    | EXTENDED_STARTUPINFO_PRESENT,
                environment.as_ptr().cast(),
                directory.as_ptr(),
                &startup.StartupInfo,
                &mut process,
            )
        } == 0
        {
            return Err("Windows не удалось запустить ядро.".into());
        }
        let handle = unsafe { owned(process.hProcess) }.map_err(|_| "Нет дескриптора ядра.")?;
        let thread = unsafe { owned(process.hThread) }.map_err(|_| "Нет потока ядра.")?;
        let mut child = Self {
            process: handle,
            pid: process.dwProcessId,
            stopped: false,
        };
        if job.assign(&child).is_err() {
            child.kill();
            return Err("Не удалось изолировать процесс ядра.".into());
        }
        if unsafe { ResumeThread(raw(&thread)) } == u32::MAX {
            child.kill();
            return Err("Не удалось продолжить запуск ядра.".into());
        }
        drop(input);
        drop(null);
        drop(attributes);
        drop(thread);
        if File::from(writer).write_all(config).is_err() {
            child.stop();
            return Err("Не удалось передать конфигурацию ядру.".into());
        }
        Ok(child)
    }
    pub fn exited(&self) -> io::Result<bool> {
        native::wait(&[raw(self)], 0).map(|event| event.is_some())
    }
    fn kill(&mut self) {
        unsafe {
            TerminateProcess(raw(self), 1);
            WaitForSingleObject(raw(self), 5000);
        }
        self.stopped = true;
    }
    pub fn stop(&mut self) {
        if self.stopped {
            return;
        }
        if self.exited().unwrap_or(false) {
            self.stopped = true;
            return;
        }
        if let Ok(exe) = crate::process::app_path()
            && let Ok(mut signal) = crate::process::child_command(&exe)
                .args(["--stop-core", &self.pid.to_string()])
                .spawn()
        {
            let _ = native::wait(&[raw(&signal)], 2000);
            let _ = signal.kill();
            let _ = signal.wait();
        }
        if matches!(native::wait(&[raw(self)], 3000), Ok(Some(_))) {
            self.stopped = true;
        } else {
            self.kill();
        }
    }
}
impl Drop for CoreChild {
    fn drop(&mut self) {
        self.stop();
    }
}
unsafe extern "system" fn ignore_control(_: u32) -> i32 {
    1
}
pub fn signal_worker(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    unsafe {
        if AttachConsole(pid) == 0 {
            return false;
        }
        SetConsoleCtrlHandler(Some(ignore_control), 1);
        let result = GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0) != 0;
        // The helper is the only temporary second console client. Give its
        // handler time to consume the event before detaching and exiting.
        Sleep(50);
        FreeConsole();
        result
    }
}
