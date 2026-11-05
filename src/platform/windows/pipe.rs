//! Bounded, overlapped local IPC. Cancellation completes before buffers are
//! released. A remote SMB connection can never enter the privileged protocol.
use super::native::{Event, SecurityDescriptor, owned, raw, wait, wide};
use std::{
    io::{self, Read, Write},
    os::windows::io::OwnedHandle,
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    Storage::FileSystem::*,
    System::{IO::*, Pipes::*, Threading::*},
};
pub const NAME: &str = r"\\.\pipe\io.eivro.tun.v1";
pub struct Pipe {
    handle: OwnedHandle,
    pub cancel: Option<Event>,
    pub finished: Option<Event>,
    pub timeout: u32,
    pub deadline: Option<std::time::Instant>,
}
impl Pipe {
    pub fn client() -> io::Result<Self> {
        Self::client_inner(None)
    }
    pub fn client_with_cancel(cancel: &Event) -> io::Result<Self> {
        Self::client_inner(Some(cancel))
    }
    fn client_inner(cancel: Option<&Event>) -> io::Result<Self> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if cancel.is_some_and(Event::signaled) {
                return Err(io::ErrorKind::ConnectionAborted.into());
            }
            // Startup/teardown only: allow the preceding lease to finish while
            // keeping cancellation responsive. Established sessions never poll.
            if unsafe { WaitNamedPipeW(wide(NAME).as_ptr(), 250) } != 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if !matches!(error.raw_os_error(), Some(code) if code == ERROR_SEM_TIMEOUT as i32 || code == ERROR_PIPE_BUSY as i32)
                || std::time::Instant::now() >= deadline
            {
                return Err(error);
            }
        }
        // FILE_CREATE_PIPE_INSTANCE is deliberately not granted to clients.
        let handle = unsafe {
            owned(CreateFileW(
                wide(NAME).as_ptr(),
                FILE_READ_DATA
                    | FILE_WRITE_DATA
                    | FILE_READ_ATTRIBUTES
                    | FILE_WRITE_ATTRIBUTES
                    | SYNCHRONIZE
                    | READ_CONTROL,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            ))
        }?;
        let mut pid = 0;
        if unsafe { GetNamedPipeServerProcessId(raw(&handle), &mut pid) } == 0
            || !super::service::is_service_process(pid)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Untrusted tunnel service",
            ));
        }
        Ok(Self {
            handle,
            cancel: cancel.cloned(),
            finished: None,
            timeout: 10000,
            deadline: None,
        })
    }
    pub fn server() -> io::Result<Self> {
        let owner = super::service::authorized_user().map_err(io::Error::other)?;
        let sd = SecurityDescriptor::new(&format!(
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;{owner})S:(ML;;NW;;;ME)"
        ))?;
        let handle = unsafe {
            owned(CreateNamedPipeW(
                wide(NAME).as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                16384,
                16384,
                5000,
                &sd.attributes(),
            ))
        }?;
        Ok(Self {
            handle,
            cancel: None,
            finished: None,
            timeout: 30000,
            deadline: None,
        })
    }
    pub fn writer(&self) -> io::Result<Self> {
        Ok(Self {
            handle: self.handle.try_clone()?,
            cancel: None,
            finished: None,
            timeout: 5000,
            deadline: None,
        })
    }
    pub fn connect(&self) -> io::Result<()> {
        let event = Event::new()?;
        let mut operation: OVERLAPPED = unsafe { std::mem::zeroed() };
        operation.hEvent = event.handle();
        let ok = unsafe { ConnectNamedPipe(raw(&self.handle), &mut operation) };
        if ok != 0 {
            return Ok(());
        }
        let error = unsafe { GetLastError() };
        if error == ERROR_PIPE_CONNECTED {
            return Ok(());
        }
        if error != ERROR_IO_PENDING {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        self.complete(&mut operation).map(|_| ())
    }
    pub fn disconnect(&self) {
        unsafe {
            DisconnectNamedPipe(raw(&self.handle));
        }
    }
    pub fn client_pid(&self) -> io::Result<u32> {
        let mut pid = 0;
        if unsafe { GetNamedPipeClientProcessId(raw(&self.handle), &mut pid) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(pid)
        }
    }
    fn complete(&self, operation: &mut OVERLAPPED) -> io::Result<usize> {
        let mut handles = vec![operation.hEvent];
        if let Some(cancel) = &self.cancel {
            handles.push(cancel.handle());
        }
        if let Some(finished) = &self.finished {
            handles.push(finished.handle());
        }
        let timeout = self.deadline.map_or(self.timeout, |deadline| {
            self.timeout.min(
                deadline
                    .saturating_duration_since(std::time::Instant::now())
                    .as_millis()
                    .min(u32::MAX as u128) as u32,
            )
        });
        let waiting = wait(&handles, timeout);
        if !matches!(waiting, Ok(Some(0))) {
            unsafe {
                CancelIoEx(raw(&self.handle), operation);
                WaitForSingleObject(operation.hEvent, INFINITE);
            }
            return match waiting {
                Ok(None) => Err(io::ErrorKind::TimedOut.into()),
                // Read::read_exact retries Interrupted; cancellation must be
                // terminal or a stopped session spins forever in the framing layer.
                Ok(Some(_)) => Err(io::ErrorKind::ConnectionAborted.into()),
                Err(e) => Err(e),
            };
        }
        let mut transferred = 0;
        if unsafe { GetOverlappedResult(raw(&self.handle), operation, &mut transferred, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(transferred as usize)
    }
    fn transfer(&self, buffer: *mut u8, len: usize, writing: bool) -> io::Result<usize> {
        if self.cancel.as_ref().is_some_and(Event::signaled) {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        if self
            .deadline
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
        {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let event = Event::new()?;
        let mut operation: OVERLAPPED = unsafe { std::mem::zeroed() };
        operation.hEvent = event.handle();
        let mut count = 0;
        let size = len.min(u32::MAX as usize) as u32;
        let ok = unsafe {
            if writing {
                WriteFile(raw(&self.handle), buffer, size, &mut count, &mut operation)
            } else {
                ReadFile(raw(&self.handle), buffer, size, &mut count, &mut operation)
            }
        };
        if ok != 0 {
            return Ok(count as usize);
        }
        let error = unsafe { GetLastError() };
        if !writing && error == ERROR_BROKEN_PIPE {
            return Ok(0);
        }
        if error != ERROR_IO_PENDING {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        self.complete(&mut operation)
    }
}
impl Read for Pipe {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.transfer(bytes.as_mut_ptr(), bytes.len(), false)
    }
}
impl Write for Pipe {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.transfer(bytes.as_ptr().cast_mut(), bytes.len(), true)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancelled_frame_is_terminal_instead_of_retried_by_read_exact() {
        let cancel = Event::new().unwrap();
        cancel.set();
        let mut pipe = Pipe {
            handle: std::fs::File::open("NUL").unwrap().into(),
            cancel: Some(cancel),
            finished: None,
            timeout: 100,
            deadline: None,
        };
        let mut frame = [0; 4];
        assert_eq!(
            pipe.read(&mut frame).unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            pipe.read_exact(&mut frame).unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
    }
}
