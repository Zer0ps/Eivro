use eframe::egui;
use eivro::platform::windows::native::{self, Event, SecurityDescriptor, owned, raw, wide};
use std::{
    io,
    os::windows::io::OwnedHandle,
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver},
    },
    thread,
    time::Duration,
};
use windows_sys::Win32::{Foundation::*, System::Threading::*};
pub struct Instance {
    _mutex: OwnedHandle,
    stop: Event,
    worker: Option<thread::JoinHandle<()>>,
    pub events: Receiver<()>,
    context: Arc<Mutex<Option<egui::Context>>>,
}
impl Instance {
    pub fn acquire(scope: &str, show: bool) -> io::Result<Option<Self>> {
        let sid = native::user_sid()?;
        let hash = scope.bytes().fold(0xcbf29ce484222325u64, |h, b| {
            (h ^ b as u64).wrapping_mul(0x100000001b3)
        });
        let name = format!("Local\\Eivro-{sid}-{hash:016x}");
        let activation = wide(format!("{name}-show"));
        let sd = SecurityDescriptor::new(&format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})"))?;
        let handle = unsafe { CreateMutexW(&sd.attributes(), 0, wide(&name).as_ptr()) };
        let existing = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
        let mutex = unsafe { owned(handle) }?;
        if existing {
            if show {
                let deadline = std::time::Instant::now() + Duration::from_secs(2);
                loop {
                    if let Ok(event) =
                        unsafe { owned(OpenEventW(EVENT_MODIFY_STATE, 0, activation.as_ptr())) }
                    {
                        unsafe {
                            SetEvent(raw(&event));
                        }
                        break;
                    }
                    if std::time::Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "Existing window is starting",
                        ));
                    }
                    thread::sleep(Duration::from_millis(20));
                }
            }
            return Ok(None);
        }
        let activated =
            unsafe { owned(CreateEventW(&sd.attributes(), 0, 0, activation.as_ptr())) }?;
        let stop = Event::new()?;
        let stopped = stop.clone();
        let (tx, events) = mpsc::channel();
        let context: Arc<Mutex<Option<egui::Context>>> = Arc::new(Mutex::new(None));
        let wake = context.clone();
        let worker = thread::spawn(move || {
            while let Ok(Some(0)) = native::wait(&[raw(&activated), stopped.handle()], INFINITE) {
                let _ = tx.send(());
                if let Ok(context) = wake.lock()
                    && let Some(context) = &*context
                {
                    context.request_repaint();
                }
            }
        });
        Ok(Some(Self {
            _mutex: mutex,
            stop,
            worker: Some(worker),
            events,
            context,
        }))
    }
    pub fn set_context(&self, ctx: egui::Context) {
        if let Ok(mut current) = self.context.lock() {
            *current = Some(ctx);
        }
    }
}
impl Drop for Instance {
    fn drop(&mut self) {
        self.stop.set();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
