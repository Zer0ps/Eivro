//! AppKit status item and SystemConfiguration/NSWorkspace notifications. All
//! native UI objects live on the main thread; no periodic polling is needed.
use crate::{Result, platform::macos::native};
use std::{
    ffi::c_void,
    path::{Path, PathBuf},
    sync::{
        Arc,
        mpsc::{self, Receiver, Sender},
    },
};
#[derive(Debug)]
pub enum Event {
    Show,
    Toggle,
    Quit,
    Network(bool),
    Sleep(bool),
    MonitorUnavailable,
    DnsChanged,
    TrayOnline(bool),
    Settings,
}
struct Sink {
    tx: Sender<Event>,
    wake: Arc<dyn Fn() + Send + Sync>,
}
pub struct Desktop {
    pub events: Receiver<Event>,
    handle: *mut c_void,
    _sink: Box<Sink>,
    last: Option<(bool, bool)>,
    dark: Option<bool>,
}
extern "C" fn callback(context: *mut c_void, code: i32, state: bool) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let sink = unsafe { &*(context as *const Sink) };
        let event = match code {
            0 => Event::Show,
            1 => Event::Toggle,
            2 => Event::Quit,
            3 => Event::Network(state),
            4 => Event::Sleep(state),
            5 => Event::DnsChanged,
            6 => Event::TrayOnline(state),
            7 => Event::MonitorUnavailable,
            8 => Event::Settings,
            _ => return,
        };
        let _ = sink.tx.send(event);
        (sink.wake)();
    }));
}
impl Desktop {
    pub fn start(wake: Arc<dyn Fn() + Send + Sync>) -> Self {
        let (tx, events) = mpsc::channel();
        let mut sink = Box::new(Sink { tx, wake });
        let handle =
            unsafe { native::eivro_desktop_start(callback, (&mut *sink as *mut Sink).cast()) };
        if handle.is_null() {
            let _ = sink.tx.send(Event::MonitorUnavailable);
        }
        Self {
            events,
            handle,
            _sink: sink,
            last: None,
            dark: None,
        }
    }
    pub fn appearance(&mut self, dark: bool) {
        if !self.handle.is_null() && self.dark != Some(dark) {
            unsafe {
                native::eivro_desktop_appearance(dark);
            }
            self.dark = Some(dark);
        }
    }
    pub fn update(&mut self, running: bool, wanted: bool, _: &str) {
        if !self.handle.is_null() && self.last != Some((running, wanted)) {
            unsafe {
                native::eivro_desktop_update(self.handle, running, wanted);
            }
            self.last = Some((running, wanted));
        }
    }
}
impl Drop for Desktop {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                native::eivro_desktop_stop(self.handle);
            }
        }
    }
}
pub fn migrate_autostart() -> Result<()> {
    Ok(())
}
pub fn autostart_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or("Нет домашнего каталога.")?;
    Ok(PathBuf::from(home).join("Library/LaunchAgents/io.eivro.Client.plist"))
}
fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
pub fn set_autostart(path: &Path, executable: &Path, enabled: bool) -> Result<()> {
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    };
    if path != autostart_path()? {
        return Err("Неверный путь автозапуска.".into());
    }
    if let Ok(meta) = fs::symlink_metadata(path)
        && (!meta.is_file() || meta.uid() != unsafe { libc::geteuid() })
    {
        return Err("Небезопасный файл автозапуска.".into());
    }
    if !enabled {
        return match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            _ => Err("Не удалось отключить автозапуск.".into()),
        };
    }
    if !executable.is_absolute() || executable.to_string_lossy().contains("AppTranslocation") {
        return Err("Сначала установите Eivro в Applications.".into());
    }
    let parent = path.parent().ok_or("Нет каталога автозапуска.")?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .map_err(|_| "Не удалось создать каталог автозапуска.")?;
    let meta = fs::symlink_metadata(parent).map_err(|_| "Не удалось проверить автозапуск.")?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
        return Err("Небезопасный каталог автозапуска.".into());
    }
    let temp = path.with_extension("plist.tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp)
        .map_err(|_| "Не удалось сохранить автозапуск.")?;
    let text = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>Label</key><string>io.eivro.Client</string><key>ProgramArguments</key><array><string>{}</string><string>--background</string></array><key>RunAtLoad</key><true/><key>StandardOutPath</key><string>/dev/null</string><key>StandardErrorPath</key><string>/dev/null</string></dict></plist>"#,
        xml(&executable.to_string_lossy())
    );
    let result = (|| {
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map_err(|_| "Не удалось сохранить автозапуск.".into())
}
