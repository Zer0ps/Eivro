//! A sleeping Win32 message loop owns the tray and OS notifications. It only
//! wakes egui when user input or meaningful network/power state changes occur.
use crate::{
    Result,
    platform::windows::{
        native::{Event as NativeEvent, wide},
        network,
    },
};
use std::{
    cell::{Cell, RefCell},
    path::{Path, PathBuf},
    ptr,
    sync::{
        Arc,
        mpsc::{self, Receiver, Sender},
    },
    thread,
};
use windows_sys::Win32::{
    Foundation::*,
    NetworkManagement::IpHelper::*,
    Networking::WinSock::AF_UNSPEC,
    System::{
        LibraryLoader::GetModuleHandleW,
        Registry::*,
        Threading::{GetCurrentThreadId, INFINITE, ResetEvent},
    },
    UI::{Shell::*, WindowsAndMessaging::*},
};
#[derive(Debug)]
pub enum Event {
    Show,
    Toggle,
    Quit,
    Settings,
    TrayOnline(bool),
    Network(bool),
    Sleep(bool),
    DnsChanged,
    MonitorUnavailable,
}
#[derive(Clone)]
struct Sink {
    tx: Sender<Event>,
    wake: Arc<dyn Fn() + Send + Sync>,
}
impl Sink {
    fn send(&self, event: Event) {
        let _ = self.tx.send(event);
        (self.wake)();
    }
}
const TRAY: u32 = WM_APP + 1;
const UPDATE: u32 = WM_APP + 2;
const NETWORK: u32 = WM_APP + 3;
struct DnsWatch {
    key: HKEY,
    event: NativeEvent,
}
impl DnsWatch {
    fn open(path: &str) -> std::io::Result<Self> {
        let event = NativeEvent::new()?;
        let mut key = ptr::null_mut();
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                wide(path).as_ptr(),
                0,
                KEY_NOTIFY,
                &mut key,
            )
        };
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
        let watch = Self { key, event };
        watch.arm()?;
        Ok(watch)
    }
    fn arm(&self) -> std::io::Result<()> {
        unsafe {
            ResetEvent(self.event.handle());
        }
        let status = unsafe {
            RegNotifyChangeKeyValue(
                self.key,
                1,
                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                self.event.handle(),
                1,
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(std::io::Error::from_raw_os_error(status as i32))
        }
    }
}
impl Drop for DnsWatch {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.key);
        }
    }
}
struct State {
    sink: Sink,
    window: Cell<HWND>,
    icon: Cell<HICON>,
    connected: Cell<bool>,
    wanted: Cell<bool>,
    taskbar: u32,
    network: RefCell<String>,
}
fn icon(connected: bool, wanted: bool) -> HICON {
    let color = if connected {
        [151, 223, 190]
    } else if wanted {
        [243, 189, 111]
    } else {
        [163, 176, 186]
    };
    let mut bytes = vec![0u8; 32 * 32 * 4];
    for y in 0..32 {
        for x in 0..32 {
            let dx = x as f32 - 15.5;
            let dy = y as f32 - 15.5;
            if dx * dx + dy * dy < 225.0 {
                let i = (y * 32 + x) * 4;
                bytes[i..i + 4].copy_from_slice(&[color[2], color[1], color[0], 255]);
                if ((8..=11).contains(&x) && (8..=24).contains(&y))
                    || ((8..=23).contains(&x) && ((8..=11).contains(&y) || (21..=24).contains(&y)))
                    || ((8..=19).contains(&x) && (15..=17).contains(&y))
                {
                    bytes[i..i + 3].copy_from_slice(&[30, 35, 20]);
                }
            }
        }
    }
    unsafe {
        CreateIcon(
            GetModuleHandleW(ptr::null()),
            32,
            32,
            1,
            32,
            [0u8; 128].as_ptr(),
            bytes.as_ptr(),
        )
    }
}
impl State {
    fn tray(&self, action: u32) {
        let mut data: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        data.cbSize = std::mem::size_of_val(&data) as u32;
        data.hWnd = self.window.get();
        data.uID = 1;
        data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        data.uCallbackMessage = TRAY;
        data.hIcon = self.icon.get();
        let title = wide(format!(
            "Eivro · {}",
            if self.connected.get() {
                "Подключено"
            } else if self.wanted.get() {
                "Подключение…"
            } else {
                "Отключено"
            }
        ));
        let n = title.len().min(data.szTip.len());
        data.szTip[..n].copy_from_slice(&title[..n]);
        let success = unsafe { Shell_NotifyIconW(action, &data) } != 0;
        if action == NIM_ADD {
            self.sink.send(Event::TrayOnline(success));
        }
    }
    fn scan(&self, force: bool) {
        let links = network::interfaces();
        let signature = links
            .iter()
            .map(|link| format!("{}:{}:{}:{:?}", link.index, link.name, link.up, link.dns))
            .collect::<Vec<_>>()
            .join("|");
        let changed = force || signature != *self.network.borrow();
        if changed {
            self.network.replace(signature);
            self.sink
                .send(Event::Network(links.iter().any(|link| link.up)));
            self.sink.send(Event::DnsChanged);
        }
    }
}
unsafe extern "system" fn changed(
    context: *const core::ffi::c_void,
    _row: *const MIB_IPINTERFACE_ROW,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    unsafe {
        PostMessageW(context as HWND, NETWORK, 0, 0);
    }
}
unsafe extern "system" fn address_changed(
    context: *const core::ffi::c_void,
    row: *const MIB_UNICASTIPADDRESS_ROW,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    if !row.is_null()
        && network::interfaces()
            .iter()
            .any(|link| link.index == unsafe { (*row).InterfaceIndex })
    {
        unsafe {
            PostMessageW(context as HWND, NETWORK, 1, 0);
        }
    }
}
unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_NCCREATE {
        let create = unsafe { &*(lparam as *const CREATESTRUCTW) };
        unsafe {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, create.lpCreateParams as isize);
        }
    }
    let state = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *mut State;
    if state.is_null() {
        return unsafe { DefWindowProcW(hwnd, message, wparam, lparam) };
    }
    // Shell/tray APIs and TrackPopupMenuEx can dispatch nested window messages.
    // Interior mutability avoids an exclusive State reference across that re-entry.
    let state = unsafe { &*state };
    state.window.set(hwnd);
    match message {
        WM_CREATE => {
            state.icon.set(icon(false, false));
            state.tray(NIM_ADD);
            state.scan(true);
            0
        }
        UPDATE => {
            state.connected.set(wparam & 1 != 0);
            state.wanted.set(wparam & 2 != 0);
            let old = state
                .icon
                .replace(icon(state.connected.get(), state.wanted.get()));
            state.tray(NIM_MODIFY);
            if !old.is_null() {
                unsafe {
                    DestroyIcon(old);
                }
            }
            0
        }
        NETWORK => {
            state.scan(wparam != 0);
            0
        }
        WM_SETTINGCHANGE => {
            state.scan(false);
            0
        }
        WM_POWERBROADCAST => {
            if wparam == 4 {
                state.sink.send(Event::Sleep(true));
            } else if wparam == 18 || wparam == 7 {
                state.sink.send(Event::Sleep(false));
                state.scan(true);
            }
            1
        }
        WM_QUERYENDSESSION => 1,
        WM_ENDSESSION => {
            if wparam != 0 {
                state.sink.send(Event::Quit);
            }
            0
        }
        TRAY => {
            match lparam as u32 {
                WM_LBUTTONUP | WM_LBUTTONDBLCLK => state.sink.send(Event::Show),
                WM_RBUTTONUP | WM_CONTEXTMENU => unsafe {
                    let menu = CreatePopupMenu();
                    if menu.is_null() {
                        return 0;
                    }
                    for (id, label) in [
                        (1, "Открыть Eivro"),
                        (
                            2,
                            if state.wanted.get() {
                                "Отключить"
                            } else {
                                "Подключить"
                            },
                        ),
                        (3, "Настройки"),
                        (4, "Завершить Eivro"),
                    ] {
                        AppendMenuW(menu, MF_STRING, id, wide(label).as_ptr());
                    }
                    let mut cursor: POINT = std::mem::zeroed();
                    GetCursorPos(&mut cursor);
                    SetForegroundWindow(hwnd);
                    let command = TrackPopupMenu(
                        menu,
                        TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON,
                        cursor.x,
                        cursor.y,
                        0,
                        hwnd,
                        ptr::null(),
                    );
                    DestroyMenu(menu);
                    PostMessageW(hwnd, WM_NULL, 0, 0);
                    match command {
                        1 => state.sink.send(Event::Show),
                        2 => state.sink.send(Event::Toggle),
                        3 => state.sink.send(Event::Settings),
                        4 => state.sink.send(Event::Quit),
                        _ => {}
                    }
                },
                _ => {}
            }
            0
        }
        WM_CLOSE => {
            unsafe {
                DestroyWindow(hwnd);
            }
            0
        }
        WM_DESTROY => {
            state.tray(NIM_DELETE);
            state.sink.send(Event::TrayOnline(false));
            let icon = state.icon.replace(ptr::null_mut());
            if !icon.is_null() {
                unsafe {
                    DestroyIcon(icon);
                }
            }
            unsafe {
                PostQuitMessage(0);
            }
            0
        }
        _ if message == state.taskbar => {
            state.tray(NIM_ADD);
            0
        }
        _ => unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
    }
}
pub struct Desktop {
    pub events: Receiver<Event>,
    sink: Sink,
    ready: Receiver<usize>,
    window: usize,
    last: Option<(bool, bool)>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Desktop {
    pub fn start(wake: Arc<dyn Fn() + Send + Sync>) -> Self {
        let (tx, events) = mpsc::channel();
        let sink = Sink { tx, wake };
        let window_sink = sink.clone();
        let (ready_tx, ready) = mpsc::channel();
        let worker = thread::spawn(move || unsafe {
            let class = wide("Eivro.Tray.Window");
            let instance = GetModuleHandleW(ptr::null());
            let wc = WNDCLASSW {
                lpfnWndProc: Some(window_proc),
                hInstance: instance,
                lpszClassName: class.as_ptr(),
                ..std::mem::zeroed()
            };
            RegisterClassW(&wc);
            let state = Box::new(State {
                sink,
                window: Cell::new(ptr::null_mut()),
                icon: Cell::new(ptr::null_mut()),
                connected: Cell::new(false),
                wanted: Cell::new(false),
                taskbar: RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()),
                network: RefCell::new(String::new()),
            });
            let hwnd = CreateWindowExW(
                0,
                class.as_ptr(),
                wide("Eivro events").as_ptr(),
                WS_OVERLAPPED,
                0,
                0,
                0,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                instance,
                (&*state as *const State).cast_mut().cast(),
            );
            if hwnd.is_null() {
                state.sink.send(Event::TrayOnline(false));
                let _ = ready_tx.send(0);
                return;
            }
            let _ = ready_tx.send(hwnd as usize);
            let mut interface = ptr::null_mut();
            let mut address = ptr::null_mut();
            if NotifyIpInterfaceChange(AF_UNSPEC, Some(changed), hwnd.cast(), false, &mut interface)
                != 0
                || NotifyUnicastIpAddressChange(
                    AF_UNSPEC,
                    Some(address_changed),
                    hwnd.cast(),
                    false,
                    &mut address,
                ) != 0
            {
                state.sink.send(Event::MonitorUnavailable);
            }
            // DNS can change without an address/link notification. Wait on the
            // registry events in this existing message thread, with no new timer.
            let mut dns = Vec::new();
            for path in [
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
            ] {
                match DnsWatch::open(path) {
                    Ok(watch) => dns.push(watch),
                    Err(_) => state.sink.send(Event::MonitorUnavailable),
                }
            }
            let mut handles: Vec<_> = dns.iter().map(|watch| watch.event.handle()).collect();
            state.scan(false);
            'messages: loop {
                let event = MsgWaitForMultipleObjectsEx(
                    handles.len() as u32,
                    handles.as_ptr(),
                    INFINITE,
                    QS_ALLINPUT,
                    MWMO_INPUTAVAILABLE,
                );
                if event == WAIT_FAILED {
                    state.sink.send(Event::MonitorUnavailable);
                    break;
                }
                if (event as usize) < handles.len() {
                    let index = event as usize;
                    if dns[index].arm().is_err() {
                        handles.remove(index);
                        dns.remove(index);
                        state.sink.send(Event::MonitorUnavailable);
                    }
                    state.scan(false);
                }
                let mut msg: MSG = std::mem::zeroed();
                while PeekMessageW(&mut msg, ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
                    if msg.message == WM_QUIT {
                        break 'messages;
                    }
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
            if !interface.is_null() {
                CancelMibChangeNotify2(interface);
            }
            if !address.is_null() {
                CancelMibChangeNotify2(address);
            }
            if IsWindow(hwnd) != 0 {
                DestroyWindow(hwnd);
            }
        });
        Self {
            events,
            sink: window_sink,
            ready,
            window: 0,
            last: None,
            worker: Some(worker),
        }
    }
    pub fn bind_main_window(
        &self,
        window: &impl raw_window_handle::HasWindowHandle,
    ) -> std::io::Result<()> {
        let raw_window_handle::RawWindowHandle::Win32(window) = window
            .window_handle()
            .map_err(std::io::Error::other)?
            .as_raw()
        else {
            return Err(std::io::ErrorKind::InvalidInput.into());
        };
        let hwnd = window.hwnd.get() as HWND;
        if unsafe { GetWindowThreadProcessId(hwnd, ptr::null_mut()) != GetCurrentThreadId() } {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        let sink = Box::into_raw(Box::new(self.sink.clone()));
        if unsafe { SetWindowSubclass(hwnd, Some(shutdown_hook), 0x45495652, sink as usize) } == 0 {
            unsafe { drop(Box::from_raw(sink)) };
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    pub fn update(&mut self, running: bool, wanted: bool, _status: &str) {
        if let Ok(window) = self.ready.try_recv() {
            self.window = window;
            self.last = None;
        }
        if self.window != 0 && self.last != Some((running, wanted)) {
            unsafe {
                PostMessageW(
                    self.window as HWND,
                    UPDATE,
                    running as usize | ((wanted as usize) << 1),
                    0,
                );
            }
            self.last = Some((running, wanted));
        }
    }
}

unsafe extern "system" fn shutdown_hook(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    id: usize,
    data: usize,
) -> LRESULT {
    // Restart Manager uses ENDSESSION, not the ordinary close-to-tray gesture.
    // The window owns this callback data until its final destruction.
    match message {
        WM_QUERYENDSESSION => return 1,
        WM_ENDSESSION if wparam != 0 => unsafe { &*(data as *const Sink) }.send(Event::Quit),
        WM_NCDESTROY => unsafe {
            RemoveWindowSubclass(hwnd, Some(shutdown_hook), id);
            drop(Box::from_raw(data as *mut Sink));
        },
        _ => {}
    }
    unsafe { DefSubclassProc(hwnd, message, wparam, lparam) }
}
impl Drop for Desktop {
    fn drop(&mut self) {
        if self.window == 0
            && let Ok(window) = self.ready.recv_timeout(std::time::Duration::from_secs(3))
        {
            self.window = window;
        }
        if self.window != 0 {
            unsafe {
                PostMessageW(self.window as HWND, WM_CLOSE, 0, 0);
            }
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
pub fn migrate_autostart() -> Result<()> {
    Ok(())
}
// The shared UI passes this opaque location back to set_autostart. On Windows
// it identifies a registry value, not a filesystem entry.
pub fn autostart_path() -> Result<PathBuf> {
    Ok(PathBuf::from(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Eivro",
    ))
}
pub fn autostart_enabled() -> bool {
    unsafe {
        let mut key = ptr::null_mut();
        if RegOpenKeyExW(
            HKEY_CURRENT_USER,
            wide(RUN).as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut key,
        ) != 0
        {
            return false;
        }
        let result = RegQueryValueExW(
            key,
            wide("Eivro").as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        ) == 0;
        RegCloseKey(key);
        result
    }
}
pub fn set_autostart(path: &Path, exe: &Path, enabled: bool) -> Result<()> {
    if path != autostart_path()? || !exe.is_absolute() || exe.to_string_lossy().contains('"') {
        return Err("Некорректный путь автозапуска.".into());
    }
    unsafe {
        let mut key = ptr::null_mut();
        if RegCreateKeyExW(
            HKEY_CURRENT_USER,
            wide(RUN).as_ptr(),
            0,
            ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            ptr::null(),
            &mut key,
            ptr::null_mut(),
        ) != 0
        {
            return Err("Не удалось открыть автозапуск Windows.".into());
        }
        let result = if enabled {
            let value = wide(format!("\"{}\" --background", exe.display()));
            RegSetValueExW(
                key,
                wide("Eivro").as_ptr(),
                0,
                REG_SZ,
                value.as_ptr().cast(),
                (value.len() * 2) as u32,
            )
        } else {
            RegDeleteValueW(key, wide("Eivro").as_ptr())
        };
        RegCloseKey(key);
        if result != 0 && !(result == ERROR_FILE_NOT_FOUND && !enabled) {
            return Err("Не удалось изменить автозапуск Windows.".into());
        }
    }
    Ok(())
}
