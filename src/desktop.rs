//! Desktop events sleep on D-Bus. No timer or network probe runs while idle.
use ksni::blocking::TrayMethods;
use std::{
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
    TrayOnline(bool),
    Network(bool),
    Sleep(bool),
    MonitorUnavailable,
}
#[derive(Clone)]
pub struct Sink {
    tx: Sender<Event>,
    wake: Arc<dyn Fn() + Send + Sync>,
}
impl Sink {
    pub fn send(&self, event: Event) {
        let _ = self.tx.send(event);
        (self.wake)();
    }
}
pub struct Desktop {
    pub events: Receiver<Event>,
    ready: Receiver<ksni::blocking::Handle<Tray>>,
    handle: Option<ksni::blocking::Handle<Tray>>,
    last: Option<(bool, bool, String)>,
}
impl Desktop {
    pub fn start(wake: Arc<dyn Fn() + Send + Sync>) -> Self {
        let (tx, events) = mpsc::channel();
        let sink = Sink { tx, wake };
        let (htx, ready) = mpsc::channel();
        let tray_sink = sink.clone();
        std::thread::spawn(move || {
            let tray = Tray {
                sink: tray_sink.clone(),
                connected: false,
                wanted: false,
                status: "Отключено".into(),
            };
            match tray.assume_sni_available(true).spawn() {
                Ok(handle) => {
                    // A watcher name alone is not sufficient: it must have a host.
                    let online = tray_host();
                    let _ = htx.send(handle);
                    tray_sink.send(Event::TrayOnline(online));
                }
                Err(_) => tray_sink.send(Event::TrayOnline(false)),
            }
        });
        let network_sink = sink.clone();
        std::thread::spawn(move || {
            if network(&network_sink).is_err() {
                network_sink.send(Event::MonitorUnavailable);
            }
        });
        std::thread::spawn(move || {
            let _ = sleep_events(&sink);
        });
        Self {
            events,
            ready,
            handle: None,
            last: None,
        }
    }
    pub fn update(&mut self, connected: bool, wanted: bool, status: &str) {
        if let Ok(handle) = self.ready.try_recv() {
            self.handle = Some(handle);
            self.last = None;
        }
        let value = (connected, wanted, status.to_owned());
        if self.last.as_ref() != Some(&value)
            && let Some(handle) = &self.handle
        {
            handle.update(|tray| {
                tray.connected = connected;
                tray.wanted = wanted;
                tray.status = status.into();
            });
            self.last = Some(value);
        }
    }
}
impl Drop for Desktop {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.shutdown();
        }
    }
}
struct Tray {
    sink: Sink,
    connected: bool,
    wanted: bool,
    status: String,
}
impl ksni::Tray for Tray {
    fn id(&self) -> String {
        "io.velum.Client".into()
    }
    fn title(&self) -> String {
        format!("Velum · {}", self.status)
    }
    fn activate(&mut self, _: i32, _: i32) {
        self.sink.send(Event::Show);
    }
    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        let color = if self.connected {
            [151, 223, 190]
        } else if self.wanted {
            [243, 189, 111]
        } else {
            [163, 176, 186]
        };
        let mut data = vec![0u8; 32 * 32 * 4];
        for y in 0..32 {
            for x in 0..32 {
                let dx = x as f32 - 15.5;
                let dy = y as f32 - 15.5;
                if dx * dx + dy * dy < 225.0 {
                    let i = (y * 32 + x) * 4;
                    data[i..i + 4].copy_from_slice(&[255, color[0], color[1], color[2]]);
                    if (8..=22).contains(&x)
                        && (8..=24).contains(&y)
                        && ((y as f32 - (2.0 * (x as f32 - 8.0) + 9.0)).abs() < 2.8
                            || (y as f32 - (-2.0 * (x as f32 - 16.0) + 24.0)).abs() < 2.8)
                    {
                        data[i + 1..i + 4].copy_from_slice(&[20, 35, 30]);
                    }
                }
            }
        }
        vec![ksni::Icon {
            width: 32,
            height: 32,
            data,
        }]
    }
    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::StandardItem;
        vec![
            StandardItem {
                label: self.status.clone(),
                enabled: false,
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Открыть Velum".into(),
                activate: Box::new(|s: &mut Self| s.sink.send(Event::Show)),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: if self.wanted {
                    "Отключить"
                } else {
                    "Подключить"
                }
                .into(),
                activate: Box::new(|s: &mut Self| s.sink.send(Event::Toggle)),
                ..Default::default()
            }
            .into(),
            ksni::MenuItem::Separator,
            StandardItem {
                label: "Завершить Velum".into(),
                activate: Box::new(|s: &mut Self| s.sink.send(Event::Quit)),
                ..Default::default()
            }
            .into(),
        ]
    }
    fn watcher_online(&self) {
        self.sink.send(Event::TrayOnline(true));
    }
    fn watcher_offline(&self, _: ksni::OfflineReason) -> bool {
        self.sink.send(Event::TrayOnline(false));
        true
    }
}
fn tray_host() -> bool {
    let Ok(c) = zbus::blocking::Connection::session() else {
        return false;
    };
    zbus::blocking::Proxy::new(
        &c,
        "org.kde.StatusNotifierWatcher",
        "/StatusNotifierWatcher",
        "org.kde.StatusNotifierWatcher",
    )
    .and_then(|p| p.get_property::<bool>("IsStatusNotifierHostRegistered"))
    .unwrap_or(false)
}
fn network(sink: &Sink) -> zbus::Result<()> {
    let c = zbus::blocking::Connection::system()?;
    let path = "/org/freedesktop/NetworkManager";
    let interface = "org.freedesktop.NetworkManager";
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .sender(interface)?
        .path(path)?
        .interface("org.freedesktop.DBus.Properties")?
        .member("PropertiesChanged")?
        .build();
    let stream = zbus::blocking::MessageIterator::for_match_rule(rule, &c, Some(16))?;
    let proxy: zbus::blocking::Proxy = zbus::blocking::proxy::Builder::new(&c)
        .destination(interface)?
        .path(path)?
        .interface(interface)?
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()?;
    let mut previous = None;
    let mut snapshot = || -> zbus::Result<()> {
        let state: u32 = proxy.get_property("State")?;
        let primary: zbus::zvariant::OwnedObjectPath = proxy.get_property("PrimaryConnection")?;
        let value = (state >= 50, primary.to_string());
        if previous.as_ref() != Some(&value) {
            sink.send(Event::Network(value.0));
            previous = Some(value);
        }
        Ok(())
    };
    snapshot()?;
    for message in stream {
        let message = message?;
        let (iface, changed, invalid): (
            String,
            std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
            Vec<String>,
        ) = message.body().deserialize()?;
        if iface == interface
            && ["State", "PrimaryConnection"]
                .iter()
                .any(|p| changed.contains_key(*p) || invalid.iter().any(|x| x == p))
        {
            snapshot()?;
        }
    }
    Ok(())
}
fn sleep_events(sink: &Sink) -> zbus::Result<()> {
    let c = zbus::blocking::Connection::system()?;
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .sender("org.freedesktop.login1")?
        .path("/org/freedesktop/login1")?
        .interface("org.freedesktop.login1.Manager")?
        .member("PrepareForSleep")?
        .build();
    for message in zbus::blocking::MessageIterator::for_match_rule(rule, &c, Some(8))? {
        let (sleeping,): (bool,) = message?.body().deserialize()?;
        sink.send(Event::Sleep(sleeping));
    }
    Ok(())
}

pub fn autostart_path() -> crate::Result<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".config")))
        .ok_or("Нет каталога автозапуска.")?;
    Ok(base.join("autostart/io.velum.Client.desktop"))
}
pub fn set_autostart(path: &Path, executable: &Path, enabled: bool) -> crate::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if !enabled {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err("Не удалось отключить автозапуск.".into()),
        }
    } else {
        let s = executable
            .to_str()
            .filter(|s| !s.chars().any(char::is_control))
            .ok_or("Некорректный путь Velum.")?;
        let escaped = s
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('`', "\\`")
            .replace('$', "\\$")
            .replace('%', "%%");
        std::fs::create_dir_all(path.parent().ok_or("Нет каталога автозапуска.")?)
            .map_err(|_| "Не удалось создать автозапуск.")?;
        let temp = path.with_extension(format!("tmp-{}", std::process::id()));
        let result = (|| {
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temp)
                .map_err(|_| "Не удалось записать автозапуск.")?;
            write!(file,"[Desktop Entry]\nType=Application\nName=Velum\nExec=\"{escaped}\" --background\nIcon=io.velum.Client\nTerminal=false\nX-GNOME-Autostart-enabled=true\n").map_err(|_|"Не удалось записать автозапуск.")?;
            file.sync_all()
                .map_err(|_| "Не удалось сохранить автозапуск.")?;
            std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))
                .map_err(|_| "Ошибка прав автозапуска.")?;
            std::fs::rename(&temp, path).map_err(|_| "Не удалось включить автозапуск.")
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temp);
        }
        result.map_err(str::to_owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;
    struct Watcher {
        registered: Arc<Mutex<Vec<String>>>,
    }
    #[zbus::interface(name = "org.kde.StatusNotifierWatcher")]
    impl Watcher {
        fn register_status_notifier_item(&self, service: String) {
            self.registered.lock().unwrap().push(service);
        }
        fn register_status_notifier_host(&self, _service: String) {}
        #[zbus(property)]
        fn is_status_notifier_host_registered(&self) -> bool {
            true
        }
        #[zbus(property)]
        fn protocol_version(&self) -> i32 {
            0
        }
        #[zbus(property)]
        fn registered_status_notifier_items(&self) -> Vec<String> {
            self.registered.lock().unwrap().clone()
        }
    }
    struct Network {
        state: u32,
        primary: zbus::zvariant::OwnedObjectPath,
    }
    #[zbus::interface(name = "org.freedesktop.NetworkManager")]
    impl Network {
        #[zbus(property)]
        fn state(&self) -> u32 {
            self.state
        }
        #[zbus(property)]
        fn set_state(&mut self, value: u32) {
            self.state = value;
        }
        #[zbus(property)]
        fn primary_connection(&self) -> zbus::zvariant::OwnedObjectPath {
            self.primary.clone()
        }
        #[zbus(property)]
        fn set_primary_connection(&mut self, value: zbus::zvariant::OwnedObjectPath) {
            self.primary = value;
        }
    }
    #[track_caller]
    fn next(desktop: &Desktop, predicate: impl Fn(&Event) -> bool) {
        for _ in 0..16 {
            let event = desktop.events.recv_timeout(Duration::from_secs(3)).unwrap();
            eprintln!("desktop test event: {event:?}");
            if predicate(&event) {
                return;
            }
        }
        panic!("expected desktop event missing");
    }
    #[test]
    fn tray_and_network_signals_in_private_dbus() {
        if std::env::var_os("VELUM_DESKTOP_TEST").is_none() {
            let output = std::process::Command::new("dbus-run-session")
                .args([
                    "--",
                    "sh",
                    "-c",
                    "DBUS_SYSTEM_BUS_ADDRESS=\"$DBUS_SESSION_BUS_ADDRESS\" exec \"$@\"",
                    "velum-test",
                ])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "desktop::tests::tray_and_network_signals_in_private_dbus",
                    "--nocapture",
                ])
                .env("VELUM_DESKTOP_TEST", "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        assert_eq!(
            std::env::var("DBUS_SYSTEM_BUS_ADDRESS").unwrap(),
            std::env::var("DBUS_SESSION_BUS_ADDRESS").unwrap()
        );
        let registered = Arc::new(Mutex::new(Vec::new()));
        let connection = zbus::blocking::connection::Builder::session()
            .unwrap()
            .name("org.kde.StatusNotifierWatcher")
            .unwrap()
            .name("org.freedesktop.NetworkManager")
            .unwrap()
            .name("org.freedesktop.login1")
            .unwrap()
            .serve_at(
                "/StatusNotifierWatcher",
                Watcher {
                    registered: registered.clone(),
                },
            )
            .unwrap()
            .serve_at(
                "/org/freedesktop/NetworkManager",
                Network {
                    state: 70,
                    primary: "/connection/one".try_into().unwrap(),
                },
            )
            .unwrap()
            .build()
            .unwrap();
        let mut desktop = Desktop::start(Arc::new(|| {}));
        next(&desktop, |e| matches!(e, Event::TrayOnline(true)));
        desktop.update(true, true, "Подключено");
        let service = registered.lock().unwrap()[0].clone();
        let proxy = zbus::blocking::Proxy::new(
            &connection,
            service,
            "/StatusNotifierItem",
            "org.kde.StatusNotifierItem",
        )
        .unwrap();
        let title: String = proxy.get_property("Title").unwrap();
        assert!(title.contains("Подключено"));
        let icon: Vec<(i32, i32, Vec<u8>)> = proxy.get_property("IconPixmap").unwrap();
        assert_eq!(icon[0].2.len(), 32 * 32 * 4);
        proxy.call::<_, _, ()>("Activate", &(0i32, 0i32)).unwrap();
        next(&desktop, |e| matches!(e, Event::Show));
        let nm = zbus::blocking::Proxy::new(
            &connection,
            "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.NetworkManager",
        )
        .unwrap();
        nm.set_property("State", 20u32).unwrap();
        next(&desktop, |e| matches!(e, Event::Network(false)));
        nm.set_property("State", 70u32).unwrap();
        next(&desktop, |e| matches!(e, Event::Network(true)));
        nm.set_property(
            "PrimaryConnection",
            zbus::zvariant::ObjectPath::try_from("/connection/two").unwrap(),
        )
        .unwrap();
        next(&desktop, |e| matches!(e, Event::Network(true)));
        connection
            .emit_signal(
                None::<&str>,
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
                "PrepareForSleep",
                &(true,),
            )
            .unwrap();
        next(&desktop, |e| matches!(e, Event::Sleep(true)));
        connection
            .emit_signal(
                None::<&str>,
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
                "PrepareForSleep",
                &(false,),
            )
            .unwrap();
        next(&desktop, |e| matches!(e, Event::Sleep(false)));
        let path: zbus::zvariant::OwnedObjectPath = proxy.get_property("Menu").unwrap();
        let menu = zbus::blocking::Proxy::new(
            &connection,
            proxy.destination().clone(),
            path,
            "com.canonical.dbusmenu",
        )
        .unwrap();
        type Layout = (
            i32,
            std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
            Vec<zbus::zvariant::OwnedValue>,
        );
        let (_, layout): (u32, Layout) = menu
            .call("GetLayout", &(0i32, -1i32, Vec::<String>::new()))
            .unwrap();
        for child in layout.2 {
            let (id, props, _): Layout = child.try_into().unwrap();
            let label = props
                .get("label")
                .and_then(|v| <&str>::try_from(v).ok())
                .unwrap_or("");
            if label == "Отключить" || label == "Завершить Velum" {
                menu.call::<_, _, ()>(
                    "Event",
                    &(id, "clicked", zbus::zvariant::Value::from(0i32), 0u32),
                )
                .unwrap();
                if label == "Отключить" {
                    next(&desktop, |e| matches!(e, Event::Toggle));
                } else {
                    next(&desktop, |e| matches!(e, Event::Quit));
                }
            }
        }
        connection
            .release_name("org.kde.StatusNotifierWatcher")
            .unwrap();
        next(&desktop, |e| matches!(e, Event::TrayOnline(false)));
    }
    #[test]
    fn autostart_is_opt_in_and_escapes_exec_fields() {
        let dir = std::env::temp_dir().join(format!("velum-startup-{}", std::process::id()));
        let path = dir.join("autostart/velum.desktop");
        set_autostart(&path, Path::new("/some path/velum%name"), true).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("Exec=\"/some path/velum%%name\" --background"));
        set_autostart(&path, Path::new("/irrelevant"), false).unwrap();
        assert!(!path.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
