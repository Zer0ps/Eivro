mod connection;
mod design;
mod desktop;
mod dialogs;
mod effects;
mod navigation;
mod rules;
mod settings;
mod subscriptions;
use self::rules::Editor;
use eframe::egui::{self, Align2, Color32, FontId, RichText, Stroke, Vec2};
use eivro::{
    catalog::{self, Document, UpdatePolicy},
    config::{ConnectRequest, Mode},
    process::{self, Event, Session},
    storage::{self, Settings, Theme},
};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        mpsc::{self, Receiver},
    },
};

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum Page {
    #[default]
    Connection,
    Subscriptions,
    Routes,
    Settings,
}

pub struct App {
    page: Page,
    sidebar_open: bool,
    navigation_overlay: bool,
    navigation_button: Option<egui::Id>,
    modal_was_open: bool,
    modal_return_focus: Option<egui::Id>,
    server_filter: String,
    catalog_open: bool,
    catalog_focus: Option<u64>,
    network_links: Vec<eivro::network::Interface>,
    network_result: Option<Receiver<Vec<eivro::network::Interface>>>,
    network_monitor: Option<eivro::network::Monitor>,
    network_monitor_failed: bool,
    network_due: Option<std::time::Instant>,
    network_initialized: bool,
    settings: Settings,
    path: Option<PathBuf>,
    session: Option<Session>,
    events: Option<Receiver<Event>>,
    running: bool,
    connection_effect: effects::ConnectionEffect,
    phase: &'static str,
    helper_ready: bool,
    install_result: Option<Receiver<eivro::Result<()>>>,
    stopping: bool,
    error: Option<String>,
    import_open: bool,
    import_text: String,
    import_reveal: bool,
    import_result: Option<Receiver<eivro::Result<Document>>>,
    appearance: bool,
    delete_server: bool,
    subscriptions_open: bool,
    delete_subscription: Option<u64>,
    rename_subscription: Option<(u64, String)>,
    import_target: Option<u64>,
    retry_after: std::collections::HashMap<u64, u64>,
    refresh_errors: std::collections::HashMap<u64, String>,
    want_connected: bool,
    reconnect_pending: bool,
    tun: Arc<eivro::tun::Controller>,
    editor: Option<Editor>,
    desktop: Option<eivro::desktop::Desktop>,
    tray_online: bool,
    window_hiding: bool,
    hidden: bool,
    quitting: bool,
    background_start: bool,
    recovery: eivro::recovery::Recovery,
    network_seen: bool,
    monitor_unavailable: bool,
    autostart: bool,
    instance: Option<crate::instance::Instance>,
    guard_session: bool,
}

#[derive(Clone, Copy)]
struct Palette {
    bg: Color32,
    card: Color32,
    raised: Color32,
    line: Color32,
    text: Color32,
    muted: Color32,
    accent: Color32,
    soft: Color32,
    error: Color32,
}

impl App {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        instance: crate::instance::Instance,
        window_hiding: bool,
    ) -> Self {
        let path = storage::prepare_config();
        let loaded = path
            .as_ref()
            .map_err(Clone::clone)
            .and_then(|p| storage::load(p));
        let error = loaded
            .as_ref()
            .err()
            .cloned()
            .or_else(|| eivro::system_proxy::recover_stale().err());
        let writable = error.is_none();
        let settings = loaded.unwrap_or_default();
        let mut style = (*cc.egui_ctx.style()).clone();
        style.spacing.item_spacing = Vec2::new(10.0, 8.0);
        style.spacing.button_padding = Vec2::new(14.0, 8.0);
        style.spacing.interact_size.y = 32.0;
        style.spacing.scroll = egui::style::ScrollStyle::solid();
        style.spacing.window_margin = egui::Margin::symmetric(18, 10);
        style
            .text_styles
            .insert(egui::TextStyle::Body, FontId::proportional(14.0));
        style
            .text_styles
            .insert(egui::TextStyle::Button, FontId::proportional(14.0));
        style
            .text_styles
            .insert(egui::TextStyle::Small, FontId::proportional(12.0));
        style.text_styles.insert(
            egui::TextStyle::Heading,
            FontId::new(24.0, egui::FontFamily::Name("display".into())),
        );
        style.animation_time = 0.0;
        cc.egui_ctx.set_style(style);
        crate::emoji::install(&cc.egui_ctx);
        let mut app = Self::model(settings, if writable { path.ok() } else { None }, error);
        app.window_hiding = window_hiding;
        #[cfg(feature = "qa")]
        if std::env::var("EIVRO_QA_FIXTURE").as_deref() == Ok("1") {
            app.network_links = vec![eivro::network::Interface {
                name: "tun0".into(),
                index: 77,
                up: true,
                dns: vec!["10.50.0.53".parse().unwrap()],
            }];
            app.network_initialized = true;
        }

        #[cfg(feature = "qa")]
        if let Some(zoom) = std::env::var("EIVRO_QA_ZOOM")
            .ok()
            .and_then(|s| s.parse::<f32>().ok())
        {
            cc.egui_ctx.set_zoom_factor(zoom.clamp(1.0, 2.0));
        }

        instance.set_context(cc.egui_ctx.clone());
        app.instance = Some(instance);
        let ctx = cc.egui_ctx.clone();
        app.desktop = Some(eivro::desktop::Desktop::start(Arc::new(move || {
            ctx.request_repaint()
        })));
        app.background_start = std::env::args().any(|s| s == "--background");
        if let Err(error) = eivro::desktop::migrate_autostart() {
            app.error.get_or_insert(error);
        }
        app.autostart = eivro::desktop::autostart_path().is_ok_and(|p| p.is_file());
        if app.settings.autoconnect && app.settings.selected_profile().is_some() {
            app.want_connected = true;
            app.recovery.schedule(std::time::Instant::now());
        }
        #[cfg(feature = "qa")]
        match std::env::var("EIVRO_QA_PAGE").as_deref() {
            Ok("rules") => app.editor = Some(Editor::new(&app.settings)),
            Ok("rules-selected") => {
                let mut editor = Editor::new(&app.settings);
                editor.preview_selection();
                app.editor = Some(editor);
            }
            Ok("rules-add") => {
                let mut editor = Editor::new(&app.settings);
                editor.open_add(false);
                app.editor = Some(editor);
            }
            Ok("rules-application") => {
                let mut editor = Editor::new(&app.settings);
                editor.open_add(true);
                app.editor = Some(editor);
            }
            Ok("appearance") => app.appearance = true,
            Ok("rename") => {
                app.rename_subscription = app.settings.current().map(|s| (s.id, s.name.clone()))
            }
            Ok("delete") => app.delete_server = true,
            Ok("import") => app.import_open = true,
            Ok("catalog") => app.catalog_open = true,
            Ok("sidebar-hidden") => app.sidebar_open = false,
            Ok("network") | Ok("network-edit") => {
                let mut editor = Editor::new(&app.settings);
                editor
                    .open_network(std::env::var("EIVRO_QA_PAGE").as_deref() == Ok("network-edit"));
                app.editor = Some(editor);
            }
            _ => {}
        }
        #[cfg(feature = "qa")]
        if app.editor.is_some() {
            app.page = Page::Routes;
        }
        #[cfg(feature = "qa")]
        if std::env::var("EIVRO_QA_CONNECTED").as_deref() == Ok("1") {
            // Visual fixture only: no session or network operation is started.
            app.running = true;
            app.want_connected = true;
            app.helper_ready = true;
            app.settings.mode = Mode::Tun;
        }
        #[cfg(feature = "qa")]
        if std::env::var("EIVRO_QA_FIXTURE").as_deref() == Ok("1")
            && std::env::var("EIVRO_QA_CONNECTION_EFFECT").as_deref() == Ok("1")
        {
            app.running = false;
            app.want_connected = false;
        }
        app
    }

    fn model(settings: Settings, path: Option<PathBuf>, error: Option<String>) -> Self {
        Self {
            page: Page::Connection,
            sidebar_open: true,
            navigation_overlay: false,
            navigation_button: None,
            modal_was_open: false,
            modal_return_focus: None,
            server_filter: String::new(),
            catalog_open: false,
            catalog_focus: None,
            network_links: Vec::new(),
            network_result: None,
            network_monitor: None,
            network_monitor_failed: false,
            network_due: None,
            network_initialized: false,
            settings,
            path,
            session: None,
            events: None,
            running: false,
            connection_effect: effects::ConnectionEffect::default(),
            phase: "Подключение…",
            helper_ready: process::helper_compatible(),
            install_result: None,
            stopping: false,
            error,
            import_open: false,
            import_text: String::new(),
            import_reveal: false,
            import_result: None,
            appearance: false,
            delete_server: false,
            subscriptions_open: cfg!(feature = "qa")
                && std::env::var("EIVRO_QA_PAGE").as_deref() == Ok("subscriptions"),
            delete_subscription: None,
            rename_subscription: None,
            import_target: None,
            retry_after: Default::default(),
            refresh_errors: Default::default(),
            want_connected: false,
            reconnect_pending: false,
            tun: Arc::new(eivro::tun::Controller::default()),
            editor: None,
            desktop: None,
            tray_online: false,
            window_hiding: true,
            hidden: false,
            quitting: false,
            background_start: false,
            recovery: Default::default(),
            network_seen: false,
            monitor_unavailable: false,
            autostart: false,
            instance: None,
            guard_session: false,
        }
    }

    fn handle_close(&mut self, ctx: &egui::Context) {
        if ctx.input(|i| i.viewport().close_requested())
            && !self.quitting
            && self.settings.close_to_tray
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            if self.tray_online && self.window_hiding {
                self.hidden = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            } else if !self.window_hiding {
                self.error = Some("Для скрытия окна в трей нужен XWayland. Для выхода используйте «Завершить Eivro» в настройках.".into());
            } else {
                self.error = Some(
                    "Трей недоступен. Для выхода используйте «Завершить Eivro» в настройках."
                        .into(),
                );
            }
        }
    }

    fn receive(&mut self, ctx: &egui::Context) {
        if let Some(result) = self.install_result.as_ref().and_then(|r| r.try_recv().ok()) {
            self.install_result = None;
            self.helper_ready = process::helper_compatible();
            self.error = result.err();
        }
        let mut done = false;
        if let Some(rx) = &self.events {
            while let Ok(event) = rx.try_recv() {
                match event {
                    Event::Running => {
                        if !self.stopping {
                            self.running = true;
                            self.guard_session =
                                self.settings.kill_switch && self.settings.mode == Mode::Tun;
                            self.recovery.cancel();
                        }
                    }
                    Event::Progress(phase) => self.phase = phase,
                    Event::Stopped => done = true,
                    Event::Failed(e) => {
                        done = true;
                        self.error = Some(e.clone());
                        let was_connected =
                            self.running || self.recovery.recovering || self.guard_session;
                        let protected =
                            self.settings.kill_switch && self.settings.mode == Mode::Tun;
                        if self.want_connected && !e.contains("Доступ TUN отменён") && was_connected
                        {
                            if self.settings.reconnect {
                                self.recovery.recovering = true;
                                if !self.recovery.failed(std::time::Instant::now()) && !protected {
                                    self.want_connected = false;
                                }
                            } else if protected {
                                self.recovery.recovering = true;
                                self.recovery.exhausted = true;
                                self.recovery.due = None;
                            } else {
                                self.want_connected = false;
                            }
                        } else {
                            self.want_connected = false;
                        }
                    }
                }
            }
        }
        if done {
            self.events = None;
            self.session = None;
            self.running = false;
            self.stopping = false;
            self.reconnect_pending = false;
            if (!self.want_connected || self.settings.mode != Mode::Tun)
                && let Err(e) = self.tun.release()
            {
                self.error = Some(e);
                self.want_connected = false;
            }
            if !self.want_connected {
                self.guard_session = false;
            }
            if self.want_connected && !self.recovery.recovering {
                self.start_connection(ctx);
            }
        }
        let result = self
            .import_result
            .as_ref()
            .and_then(|rx| match rx.try_recv() {
                Ok(r) => Some(r),
                Err(mpsc::TryRecvError::Disconnected) => Some(Err("Обновление прервано.".into())),
                Err(_) => None,
            });
        if let Some(result) = result {
            self.import_result = None;
            let target = self.import_target.take();
            let previous = self
                .settings
                .selected_profile()
                .map(catalog::effective_connection);
            match result.and_then(|doc| {
                let mut next = self.settings.clone();
                next.apply_document(target, doc)?;
                let path = self.path.as_deref().ok_or(
                    "Сохранение отключено: сначала исправьте файл настроек. Обновление не применено.",
                )?;
                storage::save(path, &next)?;
                self.settings = next;
                Ok(())
            }) {
                Ok(()) => {
                    if let Some(id) = target {
                        self.retry_after.remove(&id);
                        self.refresh_errors.remove(&id);
                    } else {
                        self.import_text.clear();
                        self.import_open = false;
                        self.import_reveal = false;
                    }
                    if previous
                        != self
                            .settings
                            .selected_profile()
                            .map(catalog::effective_connection)
                    {
                        self.reconfigure();
                    }
                }
                Err(e) => {
                    if let Some(id) = target {
                        self.retry_after.insert(id, catalog::now() + 300);
                        self.refresh_errors.insert(id, e);
                    } else {
                        self.error = Some(e);
                    }
                }
            }
        }
    }
    fn start_job(&mut self, input: String, target: Option<u64>, ctx: &egui::Context) {
        if self.import_result.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.import_result = Some(rx);
        self.import_target = target;
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = catalog::read_input(&input);
            let _ = tx.send(result);
            ctx.request_repaint();
        });
    }
    fn auto_refresh(&mut self, ctx: &egui::Context) {
        if self.import_result.is_some()
            || self.import_open
            || self.recovery.offline
            || self.recovery.sleeping
        {
            return;
        }
        let next = self
            .settings
            .subscriptions
            .iter()
            .filter_map(|sub| {
                let due = sub
                    .due_at()?
                    .max(*self.retry_after.get(&sub.id).unwrap_or(&0));
                Some((due, sub.id, sub.source.clone()?))
            })
            .min_by_key(|(due, _, _)| *due);
        if let Some((due, id, url)) = next {
            let now = catalog::now();
            if due <= now {
                self.start_job(url, Some(id), ctx);
            } else {
                ctx.request_repaint_after(std::time::Duration::from_secs((due - now).min(3600)));
            }
        }
    }
    fn reconfigure(&mut self) {
        if self.want_connected
            && let Some(session) = &mut self.session
        {
            session.restart();
            self.stopping = true;
            self.running = false;
            self.reconnect_pending = true;
        } else if self.want_connected {
            self.recovery.schedule(std::time::Instant::now());
        }
    }
    fn connect(&mut self, ctx: &egui::Context) {
        let wanted = self.want_connected;
        self.recovery.cancel();
        if let Some(session) = &mut self.session {
            self.want_connected = false;
            self.guard_session = false;
            self.reconnect_pending = false;
            session.stop();
            self.stopping = true;
            self.running = false;
        } else if wanted {
            self.want_connected = false;
            self.guard_session = false;
            if let Err(e) = self.tun.release() {
                self.error = Some(e);
            }
        } else {
            self.want_connected = true;
            self.start_connection(ctx);
        }
    }
    fn start_connection(&mut self, ctx: &egui::Context) {
        if self.settings.mode != Mode::Tun || !self.settings.kill_switch {
            self.guard_session = false;
        }
        if (self.settings.mode != Mode::Tun || !self.settings.kill_switch)
            && let Err(e) = self.tun.release()
        {
            self.error = Some(e);
            self.want_connected = false;
            return;
        }
        let Some(profile) = self.settings.selected_profile() else {
            self.want_connected = false;
            self.guard_session = false;
            if let Err(e) = self.tun.release() {
                self.error = Some(e);
            }
            return;
        };
        let req = ConnectRequest {
            connections: self.settings.connections.clone(),
            probe_port: None,
            kill_switch: self.settings.kill_switch && self.settings.mode == Mode::Tun,
            policies: self.settings.routing_profiles[self.settings.selected_routing]
                .rules
                .clone(),
            bridge_port: None,
            uri: profile.uri.clone(),
            bypass: vec![],
            port: self.settings.port,
        };
        let ctx = ctx.clone();
        match Session::start_with_controller(
            req,
            self.settings.mode,
            Arc::new(move || ctx.request_repaint()),
            self.tun.clone(),
        ) {
            Ok((session, events)) => {
                self.phase = "Подключение…";
                self.session = Some(session);
                self.events = Some(events);
                self.error = None;
            }
            Err(e) => {
                self.error = Some(e);
                if self.guard_session {
                    self.recovery.recovering = true;
                    self.recovery.exhausted = true;
                    self.recovery.due = None;
                } else {
                    self.want_connected = false;
                }
            }
        }
    }
}

fn contrast(c: Color32) -> Color32 {
    if design::luminance(c) > 0.179_128 {
        Color32::BLACK
    } else {
        Color32::WHITE
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.desktop_events(ctx);
        self.receive(ctx);
        self.recover(ctx);
        self.auto_refresh(ctx);
        if let Some(desktop) = &mut self.desktop {
            let status = if self.running {
                "Подключено"
            } else if self.want_connected {
                "Подключение…"
            } else {
                "Отключено"
            };
            desktop.update(self.running, self.want_connected, status);
        }
        self.handle_close(ctx);
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        if !dropped.is_empty() {
            if self.import_result.is_some() {
                self.error = Some("Дождитесь текущего обновления.".into());
            } else if dropped.len() != 1 {
                self.error = Some("Перетащите один файл или архив.".into());
            } else if let Some(path) = dropped[0].path.as_ref() {
                self.start_job(path.to_string_lossy().into_owned(), None, ctx);
            }
        }
        let p = self.palette();
        let mut visuals = if self.settings.theme == Theme::Dark {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        };
        visuals.panel_fill = p.bg;
        visuals.window_fill = p.card;
        visuals.extreme_bg_color = p.raised;
        visuals.override_text_color = Some(p.text);
        visuals.window_stroke = Stroke::new(1.0_f32, p.line);
        visuals.window_corner_radius = 16.into();
        visuals.selection.bg_fill = p.accent.gamma_multiply(0.22);
        visuals.selection.stroke = Stroke::new(1.0_f32, p.text);
        visuals.widgets.noninteractive.bg_fill = p.raised;
        visuals.widgets.noninteractive.weak_bg_fill = p.raised;
        visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, p.line);
        visuals.widgets.inactive.bg_fill = p.raised;
        visuals.widgets.inactive.weak_bg_fill = p.raised;
        visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, p.line);
        visuals.widgets.hovered.bg_fill = p.raised;
        visuals.widgets.hovered.weak_bg_fill = p.accent.gamma_multiply(0.16);
        visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, p.accent);
        visuals.widgets.active.bg_fill = p.accent;
        visuals.widgets.active.weak_bg_fill = p.accent.gamma_multiply(0.26);
        visuals.widgets.active.fg_stroke = Stroke::new(1.0_f32, p.text);
        for widgets in [
            &mut visuals.widgets.inactive,
            &mut visuals.widgets.hovered,
            &mut visuals.widgets.active,
            &mut visuals.widgets.open,
        ] {
            widgets.corner_radius = 3.into();
            widgets.expansion = 0.0;
        }
        ctx.set_visuals(visuals);
        ctx.style_mut(|style| {
            style.animation_time = if self.settings.reduced_motion {
                0.0
            } else {
                0.16
            }
        });
        self.poll_network(ctx);
        if self.appearance {
            self.page = Page::Settings;
            self.appearance = false;
        }
        if self.subscriptions_open {
            self.page = Page::Subscriptions;
            self.subscriptions_open = false;
        }
        #[cfg(feature = "qa")]
        if std::env::var("EIVRO_QA_ANIMATE").as_deref() == Ok("1") {
            let now = ctx.input(|i| i.time);
            let start = ctx.data_mut(|d| {
                *d.get_temp_mut_or_insert_with(egui::Id::new("qa-motion-start"), || now)
            });
            let done = ctx.data(|d| {
                d.get_temp::<bool>(egui::Id::new("qa-motion-done"))
                    .unwrap_or(false)
            });
            if !done {
                if now - start >= 0.85 {
                    self.catalog_open = true;
                    ctx.data_mut(|d| d.insert_temp(egui::Id::new("qa-motion-done"), true));
                } else {
                    ctx.request_repaint_after(std::time::Duration::from_secs_f64(
                        0.85 - (now - start),
                    ));
                }
            }
        }
        #[cfg(feature = "qa")]
        if std::env::var("EIVRO_QA_FIXTURE").as_deref() == Ok("1")
            && std::env::var("EIVRO_QA_CONNECTION_EFFECT").as_deref() == Ok("1")
        {
            // Isolated visual recording only: never starts a network session.
            let now = ctx.input(|i| i.time);
            let start = ctx.data_mut(|d| {
                *d.get_temp_mut_or_insert_with(egui::Id::new("qa-connection-effect"), || now)
            });
            let age = now - start;
            self.running = (1.2..6.0).contains(&age);
            self.want_connected = (0.6..6.0).contains(&age);
            self.helper_ready = true;
            for deadline in [0.6, 1.2, 6.0] {
                if age < deadline {
                    ctx.request_repaint_after(std::time::Duration::from_secs_f64(deadline - age));
                    break;
                }
            }
        }
        self.sync_connection_effect(ctx);
        let previous_focus = ctx.memory(|m| m.focused());
        self.shell(ctx, p);
        self.catalog(ctx, p);
        self.dialogs(ctx, p);
        let modal_open = self.navigation_overlay
            || self.catalog_open
            || self.import_open
            || self.delete_server
            || self.delete_subscription.is_some()
            || self.rename_subscription.is_some()
            || (self.page == Page::Routes && self.editor.as_ref().is_some_and(Editor::modal_open));
        if modal_open && !self.modal_was_open {
            self.modal_return_focus = previous_focus.or(self.navigation_button);
        } else if !modal_open && let Some(id) = self.modal_return_focus {
            // egui retires the modal layer at the end of the following frame.
            // Returning focus sooner lets that layer discard it again.
            if ctx.memory(|m| m.top_modal_layer().is_none()) {
                let target = ctx
                    .read_response(id)
                    .filter(|r| r.enabled())
                    .map(|r| r.id)
                    .or(self.navigation_button);
                if let Some(target) = target {
                    ctx.memory_mut(|m| m.request_focus(target));
                }
                self.modal_return_focus = None;
            }
            ctx.request_repaint();
        }
        self.modal_was_open = modal_open;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    fn model() -> App {
        let mut settings = Settings {
            port: std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port(),
            mode: Mode::Local,
            ..Settings::default()
        };
        let profiles = (1..=2)
            .map(|n| eivro::import::Profile {
                name: format!("Server {n}"),
                uri: format!("ss://chacha20-ietf-poly1305:synthetic@127.0.0.1:{n}"),
            })
            .collect();
        settings
            .apply_document(
                None,
                Document {
                    name: "Synthetic".into(),
                    source: None,
                    profiles,
                    metadata: Default::default(),
                },
            )
            .unwrap();
        App::model(settings, None, None)
    }
    fn subscription_document(port: u16) -> Document {
        Document {
            name: "Synthetic".into(),
            source: Some("https://provider.example/sub/synthetic".into()),
            profiles: (0..2)
                .map(|n| eivro::import::Profile {
                    name: format!("Server {}", n + 1),
                    uri: format!(
                        "ss://chacha20-ietf-poly1305:synthetic@127.0.0.1:{}",
                        port + n
                    ),
                })
                .collect(),
            metadata: Default::default(),
        }
    }
    #[test]
    fn subscription_changes_are_published_only_after_settings_are_saved() {
        for target in [None, Some(1)] {
            let dir = std::env::temp_dir().join(format!(
                "eivro-ui-import-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let path = dir.join("settings.json");
            let mut settings = Settings::default();
            settings
                .apply_document(None, subscription_document(443))
                .unwrap();
            settings.current_mut().unwrap().selected = 1;
            settings.routing_profiles[0]
                .add_addresses("example.test", eivro::policy::Action::Direct)
                .unwrap();
            storage::save(&path, &settings).unwrap();
            let before = serde_json::to_value(&settings).unwrap();
            let bytes = std::fs::read(&path).unwrap();
            let mut app = App::model(settings, Some(path.clone()), None);
            app.want_connected = true;
            app.import_open = target.is_none();
            app.import_text = "Synthetic input".into();
            app.import_reveal = true;
            if let Some(id) = target {
                app.retry_after.insert(id, 1);
                app.refresh_errors.insert(id, "Previous failure".into());
            }
            let mut document = subscription_document(445);
            if target.is_none() {
                document.source = Some("https://other.example/sub/synthetic".into());
            }
            let temp = dir.join(format!(".settings-{}.tmp", std::process::id()));
            std::fs::write(&temp, b"Synthetic write conflict").unwrap();
            let (tx, rx) = mpsc::channel();
            app.import_result = Some(rx);
            app.import_target = target;
            tx.send(Ok(document.clone())).unwrap();
            let now = catalog::now();
            app.receive(&egui::Context::default());
            assert_eq!(serde_json::to_value(&app.settings).unwrap(), before);
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
            assert!(app.recovery.due.is_none());
            assert!(app.want_connected);
            let error = if let Some(id) = target {
                assert!(app.retry_after[&id] >= now + 300);
                &app.refresh_errors[&id]
            } else {
                assert!(app.import_open && app.import_reveal);
                assert_eq!(app.import_text, "Synthetic input");
                app.error.as_ref().unwrap()
            };
            assert_eq!(error, "Не удалось создать временный файл настроек.");

            std::fs::remove_file(&temp).unwrap();
            let (tx, rx) = mpsc::channel();
            app.import_result = Some(rx);
            app.import_target = target;
            tx.send(Ok(document)).unwrap();
            app.receive(&egui::Context::default());
            assert_eq!(
                serde_json::to_value(storage::load(&path).unwrap()).unwrap(),
                serde_json::to_value(&app.settings).unwrap()
            );
            assert_eq!(app.settings.current().unwrap().selected, 1);
            assert_eq!(
                app.settings.routing_profiles[0].rules[0].target.value(),
                "example.test"
            );
            assert_eq!(app.recovery.due.is_some(), target.is_some());
            if let Some(id) = target {
                assert!(!app.retry_after.contains_key(&id));
                assert!(!app.refresh_errors.contains_key(&id));
                assert!(
                    app.settings
                        .selected_profile()
                        .unwrap()
                        .uri
                        .ends_with(":446")
                );
            } else {
                assert_eq!(app.settings.subscriptions.len(), 2);
                assert!(!app.import_open && !app.import_reveal);
                assert!(app.import_text.is_empty());
            }
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
    #[test]
    fn subscription_refresh_errors_preserve_settings_and_schedule_retry() {
        let dir = std::env::temp_dir().join(format!(
            "eivro-ui-refresh-errors-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = dir.join("settings.json");
        let mut settings = Settings::default();
        settings
            .apply_document(None, subscription_document(443))
            .unwrap();
        settings.current_mut().unwrap().selected = 1;
        settings.routing_profiles[0]
            .add_addresses("example.test", eivro::policy::Action::Direct)
            .unwrap();
        storage::save(&path, &settings).unwrap();
        let before = serde_json::to_value(&settings).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let selected = settings.selected_profile().unwrap().uri.clone();
        let mut app = App::model(settings, Some(path.clone()), None);
        app.want_connected = true;
        app.running = true;
        for error in [
            "HTTP 401: доступ к подписке запрещён. Проверьте ссылку и срок действия.",
            "HTTP 429: провайдер ограничил частоту обновлений. Повторите позже.",
            "HTTP 500: сервис подписок временно недоступен. Повторите позже.",
            "Время загрузки подписки истекло. Проверьте сеть и повторите позже.",
            "Некорректный JSON подписки.",
        ] {
            let (tx, rx) = mpsc::channel();
            app.import_result = Some(rx);
            app.import_target = Some(1);
            app.retry_after.insert(1, 0);
            tx.send(Err(error.into())).unwrap();
            let now = catalog::now();
            app.receive(&egui::Context::default());
            assert_eq!(serde_json::to_value(&app.settings).unwrap(), before);
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
            assert_eq!(app.settings.selected_profile().unwrap().uri, selected);
            assert_eq!(
                app.settings.routing_profiles[0].rules[0].target.value(),
                "example.test"
            );
            assert!(app.want_connected && app.running);
            assert!(!app.stopping && !app.reconnect_pending);
            assert!(app.recovery.due.is_none());
            assert_eq!(app.refresh_errors[&1], error);
            assert!((now + 300..=catalog::now() + 300).contains(&app.retry_after[&1]));
            assert!(app.import_result.is_none() && app.import_target.is_none());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn subscription_import_is_not_applied_when_saving_is_disabled() {
        let mut app = App::model(Settings::default(), None, None);
        let before = serde_json::to_value(&app.settings).unwrap();
        app.import_open = true;
        app.import_text = "Synthetic input".into();
        let (tx, rx) = mpsc::channel();
        app.import_result = Some(rx);
        tx.send(Ok(subscription_document(443))).unwrap();
        app.receive(&egui::Context::default());
        assert_eq!(serde_json::to_value(&app.settings).unwrap(), before);
        assert!(app.import_open);
        assert_eq!(app.import_text, "Synthetic input");
        assert_eq!(
            app.error.as_deref(),
            Some("Сохранение отключено: сначала исправьте файл настроек. Обновление не применено.")
        );
    }
    #[test]
    fn subscription_refresh_only_reconnects_when_the_selected_connection_changes() {
        let dir = std::env::temp_dir().join(format!(
            "eivro-ui-annotations-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = dir.join("settings.json");
        let mut original = subscription_document(443);
        original.profiles = (0..2)
            .map(|n| eivro::import::Profile {
                name: "Shared".into(),
                uri: format!(
                    "vless://a3ba7b44-3275-42e7-9a54-30aa2bde0437@edge{n}.example:443?security=tls&type=tcp&sni=cover.example#Shared"
                ),
            })
            .collect();
        let mut settings = Settings::default();
        settings.apply_document(None, original.clone()).unwrap();
        storage::save(&path, &settings).unwrap();
        let mut app = App::model(settings, Some(path.clone()), None);
        app.want_connected = true;
        let mut updated = original;
        updated.profiles.reverse();
        for profile in &mut updated.profiles {
            profile.uri = profile
                .uri
                .replace("#Shared", "&x-durev-sni-change=true#Shared");
        }
        let (tx, rx) = mpsc::channel();
        app.import_result = Some(rx);
        app.import_target = Some(1);
        tx.send(Ok(updated.clone())).unwrap();
        app.receive(&egui::Context::default());
        assert_eq!(app.settings.current().unwrap().selected, 1);
        assert!(app.recovery.due.is_none());
        assert_eq!(
            serde_json::to_value(storage::load(&path).unwrap()).unwrap(),
            serde_json::to_value(&app.settings).unwrap()
        );

        for (before, after) in [
            (
                "a3ba7b44-3275-42e7-9a54-30aa2bde0437",
                "a3ba7b44-3275-42e7-9a54-30aa2bde0438",
            ),
            ("sni=cover.example", "sni=other.example"),
            ("edge0.example", "other.example"),
        ] {
            app.recovery.cancel();
            updated.profiles[1].uri = updated.profiles[1].uri.replace(before, after);
            // Keep the name unique so credential/host rotation retains this endpoint.
            updated.profiles[1].name = "Selected".into();
            app.settings.current_mut().unwrap().profiles[1].name = "Selected".into();
            let (tx, rx) = mpsc::channel();
            app.import_result = Some(rx);
            app.import_target = Some(1);
            tx.send(Ok(updated.clone())).unwrap();
            app.receive(&egui::Context::default());
            assert_eq!(app.settings.current().unwrap().selected, 1);
            assert!(app.recovery.due.is_some(), "{before}");
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn close_hides_only_when_a_tray_host_is_available() {
        for (online, window_hiding) in [(false, true), (true, true), (true, false)] {
            let mut app = model();
            app.tray_online = online;
            app.window_hiding = window_hiding;
            let ctx = egui::Context::default();
            let mut input = egui::RawInput::default();
            input
                .viewports
                .get_mut(&egui::ViewportId::ROOT)
                .unwrap()
                .events
                .push(egui::ViewportEvent::Close);
            let output = ctx.run(input, |ctx| {
                // The close handling is shared with update below.
                app.handle_close(ctx);
            });
            assert_eq!(app.hidden, online && window_hiding);
            assert!(
                output.viewport_output[&egui::ViewportId::ROOT]
                    .commands
                    .iter()
                    .any(|c| matches!(c, egui::ViewportCommand::CancelClose))
            );
            if online && window_hiding {
                assert!(
                    output.viewport_output[&egui::ViewportId::ROOT]
                        .commands
                        .iter()
                        .any(|c| matches!(c, egui::ViewportCommand::Visible(false)))
                );
            }
        }
    }
    #[test]
    fn idle_window_stops_requesting_frames() {
        use eframe::App as _;
        let ctx = egui::Context::default();
        crate::emoji::install(&ctx);
        let mut frame = eframe::Frame::_new_kittest();
        let mut app = App::model(Settings::default(), None, None);
        for pass in 0..20 {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(960.0, 760.0),
                )),
                time: Some(pass as f64),
                ..Default::default()
            };
            let output = ctx.run(input, |ctx| app.update(ctx, &mut frame));
            if pass > 10 {
                assert!(
                    output.viewport_output[&egui::ViewportId::ROOT].repaint_delay
                        > Duration::from_secs(60),
                    "idle repaint: {:?}",
                    ctx.repaint_causes()
                );
            }
        }
    }
    #[test]
    fn navigation_can_hide_reopen_and_escape_without_a_repaint_loop() {
        use eframe::App as _;
        for width in [960.0, 650.0] {
            let ctx = egui::Context::default();
            crate::emoji::install(&ctx);
            let mut frame = eframe::Frame::_new_kittest();
            let mut app = App::model(Settings::default(), None, None);
            for step in 0..38 {
                let modifiers = if [2, 12].contains(&step) {
                    egui::Modifiers::CTRL
                } else {
                    egui::Modifiers::NONE
                };
                let key = if [2, 12].contains(&step) {
                    Some(egui::Key::B)
                } else if step == 22 {
                    Some(egui::Key::Escape)
                } else {
                    None
                };
                let output = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            Vec2::new(width, 760.0),
                        )),
                        time: Some(step as f64 * 0.1),
                        modifiers,
                        events: key
                            .map(|key| egui::Event::Key {
                                key,
                                physical_key: None,
                                pressed: true,
                                repeat: false,
                                modifiers,
                            })
                            .into_iter()
                            .collect(),
                        ..Default::default()
                    },
                    |ctx| app.update(ctx, &mut frame),
                );
                if step == 8 {
                    if width < 780.0 {
                        assert!(app.navigation_overlay);
                    } else {
                        assert!(!app.sidebar_open);
                    }
                }
                if step == 18 {
                    if width < 780.0 {
                        assert!(!app.navigation_overlay);
                        app.navigation_overlay = true;
                    } else {
                        assert!(app.sidebar_open);
                    }
                }
                if step > 32 {
                    assert!(!app.navigation_overlay);
                    assert!(
                        output.viewport_output[&egui::ViewportId::ROOT].repaint_delay
                            > Duration::from_secs(60)
                    );
                }
            }
        }
    }
    #[test]
    fn catalog_opens_closes_with_escape_and_stops_animating() {
        use eframe::App as _;
        let ctx = egui::Context::default();
        crate::emoji::install(&ctx);
        let mut frame = eframe::Frame::_new_kittest();
        let mut app = App::model(Settings::default(), None, None);
        for step in 0..35 {
            let mut events = vec![];
            if step == 2 {
                app.catalog_open = true;
            }
            if step == 12 {
                events.push(egui::Event::Key {
                    key: egui::Key::Escape,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: egui::Modifiers::NONE,
                });
            }
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(960.0, 760.0),
                    )),
                    time: Some(step as f64 * 0.1),
                    events,
                    ..Default::default()
                },
                |ctx| app.update(ctx, &mut frame),
            );
            if step == 10 {
                assert!(app.catalog_open);
            }
            if step > 25 {
                assert!(!app.catalog_open);
                assert!(
                    output.viewport_output[&egui::ViewportId::ROOT].repaint_delay
                        > Duration::from_secs(60)
                );
            }
        }
    }
    #[test]
    fn closing_a_modal_restores_the_keyboard_trigger() {
        use eframe::App as _;
        let ctx = egui::Context::default();
        crate::emoji::install(&ctx);
        let mut frame = eframe::Frame::_new_kittest();
        let mut app = App::model(Settings::default(), None, None);
        let mut render = |app: &mut App, key: Option<egui::Key>| {
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(960.0, 760.0),
                    )),
                    events: key
                        .map(|key| egui::Event::Key {
                            key,
                            physical_key: None,
                            pressed: true,
                            repeat: false,
                            modifiers: egui::Modifiers::NONE,
                        })
                        .into_iter()
                        .collect(),
                    ..Default::default()
                },
                |ctx| app.update(ctx, &mut frame),
            );
        };
        render(&mut app, None);
        let trigger = app.navigation_button.unwrap();
        ctx.memory_mut(|m| m.request_focus(trigger));
        app.import_open = true;
        render(&mut app, None);
        render(&mut app, Some(egui::Key::Tab));
        assert_ne!(ctx.memory(|m| m.focused()), Some(trigger));
        render(&mut app, Some(egui::Key::Escape));
        assert!(!app.import_open);
        render(&mut app, None);
        render(&mut app, None);
        assert_eq!(ctx.memory(|m| m.focused()), Some(trigger));
    }
    #[test]
    fn failed_protected_connection_remains_held_when_automatic_recovery_is_off() {
        let mut app = model();
        app.settings.mode = Mode::Tun;
        app.settings.kill_switch = true;
        app.settings.reconnect = false;
        app.want_connected = true;
        app.running = false;
        app.guard_session = true; // A previously running protected session is restarting.
        let (tx, rx) = mpsc::channel();
        app.events = Some(rx);
        tx.send(Event::Failed("Синтетический обрыв ядра".into()))
            .unwrap();
        app.receive(&egui::Context::default());
        assert!(app.want_connected && app.recovery.exhausted);
        assert!(app.recovery.due.is_none() && app.session.is_none());
        app.connect(&egui::Context::default());
        assert!(!app.want_connected);
    }
    fn wait(app: &mut App, ctx: &egui::Context, running: bool) {
        let deadline = Instant::now() + Duration::from_secs(6);
        while Instant::now() < deadline {
            app.receive(ctx);
            if app.running == running && (running || app.session.is_none()) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("connection transition timed out: {:?}", app.error);
    }
    #[test]
    fn server_switch_and_rule_entry_work_while_connected() {
        let ctx = egui::Context::default();
        let mut app = model();
        app.connect(&ctx);
        wait(&mut app, &ctx, true);
        app.settings.current_mut().unwrap().selected = 1;
        app.reconfigure();
        assert!(app.stopping);
        wait(&mut app, &ctx, true);
        assert_eq!(app.settings.selected_profile().unwrap().name, "Server 2");
        app.settings.routing_profiles[0]
            .add_addresses("*.example.test", eivro::policy::Action::Direct)
            .unwrap();
        app.reconfigure();
        assert_eq!(
            app.settings.routing_profiles[0].rules[0].target.value(),
            "*.example.test"
        );
        wait(&mut app, &ctx, true);
        // A failed mode switch must settle in an error, not endlessly reconnect.
        app.settings.mode = Mode::Proxy;
        app.reconfigure();
        wait(&mut app, &ctx, false);
        assert!(!app.want_connected);
        assert!(app.error.as_ref().is_some_and(|e| e.contains("HTTPS")));
    }
    #[test]
    fn disconnect_cancels_a_pending_switch() {
        let ctx = egui::Context::default();
        let mut app = model();
        app.connect(&ctx);
        wait(&mut app, &ctx, true);
        app.settings.current_mut().unwrap().selected = 1;
        app.reconfigure();
        app.connect(&ctx);
        wait(&mut app, &ctx, false);
        assert!(!app.want_connected);
    }
}
