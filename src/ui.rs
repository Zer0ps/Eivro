mod desktop;
mod rules;
use self::rules::Editor;
use eframe::egui::{self, Align2, Color32, FontId, RichText, Stroke, Vec2};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        mpsc::{self, Receiver},
    },
};
use velum::{
    catalog::{self, Document, UpdatePolicy},
    config::{ConnectRequest, Mode},
    process::{self, Event, Session},
    storage::{self, Settings, Theme},
};

pub struct App {
    settings: Settings,
    path: Option<PathBuf>,
    session: Option<Session>,
    events: Option<Receiver<Event>>,
    running: bool,
    phase: &'static str,
    helper_ready: bool,
    install_result: Option<Receiver<velum::Result<()>>>,
    stopping: bool,
    error: Option<String>,
    import_open: bool,
    import_text: String,
    import_reveal: bool,
    import_result: Option<Receiver<velum::Result<Document>>>,
    appearance: bool,
    test_input: String,
    delete_server: bool,
    subscriptions_open: bool,
    delete_subscription: Option<u64>,
    import_target: Option<u64>,
    retry_after: std::collections::HashMap<u64, u64>,
    refresh_errors: std::collections::HashMap<u64, String>,
    want_connected: bool,
    reconnect_pending: bool,
    tun: Arc<velum::tun::Controller>,
    editor: Option<Editor>,
    desktop: Option<velum::desktop::Desktop>,
    tray_online: bool,
    window_hiding: bool,
    hidden: bool,
    quitting: bool,
    background_start: bool,
    recovery: velum::recovery::Recovery,
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
}

impl App {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        instance: crate::instance::Instance,
        window_hiding: bool,
    ) -> Self {
        let path = storage::default_path();
        let loaded = path
            .as_ref()
            .map_err(Clone::clone)
            .and_then(|p| storage::load(p));
        let error = loaded
            .as_ref()
            .err()
            .cloned()
            .or_else(|| velum::system_proxy::recover_stale().err());
        let writable = error.is_none();
        let settings = loaded.unwrap_or_default();
        let mut style = (*cc.egui_ctx.style()).clone();
        style.spacing.item_spacing = Vec2::new(10.0, 8.0);
        style.spacing.button_padding = Vec2::new(14.0, 8.0);
        style.spacing.interact_size.y = 32.0;
        style.spacing.window_margin = egui::Margin::symmetric(18, 10);
        style
            .text_styles
            .insert(egui::TextStyle::Body, FontId::proportional(15.0));
        style
            .text_styles
            .insert(egui::TextStyle::Button, FontId::proportional(14.0));
        style
            .text_styles
            .insert(egui::TextStyle::Small, FontId::proportional(12.0));
        style.animation_time = 0.0;
        cc.egui_ctx.set_style(style);
        crate::emoji::install(&cc.egui_ctx);
        let mut app = Self::model(settings, if writable { path.ok() } else { None }, error);
        app.window_hiding = window_hiding;
        instance.set_context(cc.egui_ctx.clone());
        app.instance = Some(instance);
        let ctx = cc.egui_ctx.clone();
        app.desktop = Some(velum::desktop::Desktop::start(Arc::new(move || {
            ctx.request_repaint()
        })));
        app.background_start = std::env::args().any(|s| s == "--background");
        app.autostart = velum::desktop::autostart_path().is_ok_and(|p| p.is_file());
        if app.settings.autoconnect && app.settings.selected_profile().is_some() {
            app.want_connected = true;
            app.recovery.schedule(std::time::Instant::now());
        }
        #[cfg(feature = "qa")]
        match std::env::var("VELUM_QA_PAGE").as_deref() {
            Ok("rules") => app.editor = Some(Editor::new(&app.settings)),
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
            _ => {}
        }
        #[cfg(feature = "qa")]
        if std::env::var("VELUM_QA_CONNECTED").as_deref() == Ok("1") {
            // Visual fixture only: no session or network operation is started.
            app.running = true;
            app.want_connected = true;
            app.helper_ready = true;
            app.settings.mode = Mode::Tun;
        }
        app
    }

    fn model(settings: Settings, path: Option<PathBuf>, error: Option<String>) -> Self {
        Self {
            settings,
            path,
            session: None,
            events: None,
            running: false,
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
            test_input: String::new(),
            delete_server: false,
            subscriptions_open: cfg!(feature = "qa")
                && std::env::var("VELUM_QA_PAGE").as_deref() == Ok("subscriptions"),
            delete_subscription: None,
            import_target: None,
            retry_after: Default::default(),
            refresh_errors: Default::default(),
            want_connected: false,
            reconnect_pending: false,
            tun: Arc::new(velum::tun::Controller::default()),
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
                self.error = Some("Для скрытия окна в трей нужен XWayland. Для выхода используйте «Завершить Velum» в настройках.".into());
            } else {
                self.error = Some(
                    "Трей недоступен. Для выхода используйте «Завершить Velum» в настройках."
                        .into(),
                );
            }
        }
    }

    fn palette(&self) -> Palette {
        let [r, g, b] = self.settings.accent;
        if self.settings.theme == Theme::Dark {
            Palette {
                bg: Color32::from_rgb(15, 18, 20),
                card: Color32::from_rgb(22, 26, 29),
                raised: Color32::from_rgb(30, 35, 39),
                line: Color32::from_rgb(43, 50, 55),
                text: Color32::from_rgb(235, 239, 240),
                muted: Color32::from_rgb(139, 152, 160),
                accent: Color32::from_rgb(r, g, b),
            }
        } else {
            Palette {
                bg: Color32::from_rgb(244, 246, 244),
                card: Color32::WHITE,
                raised: Color32::from_rgb(239, 243, 240),
                line: Color32::from_rgb(221, 227, 223),
                text: Color32::from_rgb(26, 39, 33),
                muted: Color32::from_rgb(101, 117, 108),
                accent: Color32::from_rgb(r, g, b),
            }
        }
    }

    fn save(&mut self) {
        if let Some(path) = &self.path {
            if let Err(e) = storage::save(path, &self.settings) {
                self.error = Some(e);
            }
        } else {
            self.error=Some("Сохранение отключено: сначала исправьте файл настроек. Текущие изменения останутся только в памяти.".into());
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

    fn button(
        ui: &mut egui::Ui,
        label: &str,
        width: f32,
        fill: Color32,
        text: Color32,
    ) -> egui::Response {
        ui.add_sized(
            [width, 43.0],
            egui::Button::new(RichText::new(label).color(text))
                .fill(fill)
                .corner_radius(10),
        )
    }

    fn card(p: Palette) -> egui::Frame {
        egui::Frame::new()
            .fill(p.card)
            .stroke(Stroke::new(1.0_f32, p.line))
            .corner_radius(18)
            .inner_margin(24)
    }

    fn connection(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, p: Palette) {
        ui.label(
            RichText::new("Подключение")
                .size(18.0)
                .strong()
                .color(p.text),
        );
        ui.add_space(12.0);
        ui.vertical_centered(|ui| {
            let diameter = if ctx.content_rect().height() < 700.0 {
                80.0
            } else {
                130.0
            };
            let (rect, response) =
                ui.allocate_exact_size(Vec2::splat(diameter), egui::Sense::click());
            let center = rect.center();
            let color = if self.running { p.accent } else { p.muted };
            ui.painter()
                .circle_stroke(center, diameter * 0.5 + 3.0, Stroke::new(1.0_f32, p.line));
            ui.painter()
                .circle_filled(center, diameter * 0.42, p.raised);
            let points: Vec<_> = (0..=50)
                .map(|i| {
                    let angle = std::f32::consts::FRAC_PI_2 * 1.5
                        + (i as f32 / 50.0) * std::f32::consts::PI * 1.5;
                    center + Vec2::new(angle.cos(), angle.sin()) * 21.0
                })
                .collect();
            ui.painter()
                .add(egui::Shape::line(points, Stroke::new(3.0_f32, color)));
            ui.painter().line_segment(
                [
                    center + Vec2::new(0.0, -28.0),
                    center + Vec2::new(0.0, -4.0),
                ],
                Stroke::new(3.0_f32, color),
            );
            if response.clicked() && self.settings.selected_profile().is_some() && !self.stopping {
                self.connect(ctx);
            }
            let title = if self.stopping {
                if self.reconnect_pending {
                    "Переключение…"
                } else {
                    "Отключение…"
                }
            } else if self.running {
                if self.settings.mode == Mode::Tun {
                    "TUN запущен"
                } else if self.settings.mode == Mode::Local {
                    "Локальный порт открыт"
                } else {
                    "Прокси включён"
                }
            } else if self.recovery.recovering && self.session.is_none() {
                if self.recovery.sleeping || self.recovery.offline {
                    "Ждём сеть…"
                } else {
                    if self.recovery.exhausted {
                        "Нет соединения"
                    } else {
                        "Восстановление…"
                    }
                }
            } else if self.session.is_some() {
                self.phase
            } else {
                "Отключено"
            };
            ui.label(RichText::new(title).size(24.0).strong().color(p.text));
            ui.label(
                RichText::new(if self.settings.mode == Mode::Local {
                    format!("SOCKS5 / HTTP · 127.0.0.1:{}", self.settings.port)
                } else if self.settings.mode == Mode::Proxy {
                    "Системный прокси GNOME".into()
                } else {
                    "Весь трафик через TUN".into()
                })
                .size(12.0)
                .color(p.muted),
            );
        });
        ui.add_space(12.0);
        let mut changed = false;
        let old_group = self.settings.selected_subscription;
        let group = self
            .settings
            .current()
            .map(|s| s.name.as_str())
            .unwrap_or("Добавьте подписку");
        egui::ComboBox::from_id_salt("subscription")
            .truncate()
            .width(ui.available_width() - 8.0)
            .selected_text(crate::emoji::text(group))
            .show_ui(ui, |ui| {
                for (i, sub) in self.settings.subscriptions.iter().enumerate() {
                    ui.selectable_value(
                        &mut self.settings.selected_subscription,
                        i,
                        crate::emoji::text(&sub.name),
                    );
                }
            });
        changed |= old_group != self.settings.selected_subscription;
        if let Some(sub) = self.settings.current_mut() {
            let name = sub
                .selected_profile()
                .map(|p| p.name.clone())
                .unwrap_or_else(|| "Нет серверов".into());
            egui::ComboBox::from_id_salt("server")
                .truncate()
                .width(ui.available_width() - 8.0)
                .selected_text(crate::emoji::text(&name))
                .show_ui(ui, |ui| {
                    for (i, profile) in sub.profiles.iter().enumerate() {
                        changed |= ui
                            .selectable_value(
                                &mut sub.selected,
                                i,
                                crate::emoji::text(&profile.name),
                            )
                            .changed();
                    }
                });
        }
        ui.horizontal(|ui| {
            changed |= ui
                .selectable_value(&mut self.settings.mode, Mode::Proxy, "Прокси")
                .changed();
            changed |= ui
                .selectable_value(&mut self.settings.mode, Mode::Local, "Локально")
                .changed();
            changed |= ui
                .selectable_value(&mut self.settings.mode, Mode::Tun, "TUN")
                .changed();
        });
        if changed {
            self.save();
            self.reconfigure();
        }
        if self.settings.mode == Mode::Tun && !self.helper_ready {
            ui.label(
                RichText::new("Обновите системный помощник Velum.")
                    .size(12.0)
                    .color(p.muted),
            );
            if process::install_package_path().is_some()
                && ui
                    .add_enabled(
                        self.install_result.is_none(),
                        egui::Button::new("Установить обновление"),
                    )
                    .clicked()
            {
                let (tx, rx) = mpsc::channel();
                self.install_result = Some(rx);
                let ctx = ctx.clone();
                std::thread::spawn(move || {
                    let _ = tx.send(process::install_package());
                    ctx.request_repaint();
                });
            }
        }
    }

    fn connection_actions(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, p: Palette) {
        let busy = self.session.is_some() || self.want_connected;
        let can_connect = self.settings.selected_profile().is_some()
            && (self.settings.mode != Mode::Tun || self.helper_ready);
        ui.add_enabled_ui(can_connect || busy, |ui| {
            let label = if busy {
                if self.stopping {
                    "Отменить"
                } else {
                    "Отключить"
                }
            } else {
                "Подключить"
            };
            if Self::button(
                ui,
                label,
                ui.available_width(),
                p.accent,
                contrast(p.accent),
            )
            .clicked()
            {
                self.connect(ctx);
            }
        });
        if Self::button(ui, "Подписки", ui.available_width(), p.raised, p.text).clicked() {
            self.subscriptions_open = true;
        }
        if self
            .settings
            .current()
            .is_some_and(|s| s.source.is_none() && !s.profiles.is_empty())
        {
            ui.horizontal(|ui| {
                if ui.button("Удалить сервер").clicked() {
                    self.delete_server = true;
                }
            });
        }
    }

    fn rules(&mut self, ui: &mut egui::Ui, p: Palette) {
        ui.label(RichText::new("Маршруты").size(18.0).strong());
        ui.label(
            RichText::new("Выберите, что идёт через VPN.")
                .size(13.0)
                .color(p.muted),
        );
        ui.add_space(18.0);
        let old = self.settings.selected_routing;
        egui::ComboBox::from_id_salt("routing-profile")
            .truncate()
            .width(ui.available_width() - 8.0)
            .selected_text(&self.settings.routing_profiles[old].name)
            .show_ui(ui, |ui| {
                for (i, profile) in self.settings.routing_profiles.iter().enumerate() {
                    ui.selectable_value(&mut self.settings.selected_routing, i, &profile.name);
                }
            });
        if old != self.settings.selected_routing {
            self.save();
            self.reconfigure();
        }
        let profile = &self.settings.routing_profiles[self.settings.selected_routing];
        let enabled = profile.rules.iter().filter(|r| r.enabled).count();
        ui.add_space(12.0);
        if enabled == 0 {
            ui.add_space(32.0);
            ui.label(RichText::new("Всё через VPN").size(22.0).strong());
            ui.label(
                RichText::new("Добавьте исключения для сайтов или приложений.").color(p.muted),
            );
            ui.add_space(32.0);
        } else {
            ui.label(
                RichText::new(format!("Активных правил: {enabled}"))
                    .size(12.0)
                    .color(p.muted),
            );
            let preview_count = if ui.ctx().content_rect().height() < 700.0 {
                3
            } else {
                5
            };
            for rule in profile
                .rules
                .iter()
                .filter(|r| r.enabled)
                .take(preview_count)
            {
                egui::Frame::new()
                    .inner_margin(egui::Margin::symmetric(8, 2))
                    .show(ui, |ui| {
                        ui.spacing_mut().interact_size.y = 22.0;
                        ui.horizontal(|ui| {
                            let name = rule.target.value();
                            let short =
                                if matches!(rule.target, velum::policy::Target::Application(_)) {
                                    name.rsplit('/').next().unwrap_or(name)
                                } else {
                                    name
                                };
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.label(
                                        RichText::new(rule.action.label()).small().color(p.muted),
                                    );
                                    ui.with_layout(
                                        egui::Layout::left_to_right(egui::Align::Center),
                                        |ui| {
                                            ui.add(egui::Label::new(short).truncate())
                                                .on_hover_text(name);
                                        },
                                    );
                                },
                            );
                        });
                    });
            }
            if enabled > preview_count {
                ui.label(
                    RichText::new(format!("Ещё {}…", enabled - preview_count))
                        .small()
                        .color(p.muted),
                );
            }
        }
    }

    fn rules_actions(&mut self, ui: &mut egui::Ui, p: Palette) {
        if Self::button(
            ui,
            "Настроить правила",
            ui.available_width(),
            p.accent,
            contrast(p.accent),
        )
        .clicked()
        {
            self.editor = Some(Editor::new(&self.settings));
        }
        ui.add_space(24.0);
        ui.separator();
        ui.add_space(8.0);
        ui.label(RichText::new("Проверить адрес").small().color(p.muted));
        ui.add(
            egui::TextEdit::singleline(&mut self.test_input)
                .hint_text("example.com")
                .margin(Vec2::new(10.0, 8.0))
                .desired_width(f32::INFINITY)
                .char_limit(255),
        );
        if !self.test_input.is_empty() {
            let action = self.settings.routing_profiles[self.settings.selected_routing]
                .matches(&self.test_input);
            ui.label(action.label());
        }
    }

    fn dialogs(&mut self, ctx: &egui::Context, p: Palette) {
        if self.import_open {
            let mut open = true;
            egui::Window::new("Добавить подписку или сервер")
                .collapsible(false)
                .resizable(false)
                .default_width(490.0)
                .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label(
                        RichText::new("Ссылка, JSON, HTTPS-подписка или путь к файлу")
                            .color(p.muted),
                    );
                    ui.add_sized(
                        [490.0, 120.0],
                        egui::TextEdit::multiline(&mut self.import_text)
                            .password(!self.import_reveal)
                            .hint_text("vless://…")
                            .char_limit(velum::MAX_IMPORT),
                    );
                    ui.checkbox(&mut self.import_reveal, "Показать содержимое");
                    ui.label(
                        RichText::new("VLESS · VMess · Trojan · Shadowsocks · Hysteria2")
                            .size(12.0)
                            .color(p.muted),
                    );
                    ui.label(
                        RichText::new("ZIP / gzip / TAR можно перетащить в окно.")
                            .size(12.0)
                            .color(p.muted),
                    );
                    if let Some(e) = &self.error {
                        ui.colored_label(Color32::from_rgb(223, 133, 114), e);
                    }
                    ui.add_enabled_ui(
                        self.import_result.is_none() && !self.import_text.trim().is_empty(),
                        |ui| {
                            if Self::button(
                                ui,
                                if self.import_result.is_some() {
                                    "Загрузка…"
                                } else {
                                    "Импортировать"
                                },
                                ui.available_width(),
                                p.accent,
                                contrast(p.accent),
                            )
                            .clicked()
                            {
                                self.start_job(self.import_text.clone(), None, ctx);
                            }
                        },
                    );
                });
            if !open {
                self.import_open = false;
                self.import_text.clear();
                self.import_reveal = false;
            }
        }
        if self.appearance {
            let mut open = true;
            let mut changed = false;
            egui::Window::new("Настройки")
                .collapsible(false)
                .resizable(false)
                .default_width(380.0)
                .default_height((ctx.content_rect().height() - 130.0).min(540.0))
                .max_height((ctx.content_rect().height() - 100.0).max(280.0))
                .vscroll(true)
                .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        changed |= ui
                            .selectable_value(&mut self.settings.theme, Theme::Light, "Светлая")
                            .changed();
                        changed |= ui
                            .selectable_value(&mut self.settings.theme, Theme::Dark, "Тёмная")
                            .changed();
                    });
                    ui.add_space(6.0);
                    ui.label("Акцент");
                    ui.horizontal(|ui| {
                        for (name, color) in [
                            ("Мята", [151, 223, 190]),
                            ("Небо", [167, 196, 250]),
                            ("Лаванда", [208, 180, 241]),
                            ("Песок", [244, 197, 135]),
                        ] {
                            let fill = Color32::from_rgb(color[0], color[1], color[2]);
                            let selected = self.settings.accent == color;
                            let (rect, response) = ui.allocate_exact_size(Vec2::splat(40.0), egui::Sense::click());
                            response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, ui.is_enabled(), name));
                            ui.painter().rect_filled(rect, 10, fill);
                            if response.hovered() || response.has_focus() {
                                ui.painter().rect_stroke(rect, 10, Stroke::new(1.0_f32, contrast(fill)),egui::StrokeKind::Inside);
                            }
                            let response = response.on_hover_text(name);
                            if selected {
                                let c = response.rect.center();
                                ui.painter().add(egui::Shape::line(vec![c + Vec2::new(-6.0,0.0),
                                    c + Vec2::new(-1.0,5.0), c + Vec2::new(7.0,-5.0)],
                                    Stroke::new(2.0_f32,contrast(fill))));
                            }
                            if response.clicked() {
                                self.settings.accent = color;
                                changed = true;
                            }
                        }
                        let custom = ui.add_sized([130.0, 40.0], egui::Button::new("Свой цвет…").corner_radius(10));
                        egui::Popup::menu(&custom).close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
                            .show(|ui| {
                                let mut color = Color32::from_rgb(self.settings.accent[0], self.settings.accent[1], self.settings.accent[2]);
                                if egui::color_picker::color_picker_color32(ui, &mut color, egui::color_picker::Alpha::Opaque) {
                                    self.settings.accent = [color.r(), color.g(), color.b()];
                                    changed = true;
                                }
                            });
                    });
                    ui.add_space(8.0);
                    ui.separator();
                    let old_guard=self.settings.kill_switch;
                    ui.checkbox(&mut self.settings.kill_switch,"Kill switch · TUN (экспериментально)");
                    if self.settings.kill_switch {
                        ui.label(RichText::new("При обрыве трафик блокируется до восстановления. Отключение и выход снимают защиту; она также затрагивает контейнеры.").small().color(p.muted));
                    }
                    if old_guard!=self.settings.kill_switch { changed=true; self.reconfigure(); }
                    ui.separator();
                    ui.add_enabled_ui(self.session.is_none(), |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Локальный порт");
                            changed |= ui
                                .add(
                                    egui::DragValue::new(&mut self.settings.port)
                                        .range(1024..=65535),
                                )
                                .changed();
                        });
                    });
                    ui.separator();
                    if ui.checkbox(&mut self.settings.reconnect, "Восстанавливать соединение").changed() {
                        changed=true;
                        if !self.settings.reconnect && self.recovery.recovering {self.recovery.due=None;self.recovery.exhausted=true;}
                    }
                    changed |= ui.checkbox(&mut self.settings.close_to_tray, "При закрытии — в трей").changed();
                    changed |= ui.checkbox(&mut self.settings.autoconnect, "Подключаться при запуске").changed();
                    if ui.checkbox(&mut self.autostart, "Запускать при входе в систему").changed() {
                        let result=velum::desktop::autostart_path().and_then(|path| {
                            let exe=std::env::current_exe().map_err(|_|"Нет пути Velum.")?;
                            velum::desktop::set_autostart(&path,&exe,self.autostart)
                        });
                        if let Err(e)=result { self.autostart= !self.autostart; self.error=Some(e); }
                    }
                    if !self.tray_online { ui.label(RichText::new("Трей недоступен: окно останется открытым.").small().color(p.muted)); }
                    if !self.window_hiding { ui.label(RichText::new("Скрытие и возврат окна из трея требуют XWayland.").small().color(p.muted)); }
                    if self.monitor_unavailable { ui.label(RichText::new("NetworkManager недоступен: автоматическая смена сети не отслеживается.").small().color(p.muted)); }
                    if ui.button("Завершить Velum").clicked() { self.quitting=true; ctx.send_viewport_cmd(egui::ViewportCommand::Close); }
                    ui.separator();
                    ui.label(
                        RichText::new("NOLOGS включён всегда. Телеметрии нет.")
                            .size(12.0)
                            .color(p.muted),
                    );
                    ui.label(
                        RichText::new("Логи и история подключений не сохраняются.")
                            .size(12.0)
                            .color(p.muted),
                    );
                });
            if changed {
                self.save();
            }
            self.appearance = open;
        }
        if self.delete_server {
            egui::Window::new("Удалить сервер?")
                .collapsible(false)
                .resizable(false)
                .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.label("Сохранённый ключ будет удалён из настроек.");
                    ui.horizontal(|ui| {
                        if ui.button("Удалить").clicked() {
                            if let Some(sub) = self.settings.current_mut()
                                && sub.selected < sub.profiles.len()
                            {
                                sub.profiles.remove(sub.selected);
                                sub.selected = 0;
                            }
                            self.reconfigure();
                            self.delete_server = false;
                            self.save();
                        }
                        if ui.button("Отмена").clicked() {
                            self.delete_server = false;
                        }
                    });
                });
        }
    }
}

fn contrast(c: Color32) -> Color32 {
    if (c.r() as f32 * 0.2126 + c.g() as f32 * 0.7152 + c.b() as f32 * 0.0722) > 140.0 {
        Color32::from_rgb(19, 34, 27)
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
            widgets.corner_radius = 8.into();
            widgets.expansion = 0.0;
        }
        ctx.set_visuals(visuals);
        let compact = ctx.content_rect().height() < 700.0;
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(p.bg)
                    .inner_margin(if compact { 20 } else { 30 }),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let (rect, _) =
                        ui.allocate_exact_size(Vec2::new(38.0, 38.0), egui::Sense::hover());
                    let c = rect.center();
                    ui.painter().rect_filled(rect, 11, p.accent);
                    ui.painter().line_segment(
                        [c + Vec2::new(-9.0, -7.0), c + Vec2::new(0.0, 9.0)],
                        Stroke::new(3.0_f32, contrast(p.accent)),
                    );
                    ui.painter().line_segment(
                        [c + Vec2::new(0.0, 9.0), c + Vec2::new(10.0, -9.0)],
                        Stroke::new(3.0_f32, contrast(p.accent)),
                    );
                    ui.label(RichText::new("velum").size(29.0).strong().color(p.text));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Настройки").clicked() {
                            self.appearance = !self.appearance;
                        }
                        ui.label(
                            RichText::new(format!("STABLE {}", env!("CARGO_PKG_VERSION")))
                                .monospace()
                                .size(11.0)
                                .color(p.muted),
                        );
                    });
                });
                ui.add_space(if compact { 12.0 } else { 20.0 });
                egui::ScrollArea::vertical().id_salt("page").show(ui, |ui| {
                    ui.columns(2, |columns| {
                        let card = Self::card(p).inner_margin(if compact { 16 } else { 24 });
                        let mut connection = card.begin(&mut columns[0]);
                        let mut routing = card.begin(&mut columns[1]);
                        self.connection(&mut connection.content_ui, ctx, p);
                        self.rules(&mut routing.content_ui, p);
                        // Measure both bodies before placing their actions. The cards
                        // share a baseline even with long names or many routing rules.
                        let action_top = connection
                            .content_ui
                            .cursor()
                            .top()
                            .max(routing.content_ui.cursor().top())
                            + 12.0;
                        for content in [&mut connection.content_ui, &mut routing.content_ui] {
                            content.add_space(action_top - content.cursor().top());
                        }
                        self.connection_actions(&mut connection.content_ui, ctx, p);
                        self.rules_actions(&mut routing.content_ui, p);
                        let height = connection
                            .content_ui
                            .min_size()
                            .y
                            .max(routing.content_ui.min_size().y)
                            .max(if compact { 430.0 } else { 490.0 });
                        for content in [&mut connection.content_ui, &mut routing.content_ui] {
                            let mut bounds = content.min_rect();
                            bounds.max.y = bounds.top() + height;
                            content.expand_to_include_rect(bounds);
                        }
                        connection.end(&mut columns[0]);
                        routing.end(&mut columns[1]);
                    });
                    ui.add_space(if compact { 0.0 } else { 8.0 });
                    ui.label(
                        RichText::new("NOLOGS")
                            .monospace()
                            .size(11.0)
                            .color(p.muted),
                    );
                    if let Some(error) = self.error.clone().filter(|_| !self.import_open) {
                        ui.horizontal_wrapped(|ui| {
                            ui.colored_label(Color32::from_rgb(223, 133, 114), error);
                            if ui.small_button("×").clicked() {
                                self.error = None;
                            }
                        });
                    }
                });
            });
        self.dialogs(ctx, p);
        if let Some(editor) = &mut self.editor {
            let applied = editor.show(ctx, p);
            let closed = !editor.open;
            if let Some((profiles, selected)) = applied {
                self.settings.routing_profiles = profiles;
                self.settings.selected_routing = selected;
                self.save();
                self.reconfigure();
                self.editor = None;
            } else if closed {
                self.editor = None;
            }
        }
        self.subscription_dialog(ctx, p);
    }
}

impl App {
    fn subscription_dialog(&mut self, ctx: &egui::Context, p: Palette) {
        if self.subscriptions_open {
            let mut open = true;
            let mut changed = false;
            let mut selection_changed = false;
            let mut refresh = None;
            let mut remove = None;
            egui::Window::new("Подписки").open(&mut open).anchor(Align2::CENTER_CENTER,Vec2::ZERO).default_size([580.0,620.0]).collapsible(false).show(ctx,|ui| {
                if ui.add_enabled(self.import_result.is_none(),egui::Button::new("+ Добавить")).clicked(){self.import_open=true;
}
                egui::ScrollArea::vertical().max_height(520.0).show(ui,|ui| {
                    if self.settings.subscriptions.is_empty(){ui.label("Добавьте HTTPS-ссылку, файл или сервер.");
}
                    for (index,sub) in self.settings.subscriptions.iter_mut().enumerate() {
                        egui::Frame::new().fill(p.raised).corner_radius(10).inner_margin(14).show(ui,|ui| {
                            ui.set_min_width(ui.available_width());

                            ui.horizontal(|ui| {
                                if ui.selectable_label(self.settings.selected_subscription==index,RichText::new(crate::emoji::text(&sub.name)).strong()).clicked(){self.settings.selected_subscription=index;
changed=true;
selection_changed=true;
}
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui| {
                                    ui.menu_button("...",|ui| {
                                        if sub.source.is_some() {
                                            ui.label("Автообновление");

                                            changed|=ui.selectable_value(&mut sub.update,UpdatePolicy::Manual,"Вручную").changed();

                                            changed|=ui.selectable_value(&mut sub.update,UpdatePolicy::Provider,"По провайдеру").changed();

                                            if ui.selectable_label(matches!(sub.update,UpdatePolicy::EveryHours(_)),"Свой интервал").clicked(){sub.update=UpdatePolicy::EveryHours(1);
changed=true;
}
                                            if let UpdatePolicy::EveryHours(ref mut hours)=sub.update {ui.horizontal(|ui|{changed|=ui.add(egui::DragValue::new(hours).range(1..=720).suffix(" ч")).changed();
});
}
                                            ui.separator();

                                        }
                                        if ui.add_enabled(self.import_target!=Some(sub.id),egui::Button::new("Удалить подписку")).clicked(){remove=Some(sub.id);
ui.close();
}
                                    });

                                    if sub.source.is_some() && ui.add_enabled(self.import_result.is_none(),egui::Button::new(if self.import_target==Some(sub.id){"Обновление…"}else{"Обновить"})).clicked(){refresh=Some((sub.id,sub.source.clone().unwrap()));
}
                                });

                            });

                            let update=match sub.update {UpdatePolicy::Manual=>"Вручную".into(),UpdatePolicy::Provider=>sub.metadata.interval_hours.map(|h|format!("По провайдеру · {h} ч")).unwrap_or_else(||"Провайдер не указал интервал".into()),UpdatePolicy::EveryHours(h)=>format!("Каждые {h} ч")};

                            if sub.source.is_some(){ui.label(RichText::new(update).size(12.0).color(p.muted));
}
                            else if sub.name=="Импортированные" {ui.label(RichText::new("Для обновлений добавьте ссылки подписок заново.").size(12.0).color(p.muted));
}
                            if let Some(at)=sub.refreshed_at {ui.label(RichText::new(format!("Обновлено {} · {} серверов",catalog::date(at),sub.profiles.len())).size(12.0).color(p.muted));
}
                            if let Some(error)=self.refresh_errors.get(&sub.id){ui.colored_label(Color32::from_rgb(223,133,114),error);
}
                            let m=&sub.metadata;

                            if let Some(expire)=m.expires{ui.label(format!("Действует до {}",catalog::date(expire)));
}
                            if m.upload.is_some()||m.download.is_some() {
                                let used=m.upload.unwrap_or(0).saturating_add(m.download.unwrap_or(0)) as f64/1073741824.0;

                                let limit=m.total.filter(|v|*v>0).map(|n|format!("{:.1} ГиБ",n as f64/1073741824.0)).unwrap_or_else(||"∞".into());

                                ui.label(format!("{used:.1} ГиБ / {limit}"));

                            }
                            if !m.announcement.is_empty() {egui::CollapsingHeader::new("Информация провайдера").id_salt(sub.id).default_open(true).show(ui,|ui|{ui.label(crate::emoji::text(&m.announcement));
});
}
                            ui.horizontal(|ui| {
                                if let Some(url)=&m.support_url{ui.hyperlink_to("Поддержка",url);
}
                                if let Some(url)=&m.website_url{ui.hyperlink_to("Личный кабинет",url);
}
                            });

                        });

                        ui.add_space(6.0);

                    }
                });

            });

            self.subscriptions_open = open;
            if changed {
                self.save();
            }
            if selection_changed {
                self.reconfigure();
            }
            if let Some((id, url)) = refresh {
                self.start_job(url, Some(id), ctx);
            }
            if remove.is_some() {
                self.delete_subscription = remove;
            }
        }
        if let Some(id) = self.delete_subscription {
            egui::Window::new("Удалить подписку?")
                .collapsible(false)
                .resizable(false)
                .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.label("Ссылка и серверы этой подписки будут удалены.");
                    ui.horizontal(|ui| {
                        if ui.button("Удалить").clicked() {
                            let selected = self.settings.current().map(|s| s.id);
                            self.settings.subscriptions.retain(|s| s.id != id);
                            self.settings.selected_subscription = selected
                                .and_then(|id| {
                                    self.settings.subscriptions.iter().position(|s| s.id == id)
                                })
                                .unwrap_or(0);
                            self.retry_after.remove(&id);
                            self.refresh_errors.remove(&id);
                            self.delete_subscription = None;
                            if selected == Some(id) {
                                self.reconfigure();
                            }
                            self.save();
                        }
                        if ui.button("Отмена").clicked() {
                            self.delete_subscription = None;
                        }
                    });
                });
        }
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
            .map(|n| velum::import::Profile {
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
                .map(|n| velum::import::Profile {
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
                "velum-ui-import-{}-{}",
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
                .add_addresses("example.test", velum::policy::Action::Direct)
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
            "velum-ui-refresh-errors-{}-{}",
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
            .add_addresses("example.test", velum::policy::Action::Direct)
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
            "velum-ui-annotations-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = dir.join("settings.json");
        let mut original = subscription_document(443);
        original.profiles = (0..2)
            .map(|n| velum::import::Profile {
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
            .add_addresses("*.example.test", velum::policy::Action::Direct)
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
