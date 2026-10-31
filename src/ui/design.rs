use super::*;

pub(super) fn mix(a: Color32, b: Color32, t: f32) -> Color32 {
    let channel = |a: u8, b: u8| (a as f32 * (1.0 - t) + b as f32 * t).round() as u8;
    Color32::from_rgb(
        channel(a.r(), b.r()),
        channel(a.g(), b.g()),
        channel(a.b(), b.b()),
    )
}
pub(super) fn luminance(c: Color32) -> f32 {
    let linear = |v: u8| {
        let v = v as f32 / 255.0;
        if v <= 0.04045 {
            v / 12.92
        } else {
            ((v + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * linear(c.r()) + 0.7152 * linear(c.g()) + 0.0722 * linear(c.b())
}
pub(super) fn accent_on(accent: Color32, background: Color32) -> Color32 {
    let target = if luminance(background) < 0.2 {
        Color32::WHITE
    } else {
        Color32::BLACK
    };
    let ratio = |c| {
        let a = luminance(c);
        let b = luminance(background);
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    };
    (0..=20)
        .map(|i| mix(accent, target, i as f32 / 20.0))
        .find(|c| ratio(*c) >= 4.5)
        .unwrap_or(target)
}
#[derive(Clone, Copy)]
pub(super) enum ButtonTone {
    Primary,
    Secondary,
    Quiet,
    Selected,
    Danger,
    Segment(bool),
}

/// Shared command geometry and finite hover/press transitions. The underlying
/// egui button retains keyboard activation, focus and accessibility semantics.
pub(super) fn command(
    ui: &mut egui::Ui,
    text: impl Into<String>,
    tone: ButtonTone,
    size: Vec2,
    p: Palette,
) -> egui::Response {
    let text = text.into();
    let (base, ink) = match tone {
        ButtonTone::Primary => (p.accent, contrast(p.accent)),
        ButtonTone::Segment(selected) => (
            if selected { p.card } else { p.raised },
            if selected { p.accent } else { p.muted },
        ),
        ButtonTone::Secondary => (p.raised, p.text),
        ButtonTone::Quiet => (p.card, p.muted),
        ButtonTone::Selected => (p.soft, p.accent),
        ButtonTone::Danger => (mix(p.card, p.error, 0.08), p.error),
    };
    let background = ui.painter().add(egui::Shape::Noop);
    let mut button = egui::Button::new(RichText::new(text).color(ink))
        .fill(Color32::TRANSPARENT)
        .stroke(Stroke::NONE)
        .corner_radius(9)
        .min_size(Vec2::new(size.x, size.y.max(36.0)));
    if matches!(
        tone,
        ButtonTone::Selected | ButtonTone::Quiet | ButtonTone::Segment(_)
    ) {
        button = button.right_text(
            if matches!(tone, ButtonTone::Selected | ButtonTone::Segment(true)) {
                "✓"
            } else {
                ""
            },
        );
    }
    let response = if size.x > 0.0 {
        ui.add_sized(Vec2::new(size.x, size.y.max(36.0)), button)
    } else {
        ui.add(button)
    };
    let duration = ui.style().animation_time;
    let hover = ui.ctx().animate_bool_with_time(
        response.id.with("button-hover"),
        response.enabled() && (response.hovered() || response.has_focus()),
        duration.min(0.14),
    );
    let keyboard_press = response.has_focus()
        && ui.input(|i| i.key_down(egui::Key::Space) || i.key_down(egui::Key::Enter));
    let down = ui.ctx().animate_bool_with_time(
        response.id.with("button-down"),
        response.enabled() && (response.is_pointer_button_down_on() || keyboard_press),
        duration.min(0.08),
    );
    let mut fill = mix(mix(base, p.text, 0.065 * hover), p.bg, 0.16 * down);
    if matches!(tone, ButtonTone::Primary) {
        let ratio = (luminance(fill).max(luminance(ink)) + 0.05)
            / (luminance(fill).min(luminance(ink)) + 0.05);
        if ratio < 4.5 {
            fill = mix(
                base,
                if ink == Color32::WHITE {
                    Color32::BLACK
                } else {
                    Color32::WHITE
                },
                0.065 * hover + 0.1 * down,
            );
        }
    }
    if !response.enabled() {
        fill = fill.gamma_multiply(0.38);
    }
    let stroke = if response.has_focus() {
        Stroke::new(1.5_f32, p.accent)
    } else if matches!(tone, ButtonTone::Secondary) {
        Stroke::new(1.0_f32, mix(p.line, p.muted, hover * 0.4))
    } else {
        Stroke::NONE
    };
    ui.painter().set(
        background,
        egui::epaint::RectShape::new(
            response.rect.shrink(down * 0.65),
            9,
            fill,
            stroke,
            egui::StrokeKind::Inside,
        ),
    );
    response
}

pub(super) fn enabled_command(
    ui: &mut egui::Ui,
    enabled: bool,
    text: impl Into<String>,
    tone: ButtonTone,
    size: Vec2,
    p: Palette,
) -> egui::Response {
    ui.add_enabled_ui(enabled, |ui| command(ui, text, tone, size, p))
        .inner
}

pub(super) fn toggle(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut bool,
    p: Palette,
) -> egui::Response {
    let response = ui.add_sized(
        [44.0, 30.0],
        egui::Button::new("")
            .fill(Color32::TRANSPARENT)
            .stroke(Stroke::NONE),
    );
    if response.clicked() {
        *value = !*value;
    }
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::Checkbox, ui.is_enabled(), *value, label)
    });
    let t = ui.ctx().animate_bool_with_time(
        response.id.with("toggle"),
        *value,
        ui.style().animation_time.min(0.14),
    );
    let track = egui::Rect::from_center_size(response.rect.center(), Vec2::new(36.0, 20.0));
    ui.painter()
        .rect_filled(track, 10, mix(p.line, p.accent, t));
    ui.painter().circle_filled(
        egui::pos2(track.left() + 10.0 + 16.0 * t, track.center().y),
        7.0,
        if *value { contrast(p.accent) } else { p.muted },
    );
    if response.has_focus() {
        ui.painter().rect_stroke(
            response.rect,
            7,
            Stroke::new(1.5_f32, p.accent),
            egui::StrokeKind::Inside,
        );
    }
    response.on_hover_text(label)
}

pub(super) fn modal(ctx: &egui::Context, id: &str) -> egui::Modal {
    egui::Modal::new(egui::Id::new(id)).frame(
        egui::Frame::popup(&ctx.style())
            .inner_margin(24)
            .corner_radius(14),
    )
}
pub(super) fn heading(text: impl Into<String>, size: f32) -> RichText {
    RichText::new(text).font(FontId::new(size, egui::FontFamily::Name("display".into())))
}
pub(super) fn label(ui: &mut egui::Ui, text: &str, p: Palette) {
    ui.label(RichText::new(text).size(11.0).color(p.muted));
}
pub(super) fn section(ui: &mut egui::Ui, text: &str, p: Palette) {
    ui.add_space(8.0);
    ui.label(heading(text, 17.0).color(p.text));
    ui.add_space(8.0);
}
pub(super) fn icon(ui: &egui::Ui, center: egui::Pos2, page: Page, color: Color32) {
    let painter = ui.painter();
    let s = Stroke::new(1.5_f32, color);
    let pos = |x, y| center + Vec2::new(x, y);
    match page {
        Page::Connection => {
            painter.circle_stroke(center, 7.0, s);
            painter.line_segment([pos(-4.0, 0.0), pos(4.0, 0.0)], s);
            painter.line_segment([pos(0.0, -4.0), pos(0.0, 4.0)], s);
        }
        Page::Subscriptions => {
            for y in [-5.0, 0.0, 5.0] {
                painter.line_segment([pos(-6.0, y), pos(6.0, y)], s);
            }
        }
        Page::Routes => {
            painter.circle_stroke(pos(-5.0, -5.0), 2.5, s);
            painter.circle_stroke(pos(5.0, 5.0), 2.5, s);
            painter.add(egui::Shape::line(
                vec![pos(-5.0, -2.5), pos(-5.0, 5.0), pos(2.5, 5.0)],
                s,
            ));
            painter.add(egui::Shape::line(
                vec![pos(-2.5, -5.0), pos(5.0, -5.0), pos(5.0, 2.5)],
                s,
            ));
        }
        Page::Settings => {
            for (y, x) in [(-5.0, -2.0), (0.0, 4.0), (5.0, -3.0)] {
                painter.line_segment([pos(-7.0, y), pos(7.0, y)], s);
                painter.circle_filled(pos(x, y), 2.3, color);
            }
        }
    }
}

impl App {
    pub(super) fn palette(&self) -> Palette {
        let raw = Color32::from_rgb(
            self.settings.accent[0],
            self.settings.accent[1],
            self.settings.accent[2],
        );
        let dark = self.settings.theme == Theme::Dark;
        let (base, paper) = match self.settings.colorway {
            eivro::storage::Colorway::Graphite => ([22, 24, 29], [247, 248, 250]),
            eivro::storage::Colorway::Sage => ([22, 29, 27], [244, 247, 241]),
            eivro::storage::Colorway::Sand => ([31, 28, 25], [249, 246, 239]),
            eivro::storage::Colorway::Ocean => ([20, 27, 34], [241, 246, 250]),
            eivro::storage::Colorway::Plum => ([30, 24, 32], [248, 244, 248]),
        };
        let rgb = |c: [u8; 3]| Color32::from_rgb(c[0], c[1], c[2]);
        let bg = if dark { rgb(base) } else { rgb(paper) };
        let accent = accent_on(raw, bg);
        Palette {
            bg,
            accent,
            card: if dark {
                mix(bg, Color32::WHITE, 0.025)
            } else {
                Color32::WHITE
            },
            raised: if dark {
                mix(bg, Color32::WHITE, 0.055)
            } else {
                mix(bg, Color32::BLACK, 0.045)
            },
            line: if dark {
                mix(bg, Color32::WHITE, 0.12)
            } else {
                mix(bg, Color32::BLACK, 0.13)
            },
            text: if dark {
                Color32::from_rgb(239, 240, 243)
            } else {
                Color32::from_rgb(32, 35, 42)
            },
            muted: if dark {
                Color32::from_rgb(163, 168, 180)
            } else {
                Color32::from_rgb(97, 103, 115)
            },
            soft: mix(bg, accent, 0.10),
            error: if dark {
                Color32::from_rgb(255, 174, 153)
            } else {
                Color32::from_rgb(169, 56, 32)
            },
        }
    }

    pub(super) fn commit(&mut self, next: Settings) -> bool {
        let result = self
            .path
            .as_ref()
            .ok_or_else(|| "Настройки недоступны для записи. Изменения не применены.".to_string())
            .and_then(|path| storage::save(path, &next));
        match result {
            Ok(()) => {
                self.settings = next;
                true
            }
            Err(e) => {
                self.error = Some(e);
                false
            }
        }
    }
    pub(super) fn scan_network(&mut self, ctx: &egui::Context) {
        #[cfg(feature = "qa")]
        if std::env::var("EIVRO_QA_FIXTURE").as_deref() == Ok("1") {
            return;
        }

        if self.network_result.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        self.network_result = Some(rx);
        std::thread::spawn(move || {
            let _ = tx.send(eivro::network::interfaces());
            ctx.request_repaint();
        });
    }
    pub(super) fn schedule_network_scan(&mut self, ctx: &egui::Context) {
        if self.settings.connections.is_empty() {
            return;
        }
        // Coalesce interface/DNS notifications from one VPN transition.
        if self.network_due.is_none() {
            self.network_due =
                Some(std::time::Instant::now() + std::time::Duration::from_millis(600));
            ctx.request_repaint_after(std::time::Duration::from_millis(600));
        }
    }
    pub(super) fn poll_network(&mut self, ctx: &egui::Context) {
        #[cfg(feature = "qa")]
        if std::env::var("EIVRO_QA_FIXTURE").as_deref() == Ok("1") {
            return;
        }

        #[cfg(target_os = "linux")]
        {
            if self.settings.connections.is_empty() {
                self.network_monitor = None;
                self.network_due = None;
            }
            if !self.settings.connections.is_empty()
                && self.network_monitor.is_none()
                && !self.network_monitor_failed
            {
                let wake = ctx.clone();
                match eivro::network::Monitor::start(Arc::new(move || wake.request_repaint())) {
                    Ok(monitor) => self.network_monitor = Some(monitor),
                    Err(_) => self.network_monitor_failed = true,
                }
                self.scan_network(ctx);
            }
            if self
                .network_monitor
                .as_ref()
                .is_some_and(|m| m.events.try_iter().count() > 0)
            {
                self.schedule_network_scan(ctx);
            }
        }
        #[cfg(target_os = "macos")]
        if !self.settings.connections.is_empty()
            && !self.network_initialized
            && self.network_result.is_none()
        {
            self.scan_network(ctx);
        }
        if let Some(due) = self.network_due {
            if std::time::Instant::now() >= due {
                self.network_due = None;
                self.scan_network(ctx);
            } else {
                ctx.request_repaint_after(due.saturating_duration_since(std::time::Instant::now()));
            }
        }
        if let Some(links) = self
            .network_result
            .as_ref()
            .and_then(|rx| rx.try_recv().ok())
        {
            let changed = self.settings.connections.iter().any(|connection| {
                let state = |links: &[eivro::network::Interface]| {
                    let server = connection.servers(links)?.first().copied()?;
                    let index = links.iter().find(|l| l.name == connection.interface)?.index;
                    Some((index, server))
                };
                self.settings.routing_profiles[self.settings.selected_routing]
                    .rules
                    .iter()
                    .any(|r| {
                        r.enabled && r.action == eivro::policy::Action::Connection(connection.id)
                    })
                    && state(&links) != state(&self.network_links)
            });
            self.network_links = links;
            self.network_result = None;
            if changed && self.network_initialized && self.want_connected {
                self.reconfigure();
            }
            self.network_initialized = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_palettes_keep_text_and_custom_accents_legible() {
        use eivro::storage::Colorway;
        let ratio = |a, b| {
            let a = luminance(a);
            let b = luminance(b);
            (a.max(b) + 0.05) / (a.min(b) + 0.05)
        };
        for theme in [Theme::Light, Theme::Dark] {
            for colorway in [
                Colorway::Graphite,
                Colorway::Sage,
                Colorway::Sand,
                Colorway::Ocean,
                Colorway::Plum,
            ] {
                for accent in [[0, 0, 0], [255, 255, 255], [194, 205, 223], [255, 0, 0]] {
                    let app = App::model(
                        Settings {
                            theme,
                            colorway,
                            accent,
                            ..Default::default()
                        },
                        None,
                        None,
                    );
                    let p = app.palette();
                    assert!(ratio(p.accent, p.bg) >= 4.5);
                    for surface in [p.bg, p.card, p.raised] {
                        assert!(ratio(p.text, surface) >= 4.5);
                        assert!(
                            ratio(p.muted, surface) >= 4.5,
                            "muted contrast {:?}: {}",
                            colorway,
                            ratio(p.muted, surface)
                        );
                    }
                    assert!(ratio(contrast(p.accent), p.accent) >= 4.5);
                }
            }
        }
    }
    #[test]
    fn command_handles_pointer_keyboard_and_settles_without_idle_frames() {
        let ctx = egui::Context::default();
        crate::emoji::install(&ctx);
        let p = App::model(Settings::default(), None, None).palette();
        let mut last = None;
        let mut time = 0.0;
        let mut frame = |events: Vec<egui::Event>| {
            time += 0.05;
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(600.0, 400.0),
                    )),
                    time: Some(time),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        last = Some(command(
                            ui,
                            "Добавить",
                            ButtonTone::Primary,
                            Vec2::new(200.0, 44.0),
                            p,
                        ));
                    });
                },
            );
            (output, last.clone().unwrap())
        };
        let (_, button) = frame(vec![]);
        let at = button.rect.center();
        frame(vec![
            egui::Event::PointerMoved(at),
            egui::Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::NONE,
            },
        ]);
        let (_, clicked) = frame(vec![egui::Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Primary,
            pressed: false,
            modifiers: egui::Modifiers::NONE,
        }]);
        assert!(clicked.clicked());
        ctx.memory_mut(|m| m.request_focus(button.id));
        let (_, clicked) = frame(vec![egui::Event::Key {
            key: egui::Key::Enter,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        }]);
        assert!(clicked.clicked());
        frame(vec![
            egui::Event::PointerGone,
            egui::Event::Key {
                key: egui::Key::Enter,
                physical_key: None,
                pressed: false,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            },
        ]);
        for _ in 0..12 {
            frame(vec![]);
        }
        let (out, _) = frame(vec![]);
        assert!(
            out.viewport_output[&egui::ViewportId::ROOT].repaint_delay
                > std::time::Duration::from_secs(60)
        );
    }
}
