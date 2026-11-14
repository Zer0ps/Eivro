use super::design::{ButtonTone, command, heading};
use super::*;

// Scrolled-out rows keep a stable keyboard target and their share of the
// scroll range. Text layout, glyphs and button animation are only needed on screen.
fn server_button(
    ui: &mut egui::Ui,
    id: egui::Id,
    rect: egui::Rect,
    name: &str,
    selected: bool,
    p: Palette,
) -> egui::Response {
    let response = ui.interact(rect, id, egui::Sense::click());
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::WidgetType::SelectableLabel,
            ui.is_enabled(),
            selected,
            name,
        )
    });
    if response.gained_focus() {
        response.scroll_to_me(None);
    }
    if !ui.is_rect_visible(rect) {
        return response;
    }
    let base = if selected { p.soft } else { p.card };
    let hover = ui.ctx().animate_bool_with_time(
        id.with("hover"),
        response.hovered() || response.has_focus(),
        ui.style().animation_time.min(0.14),
    );
    let pressed = response.is_pointer_button_down_on()
        || (response.has_focus()
            && ui.input(|i| i.key_down(egui::Key::Space) || i.key_down(egui::Key::Enter)));
    let down = ui.ctx().animate_bool_with_time(
        id.with("press"),
        pressed,
        ui.style().animation_time.min(0.08),
    );
    let fill = design::mix(design::mix(base, p.text, 0.065 * hover), p.bg, 0.16 * down);
    ui.painter().rect_filled(rect.shrink(down * 0.65), 9, fill);
    if response.has_focus() {
        ui.painter().rect_stroke(
            rect,
            9,
            Stroke::new(1.5_f32, p.accent),
            egui::StrokeKind::Inside,
        );
    }
    let color = if selected { p.accent } else { p.text };
    let mut job = egui::text::LayoutJob::simple(
        crate::emoji::text(name),
        FontId::proportional(14.0),
        color,
        (rect.width() - if selected { 42.0 } else { 24.0 }).max(1.0),
    );
    job.wrap.max_rows = 1;
    job.wrap.break_anywhere = true;
    let galley = ui.painter().layout_job(job);
    ui.painter().galley(
        rect.left_center() + Vec2::new(12.0, -galley.size().y * 0.5),
        galley,
        color,
    );
    if selected {
        ui.painter().text(
            rect.right_center() - Vec2::new(10.0, 0.0),
            Align2::RIGHT_CENTER,
            "✓",
            FontId::proportional(14.0),
            color,
        );
    }
    response.on_hover_text(name)
}

impl App {
    pub(super) fn overview(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, p: Palette) {
        if (self.catalog_open || ctx.memory(|m| m.top_modal_layer().is_none()))
            && ctx.input_mut(|i| {
                i.consume_key(egui::Modifiers::NONE, egui::Key::F9)
                    || (cfg!(target_os = "macos")
                        && i.consume_key(egui::Modifiers::MAC_CMD, egui::Key::K))
            })
        {
            self.catalog_open = !self.catalog_open;
        }
        let backdrop = ui.painter().add(egui::Shape::Noop);
        let bounds = ui.max_rect().intersect(ui.clip_rect());
        let height = ui.available_height();
        let origins = if height < 620.0 {
            egui::ScrollArea::vertical()
                .id_salt("connection-small-window")
                .auto_shrink([false, false])
                .show(ui, |ui| self.connection_controls(ui, ctx, p, height))
                .inner
        } else {
            self.connection_controls(ui, ctx, p, height)
        };
        // A click can change the state during this frame. Draw underneath every
        // control, with no hit target or layout space of the effect's own.
        self.sync_connection_effect(ctx);
        ui.painter().set(
            backdrop,
            self.connection_effect.paint(ctx, bounds, origins, p.accent),
        );
    }

    fn connection_controls(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        p: Palette,
        height: f32,
    ) -> effects::Origins {
        let width = ui.available_width().min(490.0);
        let offset = (ui.available_width() - width) * 0.5;
        ui.add_space((height * 0.12).clamp(20.0, 84.0));
        ui.horizontal_top(|ui| {
            ui.add_space(offset);
            ui.allocate_ui_with_layout(
                Vec2::new(width, 0.0),
                egui::Layout::top_down(egui::Align::Center),
                |ui| {
                    let (state, action_enabled) = self.connection_controls_state();
                    let color = if self.running { p.accent } else { p.muted };
                    let (r, _) = ui.allocate_exact_size(Vec2::splat(72.0), egui::Sense::hover());
                    ui.painter()
                        .circle_stroke(r.center(), 34.0, Stroke::new(1.0_f32, p.line));
                    let points: Vec<_> = (0..=48)
                        .map(|i| {
                            let angle = std::f32::consts::PI * (-0.25 + i as f32 / 48.0 * 1.50);
                            r.center() + Vec2::angled(angle) * 19.0
                        })
                        .collect();
                    ui.painter()
                        .add(egui::Shape::line(points, Stroke::new(2.0_f32, color)));
                    ui.painter().line_segment(
                        [
                            r.center() + Vec2::new(0.0, -23.0),
                            r.center() + Vec2::new(0.0, -2.0),
                        ],
                        Stroke::new(2.0_f32, color),
                    );
                    ui.add_space(22.0);
                    ui.label(heading(state, 36.0).color(p.text));
                    ui.add_space(28.0);
                    let selected = self
                        .settings
                        .selected_profile()
                        .map(|s| crate::emoji::text(&s.name))
                        .unwrap_or_else(|| "Выбрать сервер".into());
                    let response = ui.add_sized(
                        [width, 74.0],
                        egui::Button::new("")
                            .fill(p.card)
                            .stroke(Stroke::new(1.0_f32, p.line))
                            .corner_radius(12),
                    );
                    let text_rect = egui::Rect::from_min_max(
                        response.rect.left_top() + Vec2::new(18.0, 8.0),
                        response.rect.right_bottom() - Vec2::new(46.0, 8.0),
                    );
                    // Truncate exceptionally long names to one visual line without losing the full tooltip.
                    let galley = ui.painter().layout_job({
                        let mut job = egui::text::LayoutJob::simple(
                            selected.clone(),
                            FontId::new(20.0, egui::FontFamily::Name("display".into())),
                            p.text,
                            text_rect.width(),
                        );
                        job.wrap.max_rows = 1;
                        job.wrap.break_anywhere = true;
                        job
                    });
                    ui.painter().galley(
                        egui::pos2(
                            text_rect.left(),
                            response.rect.center().y - galley.size().y * 0.5,
                        ),
                        galley,
                        p.text,
                    );
                    let c = egui::pos2(response.rect.right() - 25.0, response.rect.center().y);
                    ui.painter().add(egui::Shape::line(
                        vec![
                            c + Vec2::new(-4.0, -2.0),
                            c + Vec2::new(0.0, 2.0),
                            c + Vec2::new(4.0, -2.0),
                        ],
                        Stroke::new(1.5_f32, p.muted),
                    ));
                    response.widget_info(|| {
                        egui::WidgetInfo::labeled(
                            egui::WidgetType::Button,
                            true,
                            format!("Выбрать сервер: {selected}"),
                        )
                    });
                    if response.has_focus() || response.hovered() {
                        ui.painter().rect_stroke(
                            response.rect,
                            12,
                            Stroke::new(1.0_f32, p.accent),
                            egui::StrokeKind::Inside,
                        );
                    }
                    if response
                        .on_hover_text(format!(
                            "{selected}\nОткрыть каталог · {}",
                            if cfg!(target_os = "macos") {
                                "⌘K"
                            } else {
                                "F9"
                            }
                        ))
                        .clicked()
                    {
                        self.catalog_open = true;
                    }
                    ui.add_space(18.0);
                    let mut mode = self.settings.mode;
                    egui::Frame::new()
                        .fill(p.raised)
                        .corner_radius(9)
                        .inner_margin(4)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 4.0;
                                for (value, label, help) in [
                                    (Mode::Tun, "TUN", "Вся система, с учётом правил"),
                                    (Mode::Proxy, "Прокси", eivro::platform::PROXY_HINT),
                                    (Mode::Local, "Локально", "HTTP / SOCKS5 для приложения"),
                                ] {
                                    if command(
                                        ui,
                                        label,
                                        ButtonTone::Segment(mode == value),
                                        Vec2::new((width - 16.0) / 3.0, 36.0),
                                        p,
                                    )
                                    .on_hover_text(help)
                                    .clicked()
                                    {
                                        mode = value;
                                    }
                                }
                            });
                        });
                    if mode != self.settings.mode {
                        let mut next = self.settings.clone();
                        next.mode = mode;
                        if self.commit(next) {
                            self.apply_saved_connection();
                        }
                    }
                    ui.add_space(24.0);
                    let action = if self.want_connected {
                        if self.running {
                            "Отключить"
                        } else {
                            "Отменить"
                        }
                    } else {
                        "Подключиться"
                    };
                    let action = ui
                        .add_enabled_ui(action_enabled, |ui| {
                            command(ui, action, ButtonTone::Primary, Vec2::new(width, 48.0), p)
                        })
                        .inner;
                    if action.clicked() {
                        self.connect(ctx);
                    }
                    ui.add_space(14.0);
                    let route =
                        &self.settings.routing_profiles[self.settings.selected_routing].name;
                    let response = ui
                        .add(
                            egui::Button::new(
                                RichText::new(format!("{route}  →"))
                                    .size(13.0)
                                    .color(p.muted),
                            )
                            .fill(p.bg)
                            .stroke(Stroke::NONE)
                            .min_size(Vec2::new(180.0, 32.0)),
                        )
                        .on_hover_text("Открыть правила маршрутизации");
                    if response.clicked() {
                        self.page = Page::Routes;
                        if self.editor.is_none() {
                            self.editor = Some(Editor::new(&self.settings));
                        }
                        self.scan_network(ctx);
                    }
                    if self.settings.mode == Mode::Local {
                        ui.label(
                            RichText::new(format!("127.0.0.1:{}", self.settings.port))
                                .monospace()
                                .small()
                                .color(p.muted),
                        );
                    }
                    if self.settings.mode == Mode::Tun && !self.helper_ready {
                        ui.label(
                            RichText::new(eivro::platform::HELPER_HINT)
                                .small()
                                .color(p.muted),
                        );
                    }
                    effects::Origins {
                        power: r.center(),
                        button: action.rect.center(),
                    }
                },
            )
            .inner
        })
        .inner
    }

    fn connection_controls_state(&self) -> (&str, bool) {
        if self.quitting {
            return ("Завершение…", false);
        }
        if self.reconnect_pending {
            return ("Переключение…", self.want_connected);
        }
        if self.stopping {
            return ("Отключение…", false);
        }
        let label = if self.running {
            "Подключено"
        } else if self.want_connected {
            self.phase
        } else {
            "Не подключено"
        };
        (
            label,
            self.want_connected || self.settings.selected_profile().is_some(),
        )
    }

    pub(super) fn catalog(&mut self, ctx: &egui::Context, p: Palette) {
        // Apply one symmetric curve after interpolation so reversing mid-slide
        // leaves the sheet at the same position.
        let progress = egui::emath::easing::quadratic_in_out(ctx.animate_bool_with_time(
            egui::Id::new("catalog-reveal"),
            self.catalog_open,
            if self.settings.reduced_motion {
                0.0
            } else {
                0.22
            },
        ));
        if progress <= 0.0 {
            return;
        }
        let screen = ctx.content_rect().size();
        let inset = if screen.x < 420.0 { 8.0 } else { 20.0 };
        let width = (screen.x * 0.46)
            .clamp(330.0, 430.0)
            .min((screen.x - 2.0 * inset).max(1.0));
        let height = (screen.y - if screen.y < 480.0 { 16.0 } else { 80.0 }).max(1.0);
        // The default Area constraint pins an off-screen panel back to the
        // viewport edge for almost the entire closing animation.
        let area = egui::Modal::default_area(egui::Id::new("server-catalog"))
            .constrain(false)
            .fade_in(false)
            .anchor(
                Align2::RIGHT_CENTER,
                Vec2::new(-inset + (1.0 - progress) * (width + inset + 10.0), 0.0),
            );
        let mut choice = None;
        let mut close = false;
        let response = egui::Modal::new(egui::Id::new("server-catalog"))
            .area(area)
            .backdrop_color(Color32::from_black_alpha((85.0 * progress) as u8))
            .frame(
                egui::Frame::popup(&ctx.style())
                    .fill(p.card)
                    .inner_margin(24)
                    .corner_radius(16),
            )
            .show(ctx, |ui| {
                if !self.catalog_open {
                    ui.visuals_mut().disabled_alpha = 1.0;
                    ui.disable();
                }
                ui.set_width(width - 48.0);
                ui.set_height(height - 48.0);
                ui.horizontal(|ui| {
                    ui.label(heading("Серверы", 24.0));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if command(ui, "Закрыть", ButtonTone::Quiet, Vec2::ZERO, p).clicked()
                        {
                            close = true;
                        }
                    });
                });
                ui.add_space(12.0);
                ui.add(
                    egui::TextEdit::singleline(&mut self.server_filter)
                        .hint_text("Поиск")
                        .desired_width(f32::INFINITY)
                        .margin(Vec2::new(12.0, 10.0))
                        .char_limit(100),
                );
                ui.add_space(12.0);
                let filter = self.server_filter.to_lowercase();
                egui::ScrollArea::vertical()
                    .id_salt("catalog-scroll")
                    .max_height(height - 210.0)
                    .min_scrolled_height(32.0)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let mut visible = 0;
                        for (si, sub) in self.settings.subscriptions.iter().enumerate() {
                            let group_matches =
                                filter.is_empty() || sub.name.to_lowercase().contains(&filter);
                            let matches: Vec<_> = sub
                                .profiles
                                .iter()
                                .enumerate()
                                .filter(|(_, p)| {
                                    group_matches || p.name.to_lowercase().contains(&filter)
                                })
                                .collect();
                            if matches.is_empty() {
                                continue;
                            }
                            visible += matches.len();
                            egui::CollapsingHeader::new(
                                RichText::new(format!(
                                    "{}   ·   {}",
                                    crate::emoji::text(&sub.name),
                                    matches.len()
                                ))
                                .color(p.muted),
                            )
                            .id_salt(("catalog-sub", sub.id))
                            .default_open(si == self.settings.selected_subscription)
                            .open(
                                (!filter.is_empty() || self.catalog_focus == Some(sub.id))
                                    .then_some(true),
                            )
                            .show(ui, |ui| {
                                for (pi, profile) in matches {
                                    let selected = si == self.settings.selected_subscription
                                        && pi == sub.selected;
                                    let (_, row) =
                                        ui.allocate_space(Vec2::new(ui.available_width(), 44.0));
                                    let row_id = ui.make_persistent_id(("server", sub.id, pi));
                                    let button = egui::Rect::from_min_size(
                                        row.min,
                                        Vec2::new((row.width() - 46.0).max(1.0), row.height()),
                                    );
                                    if server_button(ui, row_id, button, &profile.name, selected, p)
                                        .clicked()
                                    {
                                        choice = Some((si, pi));
                                    }
                                    if selected && ui.is_rect_visible(row) {
                                        let menu_rect = egui::Rect::from_center_size(
                                            egui::pos2(row.right() - 16.0, row.center().y),
                                            Vec2::new(32.0, 36.0),
                                        );
                                        let menu = ui
                                            .interact(
                                                menu_rect,
                                                row_id.with("menu"),
                                                egui::Sense::click(),
                                            )
                                            .on_hover_text("Действия с выбранным сервером");
                                        menu.widget_info(|| {
                                            egui::WidgetInfo::labeled(
                                                egui::WidgetType::Button,
                                                ui.is_enabled(),
                                                "Действия с выбранным сервером",
                                            )
                                        });
                                        if menu.has_focus() || menu.hovered() {
                                            ui.painter().rect_filled(menu_rect, 8, p.raised);
                                        }
                                        if menu.has_focus() {
                                            ui.painter().rect_stroke(
                                                menu_rect,
                                                8,
                                                Stroke::new(1.5_f32, p.accent),
                                                egui::StrokeKind::Inside,
                                            );
                                        }
                                        for x in [-5.0, 0.0, 5.0] {
                                            ui.painter().circle_filled(
                                                menu_rect.center() + Vec2::new(x, 0.0),
                                                1.3,
                                                p.muted,
                                            );
                                        }
                                        egui::Popup::menu(&menu).show(|ui| {
                                            if command(
                                                ui,
                                                "Удалить сервер…",
                                                ButtonTone::Danger,
                                                Vec2::ZERO,
                                                p,
                                            )
                                            .clicked()
                                            {
                                                self.delete_server = true;
                                                close = true;
                                                ui.close();
                                            }
                                        });
                                    }
                                }
                            });
                            ui.add_space(8.0);
                        }
                        if visible == 0 {
                            ui.add_space(24.0);
                            ui.label(heading(
                                if self.settings.subscriptions.is_empty() {
                                    "Добавьте подключение"
                                } else {
                                    "Ничего не найдено"
                                },
                                18.0,
                            ));
                        }
                    });
                ui.add_space(12.0);
                if command(
                    ui,
                    "+ Добавить подключение",
                    ButtonTone::Primary,
                    Vec2::new(ui.available_width(), 44.0),
                    p,
                )
                .clicked()
                {
                    self.import_open = true;
                    close = true;
                }
            });
        self.catalog_focus = None;
        if let Some((si, pi)) = choice {
            close = self.select_catalog_profile(si, pi);
        }
        if close || response.should_close() {
            self.catalog_open = false;
        }
    }

    fn select_catalog_profile(&mut self, si: usize, pi: usize) -> bool {
        let Some(sub) = self.settings.subscriptions.get(si) else {
            return false;
        };
        if pi >= sub.profiles.len() {
            return false;
        }
        if si == self.settings.selected_subscription && pi == sub.selected {
            return true;
        }
        let mut next = self.settings.clone();
        next.selected_subscription = si;
        next.subscriptions[si].selected = pi;
        if !self.commit(next) {
            return false;
        }
        self.apply_saved_connection();
        true
    }
}

#[cfg(test)]
mod drawer_tests {
    use super::*;

    fn filled_app() -> App {
        let mut app = App::model(Settings::default(), None, None);
        let doc = catalog::Document {
            name: "Test".into(),
            source: None,
            metadata: Default::default(),
            unavailable: vec![],
            profiles: (0..256)
                .map(|i| eivro::import::Profile {
                    name: format!("🌏 Server {i}"),
                    uri: "ss://synthetic".into(),
                })
                .collect(),
        };
        app.settings.subscriptions.push(doc.into_subscription(1));
        app
    }

    #[test]
    fn catalog_drawer_moves_continuously_past_the_viewport_edge() {
        let ctx = egui::Context::default();
        crate::emoji::install(&ctx);
        let mut app = filled_app();
        let mut left = Vec::new();
        let mut costs = Vec::new();
        for frame in 0..90 {
            app.catalog_open = (3..62).contains(&frame);
            let start = std::time::Instant::now();
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(960.0, 760.0),
                    )),
                    time: Some(frame as f64 / 60.0),
                    ..Default::default()
                },
                |ctx| app.catalog(ctx, app.palette()),
            );
            if (30..62).contains(&frame) {
                costs.push(start.elapsed().as_micros());
            }
            if (61..75).contains(&frame) {
                let rect = egui::AreaState::load(&ctx, egui::Id::new("server-catalog"))
                    .unwrap()
                    .rect();
                left.push(rect.left());
            }
        }
        assert!(left.windows(2).all(|pair| pair[0] <= pair[1]));
        costs.sort_unstable();
        eprintln!(
            "256 profiles: median {} µs; closing x coordinates {left:?}",
            costs[costs.len() / 2]
        );
        assert!(
            left[10] - left[0] > 250.0,
            "drawer sticks to the window edge: {left:?}"
        );
    }

    #[test]
    fn reselecting_current_server_closes_catalog_without_restarting() {
        let mut app = filled_app();
        app.want_connected = true;
        app.running = true;
        assert!(app.select_catalog_profile(0, 0));
        assert!(app.running && app.want_connected);
        assert!(!app.stopping && app.recovery.due.is_none() && app.error.is_none());
    }

    #[test]
    fn switching_connection_can_be_cancelled_but_explicit_stop_finishes_first() {
        let mut app = filled_app();
        app.want_connected = true;
        app.stopping = true;
        app.reconnect_pending = true;
        assert_eq!(app.connection_controls_state(), ("Переключение…", true));
        app.want_connected = false;
        app.reconnect_pending = false;
        assert_eq!(app.connection_controls_state(), ("Отключение…", false));
    }
}
