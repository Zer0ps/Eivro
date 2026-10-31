use super::design::{ButtonTone, command, heading};
use super::*;

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
                    let state = if self.stopping {
                        "Отключение…"
                    } else if self.reconnect_pending {
                        "Переключение…"
                    } else if self.running {
                        "Подключено"
                    } else if self.want_connected {
                        self.phase
                    } else {
                        "Не подключено"
                    };
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
                            self.reconfigure();
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
                    let enabled = self.settings.selected_profile().is_some() || self.want_connected;
                    let action = ui
                        .add_enabled_ui(enabled, |ui| {
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

    pub(super) fn catalog(&mut self, ctx: &egui::Context, p: Palette) {
        let progress = ctx.animate_bool_with_time_and_easing(
            egui::Id::new("catalog-reveal"),
            self.catalog_open,
            if self.settings.reduced_motion {
                0.0
            } else {
                0.22
            },
            egui::emath::easing::cubic_out,
        );
        if progress <= 0.0 {
            return;
        }
        let width = (ctx.content_rect().width() * 0.46).clamp(330.0, 430.0);
        let height = ctx.content_rect().height() - 80.0;
        let area = egui::Modal::default_area(egui::Id::new("server-catalog")).anchor(
            Align2::RIGHT_CENTER,
            Vec2::new(-20.0 + (1.0 - progress) * (width + 70.0), 0.0),
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
                    .min_scrolled_height(100.0)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let mut visible = 0;
                        for (si, sub) in self.settings.subscriptions.iter().enumerate() {
                            let matches: Vec<_> = sub
                                .profiles
                                .iter()
                                .enumerate()
                                .filter(|(_, p)| {
                                    filter.is_empty()
                                        || p.name.to_lowercase().contains(&filter)
                                        || sub.name.to_lowercase().contains(&filter)
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
                                    ui.horizontal(|ui| {
                                        let label = crate::emoji::text(&profile.name);
                                        let width = (ui.available_width() - 46.0).max(120.0);
                                        if command(
                                            ui,
                                            label,
                                            if selected {
                                                ButtonTone::Selected
                                            } else {
                                                ButtonTone::Quiet
                                            },
                                            Vec2::new(width, 44.0),
                                            p,
                                        )
                                        .on_hover_text(&profile.name)
                                        .clicked()
                                        {
                                            choice = Some((si, pi));
                                        }
                                        if selected {
                                            let menu = command(
                                                ui,
                                                "···",
                                                ButtonTone::Quiet,
                                                Vec2::new(32.0, 36.0),
                                                p,
                                            )
                                            .on_hover_text("Действия с выбранным сервером");
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
                                    });
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
            let mut next = self.settings.clone();
            next.selected_subscription = si;
            next.current_mut().unwrap().selected = pi;
            if self.commit(next) {
                self.reconfigure();
                close = true;
            }
        }
        if close || response.should_close() {
            self.catalog_open = false;
        }
    }
}
