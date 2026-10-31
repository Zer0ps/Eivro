use super::design::{ButtonTone, command, heading, icon, mix};
use super::*;

impl App {
    fn navigate(&mut self, page: Page, ctx: &egui::Context) {
        self.page = page;
        self.navigation_overlay = false;
        if page == Page::Routes {
            if self.editor.is_none() {
                self.editor = Some(Editor::new(&self.settings));
            }
            self.scan_network(ctx);
        }
    }
    fn navigation_items(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, p: Palette) {
        for (page, title) in [
            (Page::Connection, "Соединение"),
            (Page::Subscriptions, "Подписки"),
            (Page::Routes, "Маршруты"),
            (Page::Settings, "Настройки"),
        ] {
            let selected = page == self.page;
            let fill = ui.painter().add(egui::Shape::Noop);
            let response = ui.add_sized(
                [ui.available_width(), 44.0],
                egui::Button::new("")
                    .fill(Color32::TRANSPARENT)
                    .stroke(Stroke::NONE),
            );
            let hover = ctx.animate_bool_with_time(
                response.id.with("nav-hover"),
                response.hovered(),
                ui.style().animation_time.min(0.14),
            );
            ui.painter().set(
                fill,
                egui::epaint::RectShape::filled(
                    response.rect,
                    9,
                    if selected {
                        p.soft
                    } else {
                        mix(p.bg, p.raised, hover)
                    },
                ),
            );
            let color = if selected { p.accent } else { p.muted };
            icon(
                ui,
                response.rect.left_center() + Vec2::new(18.0, 0.0),
                page,
                color,
            );
            ui.painter().text(
                response.rect.left_center() + Vec2::new(40.0, 0.0),
                Align2::LEFT_CENTER,
                title,
                FontId::proportional(14.0),
                color,
            );
            if selected {
                ui.painter().rect_filled(
                    egui::Rect::from_center_size(
                        response.rect.left_center() + Vec2::new(1.5, 0.0),
                        Vec2::new(3.0, 17.0),
                    ),
                    2,
                    p.accent,
                );
            }
            if response.has_focus() {
                ui.painter().rect_stroke(
                    response.rect,
                    9,
                    Stroke::new(1.5_f32, p.accent),
                    egui::StrokeKind::Inside,
                );
            }
            response
                .widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, title));
            if response.clicked() {
                self.navigate(page, ctx);
            }
            ui.add_space(3.0);
        }
    }
    pub(super) fn shell(&mut self, ctx: &egui::Context, p: Palette) {
        let narrow = ctx.content_rect().width() < 780.0;
        if (self.navigation_overlay || ctx.memory(|m| m.top_modal_layer().is_none()))
            && ctx.input_mut(|i| {
                i.consume_key(
                    if cfg!(target_os = "macos") {
                        egui::Modifiers::MAC_CMD
                    } else {
                        egui::Modifiers::CTRL
                    },
                    egui::Key::B,
                )
            })
        {
            if narrow {
                self.navigation_overlay = !self.navigation_overlay;
            } else {
                self.sidebar_open = !self.sidebar_open;
            }
        }
        egui::TopBottomPanel::top("app-toolbar")
            .exact_height(64.0)
            .frame(
                egui::Frame::new()
                    .fill(p.bg)
                    .inner_margin(egui::Margin::symmetric(16, 10)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let response = ui.add_sized(
                        [40.0, 40.0],
                        egui::Button::new("")
                            .fill(p.bg)
                            .stroke(Stroke::NONE)
                            .corner_radius(8),
                    );
                    let c = response.rect.center();
                    self.navigation_button = Some(response.id);
                    for y in [-5.0, 0.0, 5.0] {
                        ui.painter().line_segment(
                            [c + Vec2::new(-7.0, y), c + Vec2::new(7.0, y)],
                            Stroke::new(1.5_f32, p.muted),
                        );
                    }
                    if response.has_focus() || response.hovered() {
                        ui.painter().rect_stroke(
                            response.rect,
                            8,
                            Stroke::new(1.0_f32, p.accent),
                            egui::StrokeKind::Inside,
                        );
                    }
                    let open = if narrow {
                        self.navigation_overlay
                    } else {
                        self.sidebar_open
                    };
                    let label = if open {
                        "Скрыть меню"
                    } else {
                        "Показать меню"
                    };
                    response.widget_info(|| {
                        egui::WidgetInfo::labeled(egui::WidgetType::Button, true, label)
                    });
                    if response
                        .on_hover_text(format!(
                            "{label} · {}B",
                            if cfg!(target_os = "macos") {
                                "⌘"
                            } else {
                                "Ctrl+"
                            }
                        ))
                        .clicked()
                    {
                        if narrow {
                            self.navigation_overlay = !open;
                        } else {
                            self.sidebar_open = !open;
                        }
                    }
                    ui.add_space(4.0);
                    let (r, _) = ui.allocate_exact_size(Vec2::splat(24.0), egui::Sense::hover());
                    let left = r.center() + Vec2::new(-7.0, 0.0);
                    ui.painter().line_segment(
                        [left + Vec2::new(0.0, -8.0), left + Vec2::new(0.0, 8.0)],
                        Stroke::new(2.5_f32, p.accent),
                    );
                    for (y, length) in [(-8.0, 15.0), (0.0, 11.0), (8.0, 15.0)] {
                        ui.painter().line_segment(
                            [left + Vec2::new(0.0, y), left + Vec2::new(length, y)],
                            Stroke::new(2.5_f32, p.accent),
                        );
                    }
                    ui.label(heading("eivro", 21.0));
                });
            });
        let expanded = ctx.animate_bool_with_time_and_easing(
            egui::Id::new("navigation-reveal"),
            self.sidebar_open && !narrow,
            if self.settings.reduced_motion {
                0.0
            } else {
                0.18
            },
            egui::emath::easing::cubic_out,
        );
        if expanded > 0.0 {
            egui::SidePanel::left("navigation")
                .resizable(false)
                .exact_width(190.0 * expanded)
                .frame(egui::Frame::new().fill(p.bg))
                .show(ctx, |ui| {
                    let clip = ui.max_rect();
                    let min = clip.min + Vec2::new(12.0 - (1.0 - expanded) * 24.0, 24.0);
                    let mut content = ui.new_child(
                        egui::UiBuilder::new()
                            .max_rect(egui::Rect::from_min_size(
                                min,
                                Vec2::new(166.0, clip.height() - 24.0),
                            ))
                            .layout(egui::Layout::top_down(egui::Align::Min)),
                    );
                    content.set_clip_rect(clip);
                    content.set_opacity(expanded);
                    if expanded < 0.99 {
                        content.disable();
                    }
                    self.navigation_items(&mut content, ctx, p);
                });
        }
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(p.bg)
                    .inner_margin(egui::Margin::symmetric(if narrow { 18 } else { 28 }, 22)),
            )
            .show(ctx, |ui| {
                let limit = match self.page {
                    Page::Connection => f32::INFINITY,
                    Page::Routes => 1020.0,
                    Page::Subscriptions => 900.0,
                    Page::Settings => 760.0,
                };
                let width = ui.available_width().min(limit);
                let left = ((ui.available_width() - width) * 0.5).max(0.0);
                let rect = egui::Rect::from_min_size(
                    ui.max_rect().min + Vec2::new(left, 0.0),
                    Vec2::new(width, ui.available_height()),
                );
                let mut content = ui.new_child(
                    egui::UiBuilder::new()
                        .max_rect(rect)
                        .layout(egui::Layout::top_down(egui::Align::Min)),
                );
                if let Some(error) = self.error.clone().filter(|_| !self.import_open) {
                    egui::Frame::new()
                        .fill(mix(p.bg, p.error, 0.09))
                        .corner_radius(9)
                        .inner_margin(12)
                        .show(&mut content, |ui| {
                            ui.horizontal_wrapped(|ui| {
                                ui.colored_label(p.error, error);
                                if command(ui, "Закрыть", ButtonTone::Quiet, Vec2::ZERO, p)
                                    .clicked()
                                {
                                    self.error = None;
                                }
                            });
                        });
                    content.add_space(12.0);
                }
                match self.page {
                    Page::Connection => self.overview(&mut content, ctx, p),
                    Page::Subscriptions => self.subscriptions_page(&mut content, ctx, p),
                    Page::Routes => self.routes_page(&mut content, ctx, p),
                    Page::Settings => self.settings_page(&mut content, ctx, p),
                }
            });
        if narrow && self.navigation_overlay {
            let response = egui::Modal::new(egui::Id::new("navigation-overlay"))
                .area(
                    egui::Modal::default_area(egui::Id::new("navigation-overlay"))
                        .anchor(Align2::LEFT_TOP, Vec2::new(12.0, 64.0)),
                )
                .frame(
                    egui::Frame::popup(&ctx.style())
                        .inner_margin(12)
                        .corner_radius(12),
                )
                .show(ctx, |ui| {
                    ui.set_width(190.0);
                    self.navigation_items(ui, ctx, p);
                    if command(
                        ui,
                        "Скрыть меню",
                        ButtonTone::Quiet,
                        Vec2::new(190.0, 36.0),
                        p,
                    )
                    .clicked()
                    {
                        self.navigation_overlay = false;
                    }
                });
            if response.should_close() {
                self.navigation_overlay = false;
            }
        }
    }
}
