use super::design::{ButtonTone, command};
use super::design::{heading, section};
use super::*;
impl App {
    pub(super) fn settings_page(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, p: Palette) {
        ui.label(heading("Настройки", 26.0));
        ui.add_space(18.0);
        let mut next = self.settings.clone();
        let mut changed = false;
        egui::ScrollArea::vertical()
            .id_salt("settings-content")
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    for (theme, title) in [(Theme::Dark, "Тёмная"), (Theme::Light, "Светлая")]
                    {
                        changed |= ui.selectable_value(&mut next.theme, theme, title).changed();
                    }
                });
                ui.add_space(18.0);
                ui.horizontal_wrapped(|ui| {
                    use eivro::storage::Colorway;
                    for (value, name, accent, base) in [
                        (Colorway::Graphite, "Графит", [194, 205, 223], [22, 24, 29]),
                        (Colorway::Sage, "Шалфей", [164, 202, 183], [22, 29, 27]),
                        (Colorway::Sand, "Песок", [228, 198, 158], [31, 28, 25]),
                        (Colorway::Ocean, "Океан", [145, 188, 242], [20, 27, 34]),
                        (Colorway::Plum, "Слива", [215, 172, 201], [30, 24, 32]),
                    ] {
                        let color = Color32::from_rgb(accent[0], accent[1], accent[2]);
                        let selected = next.colorway == value;
                        let response = ui.add_sized(
                            [110.0, 94.0],
                            egui::Button::new("")
                                .fill(p.card)
                                .stroke(Stroke::new(
                                    1.0_f32,
                                    if selected { p.accent } else { p.line },
                                ))
                                .corner_radius(10),
                        );
                        let preview = egui::Rect::from_min_size(
                            response.rect.min + Vec2::new(10.0, 10.0),
                            Vec2::new(90.0, 44.0),
                        );
                        ui.painter().rect_filled(
                            preview,
                            5,
                            Color32::from_rgb(base[0], base[1], base[2]),
                        );
                        ui.painter().rect_filled(
                            egui::Rect::from_min_size(
                                preview.min + Vec2::new(8.0, 8.0),
                                Vec2::new(18.0, 28.0),
                            ),
                            3,
                            color.gamma_multiply(0.25),
                        );
                        ui.painter().rect_filled(
                            egui::Rect::from_min_size(
                                preview.min + Vec2::new(34.0, 26.0),
                                Vec2::new(45.0, 10.0),
                            ),
                            3,
                            color,
                        );
                        ui.painter().line_segment(
                            [
                                preview.min + Vec2::new(34.0, 13.0),
                                preview.min + Vec2::new(65.0, 13.0),
                            ],
                            Stroke::new(2.0_f32, Color32::from_gray(210)),
                        );
                        ui.painter().text(
                            response.rect.min + Vec2::new(12.0, 72.0),
                            Align2::LEFT_CENTER,
                            name,
                            FontId::proportional(13.0),
                            if selected { p.accent } else { p.text },
                        );
                        response.widget_info(|| {
                            egui::WidgetInfo::labeled(egui::WidgetType::Button, true, name)
                        });
                        if response.has_focus() {
                            ui.painter().rect_stroke(
                                response.rect,
                                10,
                                Stroke::new(2.0_f32, p.accent),
                                egui::StrokeKind::Inside,
                            );
                        }
                        if response.clicked() {
                            next.colorway = value;
                            next.accent = accent;
                            changed = true;
                        }
                    }
                });
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    let response =
                        command(ui, "Свой акцент…", ButtonTone::Secondary, Vec2::ZERO, p);
                    let (r, _) = ui.allocate_exact_size(Vec2::splat(16.0), egui::Sense::hover());
                    ui.painter().circle_filled(
                        r.center(),
                        6.0,
                        Color32::from_rgb(next.accent[0], next.accent[1], next.accent[2]),
                    );
                    egui::Popup::menu(&response)
                        .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
                        .show(|ui| {
                            let mut color =
                                Color32::from_rgb(next.accent[0], next.accent[1], next.accent[2]);
                            if egui::color_picker::color_picker_color32(
                                ui,
                                &mut color,
                                egui::color_picker::Alpha::Opaque,
                            ) {
                                next.accent = [color.r(), color.g(), color.b()];
                                changed = true;
                            }
                        });
                });
                changed |= ui
                    .checkbox(&mut next.reduced_motion, "Уменьшить движение")
                    .changed();
                ui.add_space(24.0);
                section(ui, "Поведение", p);
                egui::Frame::new()
                    .fill(p.card)
                    .inner_margin(16)
                    .corner_radius(12)
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        changed |= switch_row(ui, "Закрывать в трей", &mut next.close_to_tray, p);
                        changed |=
                            switch_row(ui, "Подключаться при запуске", &mut next.autoconnect, p);
                        changed |=
                            switch_row(ui, "Восстанавливать соединение", &mut next.reconnect, p);
                        if switch_row(ui, "Запускать при входе в систему", &mut self.autostart, p)
                        {
                            let result = eivro::desktop::autostart_path().and_then(|path| {
                                let exe =
                                    std::env::current_exe().map_err(|_| "Нет пути приложения.")?;
                                eivro::desktop::set_autostart(&path, &exe, self.autostart)
                            });
                            if let Err(error) = result {
                                self.autostart = !self.autostart;
                                self.error = Some(error);
                            }
                        }
                        if !self.tray_online || !self.window_hiding {
                            ui.label(
                                RichText::new("Трей сейчас недоступен: закрытие не скроет окно.")
                                    .small()
                                    .color(p.muted),
                            );
                        }
                    });
                ui.add_space(18.0);
                egui::CollapsingHeader::new("Дополнительно")
                    .id_salt("advanced-settings")
                    .default_open(next.kill_switch)
                    .show(ui, |ui| {
                        changed |= switch_row(
                            ui,
                            "Kill switch · экспериментально",
                            &mut next.kill_switch,
                            p,
                        );
                        if next.kill_switch {
                            ui.label(
                                RichText::new(
                                    "Блокирует трафик при обрыве. Несовместим с \
внешними сетевыми выходами; отключение \
снимает защиту.",
                                )
                                .small()
                                .color(p.muted),
                            );
                        }
                        ui.add_space(12.0);
                        ui.add_enabled_ui(self.session.is_none(), |ui| {
                            ui.horizontal(|ui| {
                                ui.label("Локальный порт");
                                changed |= ui
                                    .add(egui::DragValue::new(&mut next.port).range(1024..=65535))
                                    .changed();
                            });
                        });
                        ui.label(
                            RichText::new(format!("HTTP / SOCKS5 · 127.0.0.1:{}", next.port))
                                .small()
                                .color(p.muted),
                        );
                        if self.session.is_some() {
                            ui.label(
                                RichText::new("Изменить порт можно после отключения.")
                                    .small()
                                    .color(p.muted),
                            );
                        }
                        if self.monitor_unavailable {
                            ui.label(
                                RichText::new(
                                    "NetworkManager недоступен; изменения сети не \
отслеживаются.",
                                )
                                .small()
                                .color(p.muted),
                            );
                        }
                        if self.network_monitor_failed {
                            ui.label(
                                RichText::new(
                                    "Обновляйте интерфейсы вручную: события \
сети недоступны.",
                                )
                                .small()
                                .color(p.muted),
                            );
                        }
                    });
                ui.add_space(18.0);
                ui.separator();
                section(ui, "Eivro", p);
                ui.label(format!("Версия {}", env!("CARGO_PKG_VERSION")));
                if !self.helper_ready {
                    ui.label(
                        RichText::new("Для TUN установите RPM/DEB этой версии Eivro.")
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
                ui.add_space(12.0);
                if command(ui, "Завершить Eivro", ButtonTone::Secondary, Vec2::ZERO, p).clicked()
                {
                    self.quitting = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
        if changed {
            let reconnect = next.kill_switch != self.settings.kill_switch;
            if self.commit(next) {
                if !self.settings.reconnect && self.recovery.recovering {
                    self.recovery.due = None;
                    self.recovery.exhausted = true;
                }
                if reconnect {
                    self.reconfigure();
                }
            }
        }
    }
}

fn switch_row(ui: &mut egui::Ui, label: &str, value: &mut bool, p: Palette) -> bool {
    let before = *value;
    let label_width = (ui.available_width() - 56.0).max(80.0);
    ui.horizontal(|ui| {
        ui.allocate_ui_with_layout(
            Vec2::new(label_width, 36.0),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.set_min_width(label_width);
                ui.add(egui::Label::new(label).wrap());
            },
        );
        super::design::toggle(ui, label, value, p);
    });
    before != *value
}
