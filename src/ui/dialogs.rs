use super::design::{ButtonTone, command, enabled_command};
use super::design::{heading, modal};
use super::*;

impl App {
    pub(super) fn dialogs(&mut self, ctx: &egui::Context, p: Palette) {
        if self.import_open {
            let busy = self.import_result.is_some();
            let mut close = false;
            let response = modal(ctx, "import-server").show(ctx, |ui| {
                ui.set_width((ctx.content_rect().width() - 120.0).min(480.0));
                ui.label(heading("Добавить подключение", 23.0));
                ui.label(RichText::new("Подписка, ключ сервера или файл").color(p.muted));
                ui.add_space(14.0);
                egui::ScrollArea::vertical()
                    .id_salt("import-form")
                    .max_height((ctx.content_rect().height() - 220.0).max(65.0))
                    .show(ui, |ui| {
                        ui.add_enabled(
                            !busy,
                            egui::TextEdit::multiline(&mut self.import_text)
                                .id(egui::Id::new("import-input"))
                                .password(!self.import_reveal)
                                .hint_text("https://…  или  vless://…")
                                .desired_rows(5)
                                .desired_width(f32::INFINITY)
                                .margin(Vec2::new(12.0, 12.0))
                                .char_limit(eivro::MAX_IMPORT),
                        );
                        ui.checkbox(&mut self.import_reveal, "Показать содержимое");
                        ui.label(
                            RichText::new(
                                "Можно вставить JSON или путь к файлу. Архив ZIP, gzip \
                    или TAR также можно перетащить в окно.",
                            )
                            .small()
                            .color(p.muted),
                        );
                        if let Some(error) = &self.error {
                            ui.colored_label(p.error, error);
                        }
                    });
                ui.add_space(18.0);
                ui.horizontal(|ui| {
                    if enabled_command(ui, !busy, "Отмена", ButtonTone::Secondary, Vec2::ZERO, p)
                        .clicked()
                    {
                        close = true;
                    }
                    if enabled_command(
                        ui,
                        !busy && !self.import_text.trim().is_empty(),
                        if busy {
                            "Загрузка…"
                        } else {
                            "Добавить"
                        },
                        ButtonTone::Primary,
                        Vec2::new(130.0, 40.0),
                        p,
                    )
                    .clicked()
                    {
                        self.start_job(self.import_text.clone(), None, ctx);
                    }
                });
            });
            if close || (!busy && response.should_close()) {
                self.import_open = false;
                self.import_reveal = false;
                self.import_text.clear();
            }
        }
        if self.delete_server {
            let response = modal(ctx, "delete-server").show(ctx, |ui| {
                ui.set_width((ctx.content_rect().width() - 64.0).min(380.0));
                ui.label(heading("Удалить сервер?", 22.0));
                if let Some(profile) = self.settings.selected_profile() {
                    ui.label(crate::emoji::text(&profile.name));
                }
                ui.label(
                    RichText::new(
                        "Сохранённый ключ будет удалён. Сервер из подписки \
                    может вернуться при её обновлении.",
                    )
                    .color(p.muted),
                );
                ui.add_space(16.0);
                ui.horizontal(|ui| {
                    if command(ui, "Отмена", ButtonTone::Secondary, Vec2::ZERO, p).clicked() {
                        self.delete_server = false;
                    }
                    if command(ui, "Удалить сервер", ButtonTone::Danger, Vec2::ZERO, p).clicked()
                    {
                        let mut next = self.settings.clone();
                        if let Some(sub) = next.current_mut()
                            && sub.selected < sub.profiles.len()
                        {
                            sub.profiles.remove(sub.selected);
                            sub.selected = 0;
                        }
                        if self.commit(next) {
                            self.delete_server = false;
                            self.reconfigure();
                        }
                    }
                });
            });
            if response.should_close() {
                self.delete_server = false;
            }
        }
        self.subscription_confirmation(ctx, p);
        self.rename_dialog(ctx, p);
    }

    fn subscription_confirmation(&mut self, ctx: &egui::Context, p: Palette) {
        let Some(id) = self.delete_subscription else {
            return;
        };
        let response = modal(ctx, "delete-subscription").show(ctx, |ui| {
            ui.set_width((ctx.content_rect().width() - 64.0).min(380.0));
            ui.label(heading("Удалить подписку?", 22.0));
            ui.label(RichText::new("Ссылка и все её серверы будут удалены.").color(p.muted));
            ui.add_space(16.0);
            ui.horizontal(|ui| {
                if command(ui, "Отмена", ButtonTone::Secondary, Vec2::ZERO, p).clicked() {
                    self.delete_subscription = None;
                }
                if command(ui, "Удалить подписку", ButtonTone::Danger, Vec2::ZERO, p).clicked()
                {
                    let selected = self.settings.current().map(|s| s.id);
                    let mut next = self.settings.clone();
                    next.subscriptions.retain(|s| s.id != id);
                    next.selected_subscription = selected
                        .and_then(|id| next.subscriptions.iter().position(|s| s.id == id))
                        .unwrap_or(0);
                    if self.commit(next) {
                        self.retry_after.remove(&id);
                        self.refresh_errors.remove(&id);
                        self.delete_subscription = None;
                        if selected == Some(id) {
                            self.reconfigure();
                        }
                    }
                }
            });
        });
        if response.should_close() {
            self.delete_subscription = None;
        }
    }

    fn rename_dialog(&mut self, ctx: &egui::Context, p: Palette) {
        let Some((id, mut name)) = self.rename_subscription.take() else {
            return;
        };
        let mut close = false;
        let response = modal(ctx, "rename-subscription").show(ctx, |ui| {
            ui.set_width((ctx.content_rect().width() - 64.0).min(360.0));
            ui.label(heading("Название подписки", 22.0));
            ui.add_space(12.0);
            ui.add(
                egui::TextEdit::singleline(&mut name)
                    .char_limit(80)
                    .desired_width(f32::INFINITY)
                    .margin(Vec2::new(12.0, 10.0)),
            );
            ui.add_space(16.0);
            ui.horizontal(|ui| {
                if command(ui, "Отмена", ButtonTone::Secondary, Vec2::ZERO, p).clicked() {
                    close = true;
                }
                if enabled_command(
                    ui,
                    !name.trim().is_empty(),
                    "Сохранить",
                    ButtonTone::Primary,
                    Vec2::ZERO,
                    p,
                )
                .clicked()
                {
                    let mut next = self.settings.clone();
                    if let Some(sub) = next.subscriptions.iter_mut().find(|s| s.id == id) {
                        sub.name = name.trim().into();
                        close = self.commit(next);
                    } else {
                        close = true;
                    }
                }
            });
        });
        if !close && !response.should_close() {
            self.rename_subscription = Some((id, name));
        }
    }
}
