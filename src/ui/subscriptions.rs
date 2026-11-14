use super::design::{ButtonTone, command, enabled_command, heading};
use super::*;

impl App {
    pub(super) fn subscriptions_page(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        p: Palette,
    ) {
        ui.horizontal(|ui| {
            ui.label(heading("Подписки", 26.0));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if command(ui, "+ Добавить", ButtonTone::Primary, Vec2::ZERO, p).clicked() {
                    self.import_open = true;
                }
            });
        });
        ui.add_space(22.0);
        let mut policy_changes = Vec::new();
        let mut choose = None;
        let mut refresh = None;
        let mut retry = None;
        let mut remove = None;
        egui::ScrollArea::vertical()
            .id_salt("subscriptions-page")
            .show(ui, |ui| {
                if self.settings.subscriptions.is_empty() {
                    ui.add_space(24.0);
                    ui.label(heading("Ваши серверы появятся здесь", 22.0));
                    ui.label(RichText::new("Добавьте подписку, ключ или файл.").color(p.muted));
                }
                for (index, sub) in self.settings.subscriptions.iter().enumerate() {
                    egui::Frame::new()
                        .fill(p.card)
                        .corner_radius(12)
                        .inner_margin(18)
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        let menu = command(
                                            ui,
                                            "···",
                                            ButtonTone::Quiet,
                                            Vec2::new(36.0, 36.0),
                                            p,
                                        )
                                        .on_hover_text("Действия с подпиской");
                                        egui::Popup::menu(&menu).show(|ui| {
                                            if command(
                                                ui,
                                                "Переименовать",
                                                ButtonTone::Quiet,
                                                Vec2::ZERO,
                                                p,
                                            )
                                            .clicked()
                                            {
                                                self.rename_subscription =
                                                    Some((sub.id, sub.name.clone()));
                                                ui.close();
                                            }
                                            if enabled_command(
                                                ui,
                                                self.import_target != Some(sub.id),
                                                "Удалить подписку…",
                                                ButtonTone::Danger,
                                                Vec2::ZERO,
                                                p,
                                            )
                                            .clicked()
                                            {
                                                remove = Some(sub.id);
                                                ui.close();
                                            }
                                        });
                                        if let Some(url) = &sub.source
                                            && enabled_command(
                                                ui,
                                                self.import_result.is_none(),
                                                if self.import_target == Some(sub.id) {
                                                    "Обновление…"
                                                } else {
                                                    "Обновить"
                                                },
                                                ButtonTone::Secondary,
                                                Vec2::ZERO,
                                                p,
                                            )
                                            .clicked()
                                        {
                                            refresh = Some((sub.id, url.clone()));
                                        }
                                        ui.with_layout(
                                            egui::Layout::left_to_right(egui::Align::Center),
                                            |ui| {
                                                if ui
                                                    .add(
                                                        egui::Button::new(heading(
                                                            crate::emoji::text(&sub.name),
                                                            19.0,
                                                        ))
                                                        .frame(false)
                                                        .right_text("›")
                                                        .wrap_mode(egui::TextWrapMode::Truncate),
                                                    )
                                                    .on_hover_text("Открыть серверы")
                                                    .clicked()
                                                {
                                                    choose = Some(index);
                                                }
                                            },
                                        );
                                    },
                                );
                            });
                            ui.horizontal_wrapped(|ui| {
                                ui.label(
                                    RichText::new(format!("Серверов: {}", sub.profiles.len()))
                                        .small()
                                        .color(p.muted),
                                );
                                if self.settings.selected_subscription == index {
                                    ui.label(RichText::new("Выбрана").small().color(p.accent));
                                }
                                if let Some(at) = sub.metadata.expires {
                                    let expired = at < catalog::now();
                                    ui.label(
                                        RichText::new(format!(
                                            "{} {}",
                                            if expired { "Истекла" } else { "До" },
                                            catalog::date(at)
                                        ))
                                        .small()
                                        .color(if expired { p.error } else { p.muted }),
                                    );
                                }
                                let m = &sub.metadata;
                                if m.upload.is_some() || m.download.is_some() {
                                    let used = m
                                        .upload
                                        .unwrap_or(0)
                                        .saturating_add(m.download.unwrap_or(0))
                                        as f64
                                        / 1073741824.0;
                                    let total =
                                        m.total.filter(|v| *v > 0).map_or("∞".into(), |v| {
                                            format!("{:.1} ГиБ", v as f64 / 1073741824.0)
                                        });
                                    ui.label(
                                        RichText::new(format!("{used:.1} / {total}"))
                                            .small()
                                            .color(p.muted),
                                    );
                                }
                            });
                            if sub.source.is_some() {
                                ui.add_space(12.0);
                                ui.horizontal_wrapped(|ui| {
                                    let text = match sub.update {
                                        UpdatePolicy::Manual => "Обновление вручную".into(),
                                        UpdatePolicy::Provider => {
                                            sub.metadata.interval_hours.map_or(
                                                "Интервал провайдера".into(),
                                                |h| format!("Авто · {h} ч"),
                                            )
                                        }
                                        UpdatePolicy::EveryHours(h) => format!("Каждые {h} ч"),
                                    };
                                    let control =
                                        command(ui, text, ButtonTone::Quiet, Vec2::ZERO, p)
                                            .on_hover_text("Настроить обновление подписки");
                                    egui::Popup::menu(&control)
                                        .close_behavior(
                                            egui::PopupCloseBehavior::CloseOnClickOutside,
                                        )
                                        .show(|ui| {
                                            let mut policy = sub.update;
                                            ui.selectable_value(
                                                &mut policy,
                                                UpdatePolicy::Manual,
                                                "Вручную",
                                            );
                                            ui.selectable_value(
                                                &mut policy,
                                                UpdatePolicy::Provider,
                                                "Интервал провайдера",
                                            );
                                            if ui
                                                .selectable_label(
                                                    matches!(policy, UpdatePolicy::EveryHours(_)),
                                                    "Свой интервал",
                                                )
                                                .clicked()
                                                && !matches!(policy, UpdatePolicy::EveryHours(_))
                                            {
                                                policy = UpdatePolicy::EveryHours(1);
                                            }
                                            if let UpdatePolicy::EveryHours(ref mut h) = policy {
                                                ui.add(
                                                    egui::DragValue::new(h)
                                                        .range(1..=720)
                                                        .suffix(" ч"),
                                                );
                                            }
                                            if policy == UpdatePolicy::Provider
                                                && sub.metadata.interval_hours.is_none()
                                            {
                                                ui.label(
                                                    RichText::new("Провайдер не указал интервал.")
                                                        .small()
                                                        .color(p.muted),
                                                );
                                            }
                                            if policy != sub.update {
                                                policy_changes.push((index, policy));
                                            }
                                        });
                                    if let Some(at) = sub.refreshed_at {
                                        ui.label(
                                            RichText::new(format!(
                                                "Обновлено {}",
                                                catalog::date(at)
                                            ))
                                            .small()
                                            .color(p.muted),
                                        );
                                    }
                                });
                            }
                            if sub.using_previous {
                                ui.label(
                                    RichText::new("Используется предыдущий список серверов.")
                                        .color(p.muted),
                                );
                            }
                            if !sub.unavailable.is_empty() {
                                egui::CollapsingHeader::new(format!(
                                    "Недоступные профили · {}",
                                    sub.unavailable.len()
                                ))
                                .id_salt(("unavailable-profiles", sub.id))
                                .show(ui, |ui| {
                                    for entry in &sub.unavailable {
                                        ui.label(crate::emoji::text(&entry.name));
                                        ui.label(
                                            RichText::new(entry.reason.description())
                                                .small()
                                                .color(p.muted),
                                        );
                                    }
                                    if sub.source.is_none()
                                        && enabled_command(
                                            ui,
                                            self.import_result.is_none(),
                                            "Перепроверить",
                                            ButtonTone::Secondary,
                                            Vec2::ZERO,
                                            p,
                                        )
                                        .clicked()
                                    {
                                        retry = Some(sub.clone());
                                    }
                                });
                            }
                            if let Some(error) = self.refresh_errors.get(&sub.id) {
                                ui.add_space(8.0);
                                ui.colored_label(p.error, error);
                                ui.label(
                                    RichText::new("Прежние серверы сохранены.")
                                        .small()
                                        .color(p.muted),
                                );
                            }
                            if !sub.metadata.announcement.is_empty() {
                                ui.add_space(8.0);
                                egui::CollapsingHeader::new("Сообщение провайдера")
                                    .id_salt(("provider", sub.id))
                                    .show(ui, |ui| {
                                        egui::ScrollArea::vertical()
                                            .id_salt(("announcement", sub.id))
                                            .max_height(180.0)
                                            .show(ui, |ui| {
                                                ui.label(crate::emoji::text(
                                                    &sub.metadata.announcement,
                                                ));
                                            });
                                    });
                            }
                            if sub.metadata.support_url.is_some()
                                || sub.metadata.website_url.is_some()
                            {
                                ui.add_space(8.0);
                                ui.horizontal_wrapped(|ui| {
                                    if let Some(url) = &sub.metadata.support_url {
                                        ui.hyperlink_to(
                                            RichText::new("Поддержка ↗").color(p.accent),
                                            url,
                                        );
                                    }
                                    if let Some(url) = &sub.metadata.website_url {
                                        ui.hyperlink_to(
                                            RichText::new("Личный кабинет ↗").color(p.accent),
                                            url,
                                        );
                                    }
                                });
                            }
                        });
                    ui.add_space(14.0);
                }
            });
        let focused = choose
            .and_then(|i| self.settings.subscriptions.get(i))
            .map(|s| s.id);
        if !policy_changes.is_empty() {
            let mut next = self.settings.clone();
            for (i, policy) in policy_changes {
                next.subscriptions[i].update = policy;
            }
            self.commit(next);
        }
        if let Some(id) = focused {
            self.page = Page::Connection;
            self.catalog_open = true;
            self.catalog_focus = Some(id);
            self.server_filter.clear();
        }
        if let Some(sub) = retry {
            self.import_job(Some(sub.id), ctx, move || catalog::retry_local(&sub));
        }
        if let Some((id, url)) = refresh {
            self.start_job(url, Some(id), ctx);
        }
        if let Some(id) = remove {
            self.delete_subscription = Some(id);
        }
    }
}
