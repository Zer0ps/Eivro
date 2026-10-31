use super::design::{ButtonTone, command, enabled_command};
use super::design::{heading, label, mix};
use super::*;
use eivro::{
    network::{Connection, Dns, Interface},
    policy::{Action, PolicyRule, RoutingProfile, Target},
};
use std::collections::BTreeSet;
// Desktop clicks edit/select rows; wheel, trackpad and scrollbar own scrolling.
const RULE_SCROLL: egui::scroll_area::ScrollSource = egui::scroll_area::ScrollSource {
    scroll_bar: true,
    mouse_wheel: true,
    drag: false,
};
pub(super) struct Editor {
    profiles: Vec<RoutingProfile>,
    selected: usize,
    connections: Vec<Connection>,
    rows: BTreeSet<usize>,
    filter: String,
    test_input: String,
    add: bool,
    application: bool,
    input: String,
    action: Action,
    error: Option<String>,
    applications: Vec<(String, String)>,
    network_tab: bool,
    network_edit: Option<NetworkDraft>,
    delete_profile: bool,
    reveal_rule: Option<usize>,
}
struct NetworkDraft {
    id: Option<u64>,
    name: String,
    interface: String,
    manual_interface: bool,
    manual: bool,
    dns: String,
    error: Option<String>,
}
pub(super) struct Edit {
    pub profiles: Vec<RoutingProfile>,
    pub selected: usize,
    pub connections: Vec<Connection>,
}
fn action_name(action: Action, connections: &[Connection]) -> String {
    match action {
        Action::Connection(id) => connections
            .iter()
            .find(|c| c.id == id)
            .map_or("Выход удалён".into(), |c| c.name.clone()),
        Action::Proxy => "Через Eivro".into(),
        Action::Direct => action.label().into(),
    }
}
fn action_choice(
    ui: &mut egui::Ui,
    id: impl std::hash::Hash,
    action: &mut Action,
    connections: &[Connection],
) {
    egui::ComboBox::from_id_salt(id)
        .width(190.0)
        .selected_text(action_name(*action, connections))
        .show_ui(ui, |ui| {
            ui.selectable_value(action, Action::Proxy, "Через Eivro");
            ui.selectable_value(action, Action::Direct, "Напрямую");
            if !connections.is_empty() {
                ui.separator();
                for c in connections {
                    ui.selectable_value(action, Action::Connection(c.id), &c.name);
                }
            }
        });
}

struct RuleControls {
    select: egui::Response,
    direction: egui::Response,
    enabled: egui::Response,
}

/// Separate hit areas keep editing a route from changing the bulk selection.
fn rule_row(
    ui: &mut egui::Ui,
    rule: &mut PolicyRule,
    selected: &mut bool,
    connections: &[Connection],
    fresh: bool,
    p: Palette,
) -> egui::InnerResponse<RuleControls> {
    let before = (rule.action, rule.enabled);
    let background = ui.painter().add(egui::Shape::Noop);
    let row = egui::Frame::new()
        .inner_margin(egui::Margin::symmetric(10, 5))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                let select = ui.add_sized(
                    [
                        (ui.available_width() - 192.0 - 2.0 * ui.spacing().item_spacing.x).max(1.0),
                        38.0,
                    ],
                    egui::Button::new("")
                        .fill(Color32::TRANSPARENT)
                        .stroke(Stroke::NONE),
                );
                if select.clicked() {
                    *selected = !*selected;
                }
                select.widget_info(|| {
                    egui::WidgetInfo::selected(
                        egui::WidgetType::SelectableLabel,
                        true,
                        *selected,
                        rule.target.value(),
                    )
                });
                let galley = ui.painter().layout_job({
                    let mut job = egui::text::LayoutJob::simple(
                        rule.target.value().to_owned(),
                        FontId::proportional(14.0),
                        if rule.enabled { p.text } else { p.muted },
                        (select.rect.width() - 16.0).max(1.0),
                    );
                    job.wrap.max_rows = 1;
                    job.wrap.break_anywhere = true;
                    job
                });
                ui.painter().galley(
                    egui::pos2(
                        select.rect.left() + 8.0,
                        select.rect.center().y - galley.size().y * 0.5,
                    ),
                    galley,
                    p.text,
                );
                let plate = ui.painter().add(egui::Shape::Noop);
                let direction = ui.add_sized(
                    [148.0, 36.0],
                    egui::Button::new(action_name(rule.action, connections))
                        .right_text("⌄")
                        .truncate()
                        .fill(Color32::TRANSPARENT)
                        .stroke(Stroke::NONE),
                );
                direction.widget_info(|| {
                    egui::WidgetInfo::labeled(
                        egui::WidgetType::Button,
                        true,
                        format!(
                            "Направление {}: {}",
                            rule.target.value(),
                            action_name(rule.action, connections)
                        ),
                    )
                });
                let hover = ui.ctx().animate_bool_with_time(
                    direction.id.with("hover"),
                    direction.hovered() || direction.has_focus(),
                    ui.style().animation_time.min(0.14),
                );
                let press = ui.ctx().animate_bool_with_time(
                    direction.id.with("press"),
                    direction.is_pointer_button_down_on(),
                    ui.style().animation_time.min(0.08),
                );
                ui.painter().set(
                    plate,
                    egui::epaint::RectShape::new(
                        direction.rect.shrink(press * 0.5),
                        8,
                        mix(mix(p.raised, p.soft, hover), p.bg, press * 0.16),
                        Stroke::new(
                            1.0_f32,
                            if direction.has_focus() {
                                p.accent
                            } else {
                                mix(p.line, p.muted, hover * 0.4)
                            },
                        ),
                        egui::StrokeKind::Inside,
                    ),
                );
                egui::Popup::menu(&direction).show(|ui| {
                    ui.set_min_width(170.0);
                    egui::ScrollArea::vertical()
                        .id_salt("direction-choices")
                        .scroll_source(RULE_SCROLL)
                        .max_height((ui.ctx().content_rect().height() - 80.0).clamp(64.0, 280.0))
                        .show(ui, |ui| {
                            for action in [Action::Direct, Action::Proxy]
                                .into_iter()
                                .chain(connections.iter().map(|c| Action::Connection(c.id)))
                            {
                                if ui
                                    .selectable_value(
                                        &mut rule.action,
                                        action,
                                        action_name(action, connections),
                                    )
                                    .clicked()
                                {
                                    ui.close();
                                }
                            }
                        });
                });
                let direction = direction.on_hover_text(action_name(rule.action, connections));
                let enabled = super::design::toggle(ui, "Правило включено", &mut rule.enabled, p);
                RuleControls {
                    select: select.on_hover_text(rule.target.value()),
                    direction,
                    enabled,
                }
            })
            .inner
        });
    let duration = ui.style().animation_time;
    let selected_progress = ui.ctx().animate_bool_with_time(
        row.inner.select.id.with("selection"),
        *selected,
        duration.min(0.16),
    );
    let hover = ui.ctx().animate_bool_with_time(
        row.inner.select.id.with("row-hover"),
        row.inner.select.hovered() || row.inner.direction.hovered() || row.inner.enabled.hovered(),
        duration.min(0.12),
    );
    let changed = before != (rule.action, rule.enabled) || fresh;
    let press = ui.ctx().animate_bool_with_time(
        row.inner.select.id.with("press"),
        row.inner.select.is_pointer_button_down_on(),
        duration.min(0.08),
    );
    let feedback = if duration == 0.0 {
        0.0
    } else {
        let t = ui.ctx().animate_value_with_time(
            row.inner.select.id.with("rule-change"),
            if changed { 1.0 } else { 0.0 },
            if changed { 0.0 } else { 0.3 },
        );
        if changed {
            ui.ctx().request_repaint();
        }
        t
    };
    let fill = mix(
        mix(
            mix(p.bg, p.card, hover),
            p.soft,
            selected_progress.max(press * 0.35),
        ),
        p.accent,
        feedback * 0.10,
    );
    ui.painter().set(
        background,
        egui::epaint::RectShape::new(
            row.response.rect,
            9,
            fill,
            if row.inner.select.has_focus() {
                Stroke::new(1.5_f32, p.accent)
            } else {
                Stroke::NONE
            },
            egui::StrokeKind::Inside,
        ),
    );
    if selected_progress > 0.0 {
        ui.painter().rect_filled(
            egui::Rect::from_center_size(
                row.response.rect.left_center() + Vec2::new(2.0, 0.0),
                Vec2::new(3.0, 24.0 * selected_progress),
            ),
            2,
            p.accent,
        );
    }
    row
}

impl Editor {
    pub(super) fn modal_open(&self) -> bool {
        self.add || self.network_edit.is_some() || self.delete_profile
    }
    pub fn new(s: &Settings) -> Self {
        Self {
            profiles: s.routing_profiles.clone(),
            selected: s.selected_routing,
            connections: s.connections.clone(),
            rows: BTreeSet::new(),
            filter: String::new(),
            test_input: String::new(),
            add: false,
            application: false,
            input: String::new(),
            action: Action::Direct,
            error: None,
            applications: applications(),
            network_tab: false,
            network_edit: None,
            delete_profile: false,
            reveal_rule: None,
        }
    }
    #[cfg(feature = "qa")]
    pub fn open_add(&mut self, application: bool) {
        self.add = true;
        self.application = application;
    }
    #[cfg(feature = "qa")]
    pub fn preview_selection(&mut self) {
        self.rows
            .extend(0..self.profiles[self.selected].rules.len().min(3));
        if let Some(rule) = self.profiles[self.selected].rules.first_mut() {
            rule.enabled = false;
        }
    }
    #[cfg(feature = "qa")]
    pub fn open_network(&mut self, edit: bool) {
        self.network_tab = true;
        if edit {
            self.network_edit = Some(NetworkDraft {
                id: None,
                name: "Работа".into(),
                interface: "tun0".into(),
                manual_interface: false,
                manual: false,
                dns: String::new(),
                error: None,
            });
        }
    }
    fn dirty(&self, s: &Settings) -> bool {
        self.profiles != s.routing_profiles
            || self.selected != s.selected_routing
            || self.connections != s.connections
    }
    fn add_control(&mut self, ui: &mut egui::Ui, p: Palette) {
        if self.network_tab {
            if command(ui, "+ Новый выход", ButtonTone::Secondary, Vec2::ZERO, p).clicked()
            {
                self.network_edit = Some(NetworkDraft {
                    id: None,
                    name: String::new(),
                    interface: String::new(),
                    manual_interface: false,
                    manual: false,
                    dns: String::new(),
                    error: None,
                });
            }
        } else if command(
            ui,
            "+ Добавить правило",
            ButtonTone::Primary,
            Vec2::new(0.0, 40.0),
            p,
        )
        .clicked()
        {
            self.add = true;
            self.error = None;
        }
    }
    fn show(
        &mut self,
        ui: &mut egui::Ui,
        p: Palette,
        s: &Settings,
        links: &[Interface],
        scan: &mut bool,
        scanning: bool,
    ) -> Option<Edit> {
        let ctx = ui.ctx().clone();
        ui.label(heading("Маршруты", 26.0));
        ui.add_space(20.0);
        let narrow = ui.available_width() < 500.0;
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut self.network_tab, false, "Правила");
            ui.selectable_value(&mut self.network_tab, true, "Сетевые выходы");
            if !narrow {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    self.add_control(ui, p)
                });
            }
        });
        if narrow {
            self.add_control(ui, p);
        }
        ui.add_space(16.0);
        let dirty = self.dirty(s);
        let h = (ui.available_height() - if dirty { 112.0 } else { 48.0 }).max(110.0);
        ui.allocate_ui(Vec2::new(ui.available_width(), h), |ui| {
            if self.network_tab {
                self.networks(ui, p, links, scan, scanning, h);
            } else {
                self.rules(ui, p, h);
            }
        });
        if !self.network_tab {
            egui::CollapsingHeader::new("Проверить адрес")
                .id_salt("check-route")
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.test_input)
                                .hint_text("Домен или IP")
                                .desired_width(240.0)
                                .margin(Vec2::new(10.0, 8.0))
                                .char_limit(253),
                        );
                        if !self.test_input.trim().is_empty() {
                            let action =
                                self.profiles[self.selected].matches(self.test_input.trim());
                            ui.label(
                                RichText::new(format!(
                                    "→ {}",
                                    action_name(action, &self.connections)
                                ))
                                .color(p.accent),
                            )
                            .on_hover_text(
                                "По текущему черновику, без DNS-запросов. \
Правила приложений здесь не проверяются.",
                            );
                        }
                    });
                });
        }
        let mut apply = false;
        let mut reset = false;
        if dirty {
            ui.add_space(8.0);
            egui::Frame::new()
                .fill(p.soft)
                .corner_radius(10)
                .inner_margin(12)
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("Есть изменения").color(p.accent))
                            .on_hover_text("При применении активный VPN переподключится.");
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            apply = command(
                                ui,
                                "Применить",
                                ButtonTone::Primary,
                                Vec2::new(108.0, 40.0),
                                p,
                            )
                            .clicked();
                            reset = command(ui, "Отменить", ButtonTone::Secondary, Vec2::ZERO, p)
                                .clicked();
                        });
                    });
                });
        }
        if let Some(error) = &self.error {
            ui.colored_label(p.error, error);
        }
        if reset {
            *self = Self::new(s);
        }
        self.add_dialog(&ctx, p);
        self.network_dialog(&ctx, p, links);
        self.delete_profile_dialog(&ctx, p);
        if apply {
            let edit = Edit {
                profiles: self.profiles.clone(),
                selected: self.selected,
                connections: self.connections.clone(),
            };
            let mut next = s.clone();
            next.routing_profiles = edit.profiles.clone();
            next.selected_routing = edit.selected;
            next.connections = edit.connections.clone();
            match next.validate() {
                Ok(()) => return Some(edit),
                Err(e) => self.error = Some(e),
            }
        }
        None
    }
    fn rules(&mut self, ui: &mut egui::Ui, p: Palette, height: f32) {
        ui.horizontal(|ui| {
            label(ui, "Профиль", p);
            let old = self.selected;
            egui::ComboBox::from_id_salt("edit-profile")
                .width(160.0)
                .selected_text(&self.profiles[self.selected].name)
                .show_ui(ui, |ui| {
                    for (i, profile) in self.profiles.iter().enumerate() {
                        ui.selectable_value(&mut self.selected, i, &profile.name);
                    }
                });
            if old != self.selected {
                self.reveal_rule = None;
                self.rows.clear();
                self.filter.clear();
            }
            ui.menu_button("Управление…", |ui| {
                ui.label("Название профиля");
                ui.add(
                    egui::TextEdit::singleline(&mut self.profiles[self.selected].name)
                        .char_limit(40)
                        .desired_width(210.0),
                );
                ui.separator();
                for (title, copy) in [("Новый профиль", false), ("Создать копию", true)]
                {
                    if ui
                        .add_enabled(self.profiles.len() < 24, egui::Button::new(title))
                        .clicked()
                    {
                        let mut n = 1;
                        let name = loop {
                            let name = format!("Профиль {n}");
                            if !self.profiles.iter().any(|p| p.name == name) {
                                break name;
                            }
                            n += 1
                        };
                        let rules = if copy {
                            self.profiles[self.selected].rules.clone()
                        } else {
                            vec![]
                        };
                        self.profiles.push(RoutingProfile { name, rules });
                        self.selected = self.profiles.len() - 1;
                        self.rows.clear();
                        ui.close();
                    }
                }
                if ui
                    .add_enabled(
                        self.profiles.len() > 1,
                        egui::Button::new("Удалить профиль…"),
                    )
                    .clicked()
                {
                    self.delete_profile = true;
                    ui.close();
                }
            });
        });
        ui.add_space(8.0);
        ui.add(
            egui::TextEdit::singleline(&mut self.filter)
                .hint_text("Найти правило…")
                .desired_width(f32::INFINITY)
                .margin(Vec2::new(12.0, 9.0))
                .char_limit(255),
        );
        ui.add_space(10.0);
        let filter = self.filter.to_lowercase();
        let visible: Vec<_> = self.profiles[self.selected]
            .rules
            .iter()
            .enumerate()
            .filter(|(_, r)| r.target.value().to_lowercase().contains(&filter))
            .map(|(i, _)| i)
            .collect();
        if !self.modal_open()
            && ui.ctx().memory(|m| m.top_modal_layer().is_none())
            && !egui::Popup::is_any_open(ui.ctx())
            && ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
        {
            self.rows.clear();
        }
        ui.horizontal(|ui| {
            let all = !visible.is_empty() && visible.iter().all(|i| self.rows.contains(i));
            if enabled_command(
                ui,
                !visible.is_empty(),
                if all {
                    "Снять выбор"
                } else {
                    "Выбрать все"
                },
                ButtonTone::Quiet,
                Vec2::ZERO,
                p,
            )
            .clicked()
            {
                if all {
                    self.rows.clear();
                } else {
                    self.rows.extend(visible.iter().copied());
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(64.0);
                ui.label(RichText::new("Направление").size(11.0).color(p.muted));
            });
        });
        let selection_progress = ui.ctx().animate_bool_with_time(
            ui.id().with("rule-selection-toolbar"),
            !self.rows.is_empty(),
            ui.style().animation_time.min(0.16),
        );
        egui::ScrollArea::vertical()
            .id_salt("routing-rows")
            .scroll_source(RULE_SCROLL)
            .max_height((height - 180.0 - 55.0 * selection_progress).max(60.0))
            .min_scrolled_height(80.0)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                if visible.is_empty() {
                    ui.add_space(24.0);
                    ui.label(heading(
                        if filter.is_empty() {
                            "Всё через Eivro"
                        } else {
                            "Ничего не найдено"
                        },
                        20.0,
                    ));
                    ui.label(
                        RichText::new(if filter.is_empty() {
                            "Добавьте исключение для сайта или приложения."
                        } else {
                            "Измените поисковый запрос."
                        })
                        .color(p.muted),
                    );
                }
                for i in visible {
                    let rule = &mut self.profiles[self.selected].rules[i];
                    let mut selected = self.rows.contains(&i);
                    let fresh = self.reveal_rule == Some(i);
                    let row = ui
                        .push_id(("rule-row", self.selected, i), |ui| {
                            rule_row(ui, rule, &mut selected, &self.connections, fresh, p)
                        })
                        .inner;
                    if selected {
                        self.rows.insert(i);
                    } else {
                        self.rows.remove(&i);
                    }
                    if fresh {
                        ui.scroll_to_rect_animation(
                            row.response.rect,
                            Some(egui::Align::Center),
                            if ui.style().animation_time == 0.0 {
                                egui::style::ScrollAnimation::none()
                            } else {
                                ui.style().scroll_animation
                            },
                        );
                        self.reveal_rule = None;
                    }
                    ui.add_space(2.0);
                }
            });
        ui.add_space(8.0);
        if self.rows.is_empty() {
            ui.label(
                RichText::new("Первое совпадение сверху. Остальное — через Eivro.")
                    .small()
                    .color(p.muted),
            );
        } else {
            ui.scope(|ui| {
                ui.set_opacity(selection_progress);
                ui.horizontal_wrapped(|ui| {
                    ui.label(format!("Выбрано: {}", self.rows.len()));
                    ui.menu_button("Направление", |ui| {
                        for action in std::iter::once(Action::Proxy)
                            .chain(std::iter::once(Action::Direct))
                            .chain(self.connections.iter().map(|c| Action::Connection(c.id)))
                        {
                            if ui.button(action_name(action, &self.connections)).clicked() {
                                for i in &self.rows {
                                    self.profiles[self.selected].rules[*i].action = action;
                                }
                                ui.close();
                            }
                        }
                    });
                    ui.menu_button("Действия", |ui| {
                        for (title, on) in [("Включить", true), ("Выключить", false)]
                        {
                            if ui.button(title).clicked() {
                                for i in &self.rows {
                                    self.profiles[self.selected].rules[*i].enabled = on;
                                }
                                ui.close();
                            }
                        }
                        if command(ui, "Удалить выбранные", ButtonTone::Danger, Vec2::ZERO, p)
                            .clicked()
                        {
                            let mut i = 0;
                            self.profiles[self.selected].rules.retain(|_| {
                                let keep = !self.rows.contains(&i);
                                i += 1;
                                keep
                            });
                            self.rows.clear();
                            ui.close();
                        }
                    });
                    if self.rows.len() == 1 {
                        let i = *self.rows.first().unwrap();
                        for (title, to) in [
                            ("Выше", i.checked_sub(1)),
                            (
                                "Ниже",
                                i.checked_add(1)
                                    .filter(|n| *n < self.profiles[self.selected].rules.len()),
                            ),
                        ] {
                            if ui
                                .add_enabled(to.is_some(), egui::Button::new(title))
                                .clicked()
                                && let Some(to) = to
                            {
                                self.profiles[self.selected].rules.swap(i, to);
                                self.rows.clear();
                                self.rows.insert(to);
                            }
                        }
                    }
                    if command(ui, "Снять выбор", ButtonTone::Quiet, Vec2::ZERO, p).clicked()
                    {
                        self.rows.clear();
                    }
                });
            });
        }
    }
    fn networks(
        &mut self,
        ui: &mut egui::Ui,
        p: Palette,
        links: &[Interface],
        scan: &mut bool,
        scanning: bool,
        height: f32,
    ) {
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(format!("Выходов: {}", self.connections.len()))
                    .small()
                    .color(p.muted),
            );
            if enabled_command(
                ui,
                !scanning,
                if scanning {
                    "Обновление…"
                } else {
                    "Обновить интерфейсы"
                },
                ButtonTone::Quiet,
                Vec2::ZERO,
                p,
            )
            .clicked()
            {
                *scan = true;
            }
        });
        ui.add_space(12.0);
        let columns = if ui.available_width() > 760.0 { 2 } else { 1 };
        let width = (ui.available_width() - 12.0 * (columns - 1) as f32) / columns as f32;
        let mut remove = None;
        egui::ScrollArea::vertical()
            .id_salt("network-exits")
            .max_height((height - 55.0).max(80.0))
            .show(ui, |ui| {
                if self.connections.is_empty() {
                    ui.add_space(22.0);
                    ui.label(heading("Своя сеть для исключений", 22.0));
                    ui.label(
                        RichText::new(
                            "Добавьте рабочий VPN, затем выберите его в \
правилах.",
                        )
                        .color(p.muted),
                    );
                }
                egui::Grid::new("network-grid")
                    .num_columns(columns)
                    .spacing(Vec2::splat(12.0))
                    .show(ui, |ui| {
                        for (i, connection) in self.connections.iter().enumerate() {
                            egui::Frame::new()
                                .fill(p.card)
                                .corner_radius(12)
                                .inner_margin(18)
                                .show(ui, |ui| {
                                    ui.with_layout(
                                        egui::Layout::top_down(egui::Align::Min),
                                        |ui| {
                                            ui.set_width((width - 36.0).max(120.0));
                                            let used = self
                                                .profiles
                                                .iter()
                                                .flat_map(|p| &p.rules)
                                                .filter(|r| {
                                                    r.action == Action::Connection(connection.id)
                                                })
                                                .count();
                                            ui.horizontal(|ui| {
                                                ui.add(
                                                    egui::Label::new(heading(
                                                        &connection.name,
                                                        19.0,
                                                    ))
                                                    .truncate(),
                                                )
                                                .on_hover_text(&connection.name);
                                                ui.with_layout(
                                                    egui::Layout::right_to_left(
                                                        egui::Align::Center,
                                                    ),
                                                    |ui| {
                                                        let r = command(
                                                            ui,
                                                            "···",
                                                            ButtonTone::Quiet,
                                                            Vec2::new(32.0, 36.0),
                                                            p,
                                                        )
                                                        .on_hover_text("Действия с выходом");
                                                        egui::Popup::menu(&r).show(|ui| {
                                                            if enabled_command(
                                                        ui,
                                                        used == 0,
                                                        "Удалить выход",
                                                        ButtonTone::Danger,
                                                        Vec2::ZERO,
                                                        p,
                                                    )
                                                    .on_hover_text(
                                                        "Сначала уберите этот выход из правил.",
                                                    )
                                                    .clicked()
                                                    {
                                                        remove = Some(connection.id);
                                                        ui.close();
                                                    }
                                                        });
                                                    },
                                                );
                                            });
                                            let servers = connection.servers(links);
                                            ui.horizontal_wrapped(|ui| {
                                                ui.label(
                                                    RichText::new(&connection.interface)
                                                        .monospace()
                                                        .color(p.text),
                                                );
                                                if scanning {
                                                    ui.label(
                                                        RichText::new("Проверка DNS…")
                                                            .small()
                                                            .color(p.muted),
                                                    );
                                                } else if let Some(servers) = servers {
                                                    ui.label(
                                                        RichText::new(format!(
                                                            "DNS {}",
                                                            servers[0]
                                                        ))
                                                        .small()
                                                        .color(p.muted),
                                                    );
                                                } else {
                                                    ui.label(
                                                        RichText::new("Недоступен")
                                                            .small()
                                                            .color(p.error),
                                                    )
                                                    .on_hover_text(
                                                        "Проверьте интерфейс и его DNS. Совпавшие \
запросы блокируются.",
                                                    );
                                                }
                                            });
                                            ui.add_space(16.0);
                                            ui.horizontal(|ui| {
                                                if command(
                                                    ui,
                                                    "Настроить",
                                                    ButtonTone::Secondary,
                                                    Vec2::ZERO,
                                                    p,
                                                )
                                                .clicked()
                                                {
                                                    self.network_edit = Some(NetworkDraft {
                                                        id: Some(connection.id),
                                                        name: connection.name.clone(),
                                                        interface: connection.interface.clone(),
                                                        manual_interface: !links.iter().any(|l| {
                                                            l.name == connection.interface
                                                        }),
                                                        manual: matches!(
                                                            connection.dns,
                                                            Dns::Manual(_)
                                                        ),
                                                        dns: match &connection.dns {
                                                            Dns::Manual(servers) => {
                                                                servers.first().map_or(
                                                                    String::new(),
                                                                    ToString::to_string,
                                                                )
                                                            }
                                                            _ => String::new(),
                                                        },
                                                        error: None,
                                                    });
                                                }
                                                ui.label(
                                                    RichText::new(format!("Правил: {used}"))
                                                        .small()
                                                        .color(p.muted),
                                                );
                                            });
                                        },
                                    );
                                });
                            if (i + 1) % columns == 0 {
                                ui.end_row();
                            }
                        }
                    });
            });
        if let Some(id) = remove {
            self.connections.retain(|c| c.id != id);
        }
    }
    fn add_dialog(&mut self, ctx: &egui::Context, p: Palette) {
        if !self.add {
            return;
        }
        let mut close = false;
        let response = super::design::modal(ctx, "add-routing-rule").show(ctx, |ui| {
            ui.set_width((ctx.content_rect().width() - 100.0).min(470.0));
            ui.label(heading("Добавить правило", 23.0));
            ui.add_space(14.0);
            egui::ScrollArea::vertical()
                .id_salt("add-rule-form")
                .max_height((ctx.content_rect().height() - 190.0).max(70.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        if ui
                            .selectable_value(&mut self.application, false, "Адреса")
                            .changed()
                        {
                            self.input.clear();
                        }
                        if ui
                            .selectable_value(&mut self.application, true, "Приложение")
                            .changed()
                        {
                            self.input.clear();
                        }
                    });
                    ui.add_space(10.0);
                    if self.application {
                        egui::ComboBox::from_id_salt("new-rule-application")
                            .width(ui.available_width())
                            .selected_text("Выбрать приложение…")
                            .show_ui(ui, |ui| {
                                for (name, path) in &self.applications {
                                    if ui.selectable_label(self.input == *path, name).clicked() {
                                        self.input = path.clone();
                                    }
                                }
                            });
                        ui.add(
                            egui::TextEdit::singleline(&mut self.input)
                                .hint_text("/usr/bin/firefox")
                                .desired_width(f32::INFINITY)
                                .margin(Vec2::new(12.0, 10.0))
                                .char_limit(4096),
                        );
                        ui.label(
                            RichText::new(
                                "Правила приложений действуют в TUN. Для \
внутренних имён добавьте также доменное \
правило DNS.",
                            )
                            .small()
                            .color(p.muted),
                        );
                    } else {
                        label(ui, "Адреса, по одному на строку", p);
                        ui.add(
                            egui::TextEdit::multiline(&mut self.input)
                                .id(egui::Id::new("bypass-input"))
                                .hint_text("example.com\n*.example.com\n10.0.0.0/8")
                                .desired_rows(4)
                                .desired_width(f32::INFINITY)
                                .margin(Vec2::new(12.0, 10.0))
                                .char_limit(65536),
                        );
                        ui.label(
                            RichText::new("*.example.com не включает сам example.com.")
                                .small()
                                .color(p.muted),
                        );
                    }
                    ui.add_space(12.0);
                    label(ui, "Направление", p);
                    action_choice(
                        ui,
                        "new-rule-destination",
                        &mut self.action,
                        &self.connections,
                    );
                    if let Action::Connection(id) = self.action
                        && let Some(connection) = self.connections.iter().find(|c| c.id == id)
                    {
                        ui.label(
                            RichText::new(format!(
                                "Интерфейс {} и DNS сетевого выхода «{}».",
                                connection.interface, connection.name
                            ))
                            .small()
                            .color(p.accent),
                        );
                    }
                    if let Some(error) = &self.error {
                        ui.colored_label(p.error, error);
                    }
                });
            ui.add_space(20.0);
            ui.horizontal(|ui| {
                if command(ui, "Отмена", ButtonTone::Secondary, Vec2::ZERO, p).clicked() {
                    close = true;
                }
                if command(
                    ui,
                    "Добавить в профиль",
                    ButtonTone::Primary,
                    Vec2::new(0.0, 40.0),
                    p,
                )
                .clicked()
                {
                    let profile = &mut self.profiles[self.selected];
                    let previous_count = profile.rules.len();
                    let result = if self.application {
                        Target::application(&self.input).and_then(|target| {
                            if profile.rules.len() >= 256 {
                                return Err("Максимум 256 правил.".into());
                            }
                            if !profile
                                .rules
                                .iter()
                                .any(|r| r.target == target && r.action == self.action)
                            {
                                profile.rules.push(PolicyRule {
                                    enabled: true,
                                    target,
                                    action: self.action,
                                });
                            }
                            Ok(1)
                        })
                    } else {
                        profile.add_addresses(&self.input, self.action)
                    };
                    match result {
                        Ok(_) => {
                            if profile.rules.len() > previous_count {
                                self.reveal_rule = Some(previous_count);
                                self.filter.clear();
                            }
                            self.input.clear();
                            self.error = None;
                            close = true
                        }
                        Err(error) => self.error = Some(error),
                    }
                }
            });
        });
        if close || response.should_close() {
            self.add = false;
        }
    }
    fn network_dialog(&mut self, ctx: &egui::Context, p: Palette, links: &[Interface]) {
        let Some(draft) = &mut self.network_edit else {
            return;
        };
        let mut cancel = false;
        let mut saved = None;
        let response = super::design::modal(ctx, "network-exit-editor").show(ctx, |ui| {
            ui.set_width((ctx.content_rect().width() - 100.0).min(470.0));
            ui.label(heading(
                if draft.id.is_some() {
                    "Сетевой выход"
                } else {
                    "Новый сетевой выход"
                },
                23.0,
            ));
            ui.add_space(16.0);
            egui::ScrollArea::vertical()
                .id_salt("network-exit-form")
                .max_height((ctx.content_rect().height() - 220.0).max(70.0))
                .show(ui, |ui| {
                    label(ui, "Название", p);
                    ui.add(
                        egui::TextEdit::singleline(&mut draft.name)
                            .hint_text("Работа")
                            .char_limit(40)
                            .desired_width(f32::INFINITY)
                            .margin(Vec2::new(12.0, 9.0)),
                    );
                    ui.add_space(12.0);
                    label(ui, "Интерфейс", p);
                    if draft.manual_interface {
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut draft.interface)
                                    .hint_text("tun0 или wg0")
                                    .char_limit(15)
                                    .desired_width(ui.available_width() - 115.0)
                                    .margin(Vec2::new(12.0, 10.0)),
                            );
                            if command(ui, "Из списка", ButtonTone::Quiet, Vec2::ZERO, p).clicked()
                            {
                                draft.manual_interface = false;
                            }
                        });
                    } else {
                        egui::ComboBox::from_id_salt("network-interface")
                            .width(ui.available_width())
                            .selected_text(if draft.interface.is_empty() {
                                "Выберите интерфейс"
                            } else {
                                &draft.interface
                            })
                            .show_ui(ui, |ui| {
                                for link in links {
                                    ui.selectable_value(
                                        &mut draft.interface,
                                        link.name.clone(),
                                        format!(
                                            "{}{}",
                                            link.name,
                                            if link.up { "" } else { " · выключен" }
                                        ),
                                    );
                                }
                                ui.separator();
                                if ui.selectable_label(false, "Ввести имя…").clicked() {
                                    draft.manual_interface = true;
                                }
                            });
                    }
                    ui.add_space(14.0);
                    label(ui, "DNS", p);
                    let server = links
                        .iter()
                        .find(|l| l.name == draft.interface)
                        .and_then(|l| l.dns.first());
                    let auto = server.map_or("DNS интерфейса".to_owned(), |ip| {
                        format!("Автоматически · {ip}")
                    });
                    egui::ComboBox::from_id_salt("network-dns-mode")
                        .width(ui.available_width())
                        .selected_text(if draft.manual {
                            "Указать вручную".to_owned()
                        } else {
                            auto
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut draft.manual, false, "DNS интерфейса");
                            ui.selectable_value(&mut draft.manual, true, "Указать вручную");
                        });
                    if draft.manual {
                        ui.add(
                            egui::TextEdit::singleline(&mut draft.dns)
                                .hint_text("IP-адрес DNS")
                                .desired_width(f32::INFINITY)
                                .margin(Vec2::new(12.0, 10.0))
                                .char_limit(64),
                        );
                    } else if !draft.interface.is_empty() && server.is_none() {
                        ui.label(
                            RichText::new(
                                "DNS не найден. Подключите сеть или укажите \
его вручную.",
                            )
                            .small()
                            .color(p.error),
                        );
                    }
                    ui.add_space(14.0);
                    egui::CollapsingHeader::new("Как это работает").show(ui, |ui| {
                        ui.label(
                            RichText::new(
                                "Трафик и DNS идут через выбранный интерфейс. \
Если выход недоступен, совпавшие запросы \
блокируются без перехода на другой VPN или \
публичный DNS.",
                            )
                            .small()
                            .color(p.muted),
                        );
                    });
                    if let Some(error) = &draft.error {
                        ui.colored_label(p.error, error);
                    }
                });
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                if command(ui, "Отмена", ButtonTone::Secondary, Vec2::ZERO, p).clicked() {
                    cancel = true;
                }
                if command(
                    ui,
                    "Сохранить выход",
                    ButtonTone::Primary,
                    Vec2::new(0.0, 40.0),
                    p,
                )
                .clicked()
                {
                    let dns = if draft.manual {
                        draft
                            .dns
                            .trim()
                            .parse()
                            .map(|ip| Dns::Manual(vec![ip]))
                            .map_err(|_| "Укажите IP-адрес DNS без URL и порта.".to_string())
                    } else {
                        Ok(Dns::Interface)
                    };
                    let result = dns.and_then(|dns| {
                        let id = match draft.id {
                            Some(id) => id,
                            None => self
                                .connections
                                .iter()
                                .map(|c| c.id)
                                .max()
                                .unwrap_or(0)
                                .checked_add(1)
                                .ok_or("Нет идентификатора выхода.")?,
                        };
                        let connection = Connection {
                            id,
                            name: draft.name.trim().into(),
                            interface: draft.interface.trim().into(),
                            dns,
                        };
                        let mut candidate = self.connections.clone();
                        if let Some(old) = candidate.iter_mut().find(|c| c.id == id) {
                            *old = connection.clone()
                        } else {
                            candidate.push(connection.clone())
                        }
                        eivro::network::validate(&candidate)?;
                        Ok(connection)
                    });
                    match result {
                        Ok(connection) => saved = Some(connection),
                        Err(error) => draft.error = Some(error),
                    }
                }
            });
        });
        if let Some(connection) = saved {
            if let Some(old) = self.connections.iter_mut().find(|c| c.id == connection.id) {
                *old = connection
            } else {
                self.connections.push(connection)
            }
            self.network_edit = None;
        } else if cancel || response.should_close() {
            self.network_edit = None;
        }
    }
    fn delete_profile_dialog(&mut self, ctx: &egui::Context, p: Palette) {
        if !self.delete_profile {
            return;
        }
        let response = super::design::modal(ctx, "delete-route-profile").show(ctx, |ui| {
            ui.set_width((ctx.content_rect().width() - 64.0).min(360.0));
            ui.label(heading("Удалить профиль?", 22.0));
            ui.label(
                "Его правила будут удалены после применения \
изменений.",
            );
            ui.horizontal(|ui| {
                if command(ui, "Отмена", ButtonTone::Secondary, Vec2::ZERO, p).clicked() {
                    self.delete_profile = false;
                }
                if command(ui, "Удалить", ButtonTone::Danger, Vec2::ZERO, p).clicked() {
                    self.profiles.remove(self.selected);
                    self.selected = 0;
                    self.rows.clear();
                    self.delete_profile = false;
                }
            });
        });
        if response.should_close() {
            self.delete_profile = false;
        }
    }
}
impl App {
    pub(super) fn routes_page(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, p: Palette) {
        let mut editor = self
            .editor
            .take()
            .unwrap_or_else(|| Editor::new(&self.settings));
        let mut scan = false;
        // Keep the footer reachable with large text or short windows. The inner
        // list retains its own bounded viewport for long rule sets.
        let applied = egui::ScrollArea::vertical()
            .id_salt("routes-page")
            .scroll_source(RULE_SCROLL)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                editor.show(
                    ui,
                    p,
                    &self.settings,
                    &self.network_links,
                    &mut scan,
                    self.network_result.is_some(),
                )
            })
            .inner;
        if scan {
            self.scan_network(ctx);
        }
        if let Some(edit) = applied {
            let mut next = self.settings.clone();
            next.routing_profiles = edit.profiles;
            next.selected_routing = edit.selected;
            next.connections = edit.connections;
            if self.commit(next) {
                editor = Editor::new(&self.settings);
                self.reconfigure();
            }
        }
        self.editor = Some(editor);
    }
}
/// Read desktop entries as data; never execute their commands or expand a shell.
fn applications() -> Vec<(String, String)> {
    let mut dirs = vec![
        PathBuf::from("/usr/share/applications"),
        PathBuf::from("/usr/local/share/applications"),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join(".local/share/applications"));
    }
    let mut apps = Vec::new();
    for dir in dirs {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten().take(2048) {
                let path = entry.path();
                if path.extension().is_none_or(|s| s != "desktop")
                    || !entry.metadata().is_ok_and(|m| m.len() <= 65536)
                {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(path) else {
                    continue;
                };
                let mut name = None;
                let mut executable = None;
                let mut active = false;
                let mut hidden = false;
                for line in text.lines() {
                    if line.starts_with('[') {
                        active = line == "[Desktop Entry]";
                    }
                    if !active {
                        continue;
                    }
                    if line == "NoDisplay=true" || line == "Hidden=true" {
                        hidden = true;
                    }
                    if let Some(s) = line.strip_prefix("Name=") {
                        name = Some(
                            s.chars()
                                .filter(|c| !c.is_control())
                                .take(80)
                                .collect::<String>(),
                        );
                    }
                    if let Some(s) = line.strip_prefix("Exec=") {
                        let program = if let Some(s) = s.strip_prefix('"') {
                            s.split('"').next().unwrap_or("")
                        } else {
                            s.split_whitespace().next().unwrap_or("")
                        };
                        if program.starts_with('/') {
                            executable = Some(program.to_owned());
                        } else if !["env", "flatpak", "sh", "bash", "xdg-open"].contains(&program) {
                            executable = ["/usr/bin", "/usr/local/bin", "/bin"]
                                .iter()
                                .map(|p| PathBuf::from(p).join(program))
                                .find(|p| p.is_file())
                                .map(|p| p.to_string_lossy().into_owned());
                        }
                    }
                }
                if !hidden
                    && let (Some(name), Some(path)) = (name, executable)
                    && Target::application(&path).is_ok()
                {
                    apps.push((name, path));
                }
            }
        }
    }
    apps.sort_by_key(|(name, _)| name.to_lowercase());
    apps.dedup();
    apps
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    struct RowHarness {
        ctx: egui::Context,
        rule: PolicyRule,
        selected: bool,
        time: f64,
    }
    impl RowHarness {
        fn new(reduced_motion: bool) -> Self {
            let ctx = egui::Context::default();
            crate::emoji::install(&ctx);
            ctx.style_mut(|s| {
                s.animation_time = if reduced_motion { 0.0 } else { 0.16 };
                s.spacing.interact_size.y = 32.0;
            });
            Self {
                ctx,
                rule: PolicyRule {
                    enabled: true,
                    target: Target::address("example.test").unwrap(),
                    action: Action::Direct,
                },
                selected: false,
                time: 0.0,
            }
        }
        fn render(&mut self, events: Vec<egui::Event>) -> (egui::FullOutput, RuleControls) {
            self.time += 0.05;
            let p = App::model(Settings::default(), None, None).palette();
            let mut row = None;
            let output = self.ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(640.0, 420.0),
                    )),
                    time: Some(self.time),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        let connections = [Connection {
                            id: 1,
                            name: "Работа".into(),
                            interface: "tun0".into(),
                            dns: Dns::Interface,
                        }];
                        row = Some(
                            rule_row(
                                ui,
                                &mut self.rule,
                                &mut self.selected,
                                &connections,
                                false,
                                p,
                            )
                            .inner,
                        );
                    });
                },
            );
            (output, row.unwrap())
        }
        fn click(&mut self, pos: egui::Pos2) -> RuleControls {
            self.render(vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                },
            ]);
            self.render(vec![egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            }])
            .1
        }
    }
    fn key(key: egui::Key, pressed: bool) -> egui::Event {
        egui::Event::Key {
            key,
            physical_key: None,
            pressed,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        }
    }
    #[test]
    fn row_selection_direction_and_enable_are_independent() {
        let mut h = RowHarness::new(false);
        let (_, controls) = h.render(vec![]);
        let initial = h.rule.clone();
        h.click(controls.select.rect.center());
        assert!(h.selected);
        assert_eq!(h.rule, initial, "selection must not edit a rule");
        h.click(controls.select.rect.center());
        assert!(!h.selected);
        h.ctx.memory_mut(|m| m.request_focus(controls.select.id));
        h.render(vec![key(egui::Key::Space, true)]);
        h.render(vec![key(egui::Key::Space, false)]);
        assert!(h.selected, "the row must remain keyboard-selectable");
        h.click(controls.enabled.rect.center());
        assert!(!h.rule.enabled && h.selected);
        h.click(controls.direction.rect.center());
        assert!(h.selected && h.rule.action == Action::Direct);
        h.render(vec![]);
        let popup = egui::Popup::menu(&controls.direction)
            .get_popup_rect()
            .unwrap();
        // The middle entry of this three-choice menu is the proxy route.
        h.click(popup.center());
        assert_eq!(h.rule.action, Action::Proxy);
        assert!(
            h.selected && !h.rule.enabled,
            "editing direction must preserve the other two states"
        );
    }
    #[test]
    fn rule_feedback_and_reduced_motion_settle_without_idle_repaints() {
        for reduced in [false, true] {
            let mut h = RowHarness::new(reduced);
            let (_, controls) = h.render(vec![]);
            h.click(controls.select.rect.center());
            h.click(controls.enabled.rect.center());
            h.render(vec![egui::Event::PointerGone]);
            for _ in 0..30 {
                h.render(vec![]);
            }
            let (output, _) = h.render(vec![]);
            assert!(
                output.viewport_output[&egui::ViewportId::ROOT].repaint_delay
                    > Duration::from_secs(60)
            );
        }
    }
    #[test]
    fn opening_a_route_menu_keeps_the_list_still_and_wheel_scrolling_works() {
        let ctx = egui::Context::default();
        crate::emoji::install(&ctx);
        let p = App::model(Settings::default(), None, None).palette();
        let mut rules = vec![
            PolicyRule {
                enabled: true,
                target: Target::address("example.test").unwrap(),
                action: Action::Direct
            };
            10
        ];
        let mut time = 0.0;
        let mut render = |events| {
            time += 0.05;
            let mut controls = Vec::new();
            let mut offset = Vec2::ZERO;
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(640.0, 420.0),
                    )),
                    time: Some(time),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        let area = egui::ScrollArea::vertical()
                            .scroll_source(RULE_SCROLL)
                            .max_height(180.0)
                            .show(ui, |ui| {
                                for (i, rule) in rules.iter_mut().enumerate() {
                                    let response = ui.push_id(i, |ui| {
                                        rule_row(ui, rule, &mut false, &[], false, p)
                                    });
                                    controls.push(response.inner.inner);
                                }
                            });
                        offset = area.state.offset;
                    });
                },
            );
            (offset, controls)
        };
        render(vec![]);
        let (_, controls) = render(vec![egui::Event::PointerMoved(egui::pos2(200.0, 160.0))]);
        let pos = controls[0].direction.rect.center();
        let (offset, _) = render(vec![
            egui::Event::PointerMoved(pos),
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::NONE,
            },
        ]);
        assert_eq!(offset.y, 0.0);
        render(vec![egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed: false,
            modifiers: egui::Modifiers::NONE,
        }]);
        for _ in 0..5 {
            assert_eq!(render(vec![]).0.y, 0.0);
        }
        render(vec![key(egui::Key::Escape, true)]);
        render(vec![key(egui::Key::Escape, false)]);
        render(vec![
            egui::Event::PointerMoved(egui::pos2(200.0, 80.0)),
            egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                delta: Vec2::new(0.0, -60.0),
                modifiers: egui::Modifiers::NONE,
            },
        ]);
        assert!(render(vec![]).0.y > 0.0);
    }
    #[test]
    fn escape_clears_selection_without_discarding_route_edits() {
        let mut settings = Settings::default();
        settings.routing_profiles[0]
            .add_addresses("example.test", Action::Direct)
            .unwrap();
        let mut editor = Editor::new(&settings);
        editor.rows.insert(0);
        editor.profiles[0].rules[0].action = Action::Proxy;
        let ctx = egui::Context::default();
        crate::emoji::install(&ctx);
        let p = App::model(Settings::default(), None, None).palette();
        let _ = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    Vec2::new(960.0, 760.0),
                )),
                events: vec![key(egui::Key::Escape, true)],
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| editor.rules(ui, p, 600.0));
            },
        );
        assert!(editor.rows.is_empty());
        assert!(editor.dirty(&settings));
        assert_eq!(editor.profiles[0].rules[0].action, Action::Proxy);
    }
    #[test]
    fn adding_rules_from_the_keyboard_works() {
        let ctx = egui::Context::default();
        crate::emoji::install(&ctx);
        let p = App::model(Settings::default(), None, None).palette();
        let mut editor = Editor::new(&Settings::default());
        editor.add = true;
        let mut time = 0.0;
        let mut render = |editor: &mut Editor, events| {
            time += 0.1;
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(960.0, 760.0),
                    )),
                    time: Some(time),
                    events,
                    ..Default::default()
                },
                |ctx| editor.add_dialog(ctx, p),
            );
        };
        render(&mut editor, vec![]);
        render(&mut editor, vec![]);
        ctx.memory_mut(|m| m.request_focus(egui::Id::new("bypass-input")));
        render(
            &mut editor,
            vec![egui::Event::Text("example.test\n*.example.test".into())],
        );
        assert_eq!(editor.input, "example.test\n*.example.test");
        let key = |key| egui::Event::Key {
            key,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        };
        for _ in 0..3 {
            render(&mut editor, vec![key(egui::Key::Tab)]);
        }
        render(&mut editor, vec![key(egui::Key::Enter)]);
        assert_eq!(editor.profiles[0].rules.len(), 2);
        assert!(!editor.add);
        assert_eq!(editor.reveal_rule, Some(0));
    }
}
