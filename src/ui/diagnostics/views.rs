use super::*;

// Native collapsing bodies, with a wrapping, keyboard-operable header. egui's
// stock CollapsingHeader extends long titles beyond narrow/zoomed windows.
fn disclosure(
    ui: &mut egui::Ui,
    salt: impl std::hash::Hash,
    title: RichText,
    open: Option<bool>,
    body: impl FnOnce(&mut egui::Ui),
) {
    let id = ui.make_persistent_id(salt);
    let mut state =
        egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, false);
    if let Some(open) = open {
        state.set_open(open);
    }
    let mut clicked = false;
    let mut header = state.show_header(ui, |ui| {
        clicked = ui
            .add(
                egui::Button::new(title)
                    .frame(false)
                    .wrap()
                    .right_text("")
                    .min_size(Vec2::new(ui.available_width(), 30.0)),
            )
            .clicked();
    });
    if clicked {
        header.toggle();
    }
    header.body(body);
}

// Unknown evidence remains available without presenting a coverage limitation
// as a fault. A requested access probe that did not finish still needs attention.
fn needs_attention(finding: &Finding) -> bool {
    matches!(finding.status, Status::Error | Status::Warning)
        || (finding.status == Status::Unknown && matches!(finding.id.as_str(), "https" | "direct"))
}

pub(super) fn summary(state: &State) -> (String, String, Status) {
    let result = if state.busy() && state.repairing {
        (
            "Выполняем действие",
            "Дождитесь завершения.",
            Status::Unknown,
        )
    } else if state.busy() {
        ("Проверяем…", "", Status::Unknown)
    } else if state.stale {
        (
            "Повторите проверку",
            "Сеть или параметры проверки изменились.",
            Status::Unknown,
        )
    } else if let Some(report) = &state.report {
        if report.cancelled {
            (
                "Проверка отменена",
                "Можно запустить её снова.",
                Status::Unknown,
            )
        } else if let Some(f) =
            primary_finding(report).filter(|f| matches!(f.status, Status::Error | Status::Warning))
        {
            let (title, hint) = next_step(f);
            (title, hint, f.status)
        } else if state.last_network_tests
            && (!report.findings.iter().any(|f| f.id == "https")
                || report.findings.iter().any(|f| {
                    matches!(f.id.as_str(), "https" | "direct" | "state")
                        && f.status == Status::Unknown
                }))
        {
            (
                "Проверку доступа нужно повторить",
                "Не удалось получить результат всех запросов.",
                Status::Unknown,
            )
        } else if state.last_network_tests
            && report
                .findings
                .iter()
                .any(|f| f.id == "https" && f.status == Status::Pass)
        {
            (
                "Сайт отвечает",
                "Получен ответ по защищённому соединению.",
                Status::Pass,
            )
        } else if report
            .findings
            .iter()
            .any(|f| f.id == "state" && f.status == Status::Unknown)
        {
            (
                "Не удалось завершить проверку",
                "Повторите проверку.",
                Status::Unknown,
            )
        } else if report.findings.iter().any(|f| f.status == Status::Pass) {
            (
                "Проверка завершена",
                "В проверенных настройках проблем не найдено.",
                Status::Unknown,
            )
        } else {
            (
                "Недостаточно данных",
                "Повторите проверку. Подробности — в разделе «Информация».",
                Status::Unknown,
            )
        }
    } else {
        ("", "", Status::Unknown)
    };
    (result.0.into(), result.1.into(), result.2)
}

impl App {
    pub(in crate::ui) fn diagnostics_page(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        p: Palette,
    ) {
        ui.horizontal_wrapped(|ui| {
            ui.label(heading("Диагностика", 26.0));
            let (rect, badge) = ui.allocate_exact_size(design::BETA_SIZE, egui::Sense::hover());
            design::paint_beta(ui, rect, p);
            badge.widget_info(|| {
                egui::WidgetInfo::labeled(
                    egui::WidgetType::Label,
                    true,
                    design::DIAGNOSTICS_BETA_HINT,
                )
            });
            badge.on_hover_text(design::DIAGNOSTICS_BETA_HINT);
        });
        ui.add_space(22.0);
        egui::ScrollArea::vertical()
            .id_salt("diagnostics-page")
            .show(ui, |ui| {
                if self.diagnostics.report.is_some()
                    && !self.diagnostics.editing_check
                    && !self.diagnostics.busy()
                {
                    self.connection_report(ui, ctx, p);
                } else {
                    if self.diagnostics.report.is_some()
                        && !self.diagnostics.busy()
                        && command(ui, "← К результату", ButtonTone::Quiet, Vec2::ZERO, p).clicked()
                    {
                        self.diagnostics.editing_check = false;
                    }
                    self.diagnostic_controls(ui, ctx, p);
                    if self.diagnostics.busy() {
                        ui.add_space(12.0);
                        ui.label(RichText::new(&self.diagnostics.progress).color(p.muted));
                    }
                }
                if let Some(error) = &self.diagnostics.repair_error {
                    ui.add_space(12.0);
                    ui.colored_label(p.error, error);
                }
                if let Some(notice) = &self.diagnostics.notice {
                    ui.add_space(10.0);
                    ui.label(RichText::new(notice).color(p.muted));
                }
            });
    }

    fn connection_report(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, p: Palette) {
        let (title, subtitle, status) = summary(&self.diagnostics);
        let report = self
            .diagnostics
            .report
            .as_ref()
            .expect("result view requires a report");
        let current = !self.diagnostics.stale && !report.cancelled;
        let first = if current {
            primary_finding(report)
        } else {
            None
        };
        let stage = first.map_or(Stage::Device, |f| Stage::for_id(&f.id));
        let mut next = None;
        let mut retry = false;
        let mut edit = false;
        egui::Frame::new()
            .fill(p.card)
            .corner_radius(14)
            .inner_margin(20)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                let tint = status_color(status, p);
                ui.horizontal_wrapped(|ui| {
                    let (rect, _) =
                        ui.allocate_exact_size(Vec2::new(19.0, 10.0), egui::Sense::hover());
                    ui.painter().line_segment(
                        [rect.left_center(), rect.right_center()],
                        Stroke::new(2.5_f32, tint),
                    );
                    ui.label(
                        RichText::new(if self.diagnostics.last_network_tests {
                            "Доступ к сайту"
                        } else {
                            "На устройстве"
                        })
                        .small()
                        .strong()
                        .color(p.muted),
                    );
                });
                ui.add_space(8.0);
                ui.label(heading(title, 28.0));
                if !subtitle.is_empty() {
                    ui.label(RichText::new(subtitle).color(p.muted));
                }
                if current {
                    ui.add_space(20.0);
                    stage_path(ui, report, self.diagnostics.last_network_tests, p);
                }
                if let Some(action) = first.and_then(|f| f.action.as_ref()) {
                    ui.add_space(14.0);
                    if enabled_command(
                        ui,
                        self.diagnostics_action_available(action),
                        action_label(action),
                        ButtonTone::Secondary,
                        Vec2::ZERO,
                        p,
                    )
                    .clicked()
                    {
                        next = Some(action.clone());
                    }
                }
                ui.add_space(18.0);
                ui.horizontal_wrapped(|ui| {
                    retry = enabled_command(
                        ui,
                        !self.diagnostics_session_busy(),
                        "Проверить снова",
                        if current && first.is_some_and(|f| f.action.is_some()) {
                            ButtonTone::Secondary
                        } else {
                            ButtonTone::Primary
                        },
                        Vec2::ZERO,
                        p,
                    )
                    .clicked();
                    edit = command(ui, "Изменить проверку", ButtonTone::Quiet, Vec2::ZERO, p)
                        .clicked();
                });
            });
        ui.add_space(12.0);
        if command(ui, "Подробный отчёт →", ButtonTone::Quiet, Vec2::ZERO, p).clicked()
        {
            self.diagnostics.open_technical();
            self.diagnostics.evidence_stage = stage;
            self.navigate(Page::Information, ctx);
        } else if let Some(action) = next {
            self.diagnostic_action(action, ctx);
        } else if retry && self.diagnostics.stale {
            // The edited target or path may now differ from the old report.
            // Present the selected settings before sending any new requests.
            self.diagnostics.editing_check = true;
        } else if retry {
            self.start_diagnostics_with(ctx, !self.diagnostics.last_network_tests);
        } else if edit {
            self.diagnostics.editing_check = true;
        }
    }

    fn diagnostic_action(&mut self, action: Action, ctx: &egui::Context) {
        if !self.diagnostics_action_available(&action) {
            return;
        }
        match action {
            Action::OpenRoutes => self.navigate(Page::Routes, ctx),
            Action::OpenSettings => self.navigate(Page::Settings, ctx),
            _ => self.diagnostics.confirmation = Some(action),
        }
    }

    fn diagnostic_controls(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, p: Palette) {
        let busy = self.diagnostics.busy();
        let session_busy = self.diagnostics_session_busy();
        let before = (
            self.diagnostics.network_tests,
            self.diagnostics.direct_test,
            self.diagnostics.address.clone(),
        );
        egui::Frame::new().fill(p.card).corner_radius(12).inner_margin(18).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.add_enabled_ui(!busy, |ui| {
                egui::Frame::new().fill(p.raised).corner_radius(10).inner_margin(4).show(ui, |ui| {
                    let narrow = ui.available_width() < 340.0;
                    let width = if narrow { ui.available_width() } else { (ui.available_width() - 6.0) / 2.0 };
                    let buttons = |ui: &mut egui::Ui| {
                        ui.spacing_mut().item_spacing.x = 6.0;
                        for (network, label) in [(false, "На устройстве"), (true, "Доступ к сайту")] {
                            if command(ui, label, ButtonTone::Segment(self.diagnostics.network_tests == network), Vec2::new(width, 40.0), p).clicked() {
                                self.diagnostics.network_tests = network;
                            }
                        }
                    };
                    if narrow { ui.vertical(buttons); } else { ui.horizontal(buttons); }
                });
                ui.add_space(12.0);
                let address_field = |ui: &mut egui::Ui, address: &mut String| {
                    ui.add(egui::TextEdit::singleline(address)
                        .id_salt("diagnostics-address")
                        .hint_text("Домен или IP-адрес")
                        .margin(egui::Margin::symmetric(12, 10))
                        .desired_width(f32::INFINITY).char_limit(253));
                };
                if self.diagnostics.network_tests {
                    address_field(ui, &mut self.diagnostics.address);
                    ui.add_space(6.0);
                    ui.label(RichText::new("Настройки сети и короткий запрос к сайту. Без адреса — example.com.").small().color(p.muted));
                    ui.add_space(4.0);
                    #[cfg(target_os="linux")]
                    egui::CollapsingHeader::new("Дополнительно").id_salt("diagnostics-advanced").show(ui, |ui| {
                        if self.settings.kill_switch { self.diagnostics.direct_test = false; }
                        ui.add_enabled(!self.settings.kill_switch, egui::Checkbox::new(&mut self.diagnostics.direct_test, "Сравнить с доступом вне VPN"));
                        ui.label(RichText::new(if self.settings.kill_switch {
                            "Недоступно при включённой блокировке трафика вне VPN."
                        } else {
                            "Добавит запрос через физическое подключение, в обход Eivro."
                        }).small().color(p.muted));
                    });
                } else {
                    ui.label(RichText::new("Сеть, DNS и настройки Eivro. Без запросов в интернет.").color(p.muted));
                    egui::CollapsingHeader::new("Проверить правило для адреса")
                        .id_salt("local-rule-address")
                        .show(ui, |ui| address_field(ui, &mut self.diagnostics.address));
                }
            });
            if before != (self.diagnostics.network_tests, self.diagnostics.direct_test, self.diagnostics.address.clone()) {
                self.diagnostics.invalidate_and_cancel();
            }
            ui.add_space(18.0);
            ui.horizontal_wrapped(|ui| {
                if busy {
                    ui.spinner();
                    let cancelling = self.diagnostics.cancel.as_ref().is_some_and(|c| c.load(Ordering::Relaxed));
                    if enabled_command(ui, !cancelling, if cancelling { "Отменяем…" } else { "Отменить" }, ButtonTone::Secondary, Vec2::new(160.0, 40.0), p).clicked() {
                        self.diagnostics.cancel_by_user();
                    }
                } else {
                    let label = if self.diagnostics.report.is_some() { "Проверить снова" } else { "Проверить" };
                    if enabled_command(ui, !session_busy, label, ButtonTone::Primary, Vec2::new(160.0, 40.0), p).clicked() {
                        self.start_diagnostics(ctx);
                    }
                    ui.label(RichText::new(if session_busy { "Подключение меняется…" } else { "Настройки не изменятся" }).small().color(p.muted));
                }
            });
        });
    }

    pub(in crate::ui) fn information_page(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        p: Palette,
    ) {
        ui.label(heading("Информация", 26.0));
        ui.label(RichText::new(format!("Eivro {}", env!("CARGO_PKG_VERSION"))).color(p.muted));
        ui.add_space(22.0);
        egui::ScrollArea::vertical()
            .id_salt("information-page")
            .show(ui, |ui| {
                if self.diagnostics.report.is_none() {
                    ui.label(RichText::new("Результатов проверки пока нет.").color(p.muted));
                    ui.add_space(12.0);
                    if command(
                        ui,
                        "Открыть диагностику",
                        ButtonTone::Secondary,
                        Vec2::ZERO,
                        p,
                    )
                    .clicked()
                    {
                        self.navigate(Page::Diagnostics, ctx);
                    }
                    return;
                }
                if self.diagnostics.stale {
                    ui.label(RichText::new("Сеть изменилась. Повторите проверку.").color(p.muted));
                } else if self
                    .diagnostics
                    .report
                    .as_ref()
                    .is_some_and(|r| r.cancelled)
                {
                    ui.label(
                        RichText::new("Проверка отменена. Результат частичный.").color(p.muted),
                    );
                }
                if command(
                    ui,
                    "Отчёт для отправки…",
                    ButtonTone::Secondary,
                    Vec2::ZERO,
                    p,
                )
                .clicked()
                {
                    self.diagnostics.open_export();
                }
                ui.add_space(16.0);
                let open = std::mem::take(&mut self.diagnostics.show_technical).then_some(true);
                let mut next = None;
                disclosure(
                    ui,
                    "technical-evidence",
                    heading("Детали проверки", 18.0),
                    open,
                    |ui| {
                        ui.add_space(8.0);
                        ui.horizontal_wrapped(|ui| {
                            for stage in Stage::ALL {
                                ui.selectable_value(
                                    &mut self.diagnostics.evidence_stage,
                                    stage,
                                    stage.title(),
                                );
                            }
                        });
                        ui.add_space(10.0);
                        let stage = self.diagnostics.evidence_stage;
                        let report = self
                            .diagnostics
                            .report
                            .as_ref()
                            .expect("information has report");
                        let mut empty = true;
                        for f in report
                            .findings
                            .iter()
                            .filter(|f| Stage::for_id(&f.id) == stage)
                        {
                            if !empty {
                                ui.add_space(8.0);
                                ui.separator();
                                ui.add_space(8.0);
                            }
                            empty = false;
                            ui.label(RichText::new(&f.title).strong());
                            ui.label(
                                RichText::new(status_label(f.status))
                                    .small()
                                    .color(status_color(f.status, p)),
                            );
                            if !f.detail.is_empty() {
                                ui.label(RichText::new(&f.detail).color(p.muted));
                            }
                            if needs_attention(f) && !f.advice.is_empty() {
                                ui.label(&f.advice);
                            }
                            if needs_attention(f)
                                && let Some(action) = &f.action
                                && enabled_command(
                                    ui,
                                    self.diagnostics_action_available(action),
                                    action_label(action),
                                    ButtonTone::Secondary,
                                    Vec2::ZERO,
                                    p,
                                )
                                .clicked()
                            {
                                next = Some(action.clone());
                            }
                        }
                        if empty {
                            ui.label(
                                RichText::new("Для этого раздела нет результатов.").color(p.muted),
                            );
                        }
                    },
                );
                if let Some(action) = next {
                    self.diagnostic_action(action, ctx);
                }
            });
    }
}

/// The main path is a summary of independent observations, not a causal trace.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub(super) enum Stage {
    #[default]
    Device,
    Client,
    Site,
}
impl Stage {
    const ALL: [Self; 3] = [Self::Device, Self::Client, Self::Site];
    fn title(self) -> &'static str {
        match self {
            Self::Device => "Устройство",
            Self::Client => "Eivro",
            Self::Site => "Сайт",
        }
    }
    fn for_id(id: &str) -> Self {
        match id {
            "https" | "direct" | "dns_probe" | "target_route" | "rule" | "scope" => Self::Site,
            "core" | "xray" | "helper" | "profile" | "exit" | "settings_file" | "subscription"
            | "proxy_port" | "system_proxy" | "tun" | "fakeip" | "endpoint" | "endpoint_route" => {
                Self::Client
            }
            _ => Self::Device,
        }
    }
    fn result(self, report: &Report, network: bool) -> (Status, &'static str) {
        let rows = || {
            report
                .findings
                .iter()
                .filter(|f| Self::for_id(&f.id) == self)
        };
        if rows().any(|f| f.status == Status::Error) {
            return (Status::Error, "Есть проблема");
        }
        if rows().any(|f| f.status == Status::Warning) {
            return (Status::Warning, "Есть замечание");
        }
        if self == Self::Site {
            if !network {
                return (Status::Unknown, "Без запроса");
            }
            if rows()
                .any(|f| matches!(f.id.as_str(), "direct" | "https") && f.status == Status::Unknown)
                || report
                    .findings
                    .iter()
                    .any(|f| f.id == "state" && f.status == Status::Unknown)
            {
                return (Status::Unknown, "Неполный результат");
            }
            if rows().any(|f| f.id == "https" && f.status == Status::Pass) {
                return (Status::Pass, "Получен ответ");
            }
            return (Status::Unknown, "Нет ответа проверки");
        }
        if rows().any(|f| f.status == Status::Pass) {
            (Status::Pass, "Есть данные")
        } else {
            (Status::Unknown, "Нет данных")
        }
    }
}

fn primary_finding(report: &Report) -> Option<&Finding> {
    report
        .findings
        .iter()
        .filter(|f| needs_attention(f))
        .min_by_key(|f| {
            let impact = match f.status {
                Status::Error => 0,
                Status::Warning => 1,
                _ => 2,
            };
            // Prefer an actionable observation over a later symptom of the same issue.
            (
                impact,
                f.action.is_none(),
                matches!(f.id.as_str(), "https" | "direct"),
            )
        })
}

fn next_step(f: &Finding) -> (&str, &str) {
    match (&f.action, f.id.as_str()) {
        (Some(Action::RestoreDns { .. }), _) => (
            "У сети не указан DNS",
            "Можно вернуть адреса из сохранённых настроек сети.",
        ),
        (Some(Action::RecoverProxy), _) => (
            "В системе остались настройки прокси",
            "Проверьте параметры, оставшиеся от предыдущего сеанса Eivro.",
        ),
        (Some(Action::Reconnect), _) => (
            "Проверьте подключение Eivro",
            "Сеанс можно запустить заново и повторить проверку.",
        ),
        (_, "exit") => (
            "Проверьте сеть, выбранную в правилах",
            "Подключите нужную сеть или выберите другой выход для этого правила.",
        ),
        (_, "uplink" | "routes4") => (
            "Проверьте подключение устройства",
            "Проверьте Wi-Fi, кабель и другие запущенные VPN.",
        ),
        (_, "resolver" | "nm_dns" | "dns_route" | "dns_probe") => (
            "Проверьте, как устройство находит сайты",
            "Откройте настройки DNS активной сети и повторите проверку.",
        ),
        (_, "profile" | "subscription") => (
            "Проверьте выбранный сервер",
            "Посмотрите данные подписки и выберите доступный сервер.",
        ),
        (_, "core" | "xray" | "helper") => (
            "Проверьте установку Eivro",
            "Проверьте, установлены ли приложение и его компоненты из одной сборки.",
        ),
        (_, "https" | "direct") if f.status == Status::Unknown => (
            "Попробуйте ещё раз",
            "Для выбранного пути пока недостаточно данных.",
        ),
        (_, "https" | "direct") => ("Ответ сайта требует внимания", &f.detail),
        (_, "policy" | "target_route" | "rule" | "endpoint_route") => (
            "Проверьте правила подключения",
            "Убедитесь, что для нужного адреса выбран доступный выход.",
        ),
        (_, "routes6") => (
            "Проверьте дополнительный сетевой маршрут",
            "Подробности доступны в разделе устройства.",
        ),
        _ => (&f.title, &f.advice),
    }
}

// The export preview only derives from the already sanitized, immutable text.
// Present it as a reproducible document. Never substitute local report evidence.
pub(super) fn export_preview(ui: &mut egui::Ui, text: &str, p: Palette) {
    egui::Frame::new()
        .fill(p.raised)
        .corner_radius(10)
        .inner_margin(14)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            for line in text.lines() {
                match line {
                    "" => ui.add_space(8.0),
                    "Ошибка" | "Внимание" | "В порядке" | "Справочно" =>
                    {
                        let color = match line {
                            "Ошибка" => p.error,
                            "Внимание" => status_color(Status::Warning, p),
                            "В порядке" => p.accent,
                            _ => p.muted,
                        };
                        ui.label(RichText::new(line).strong().color(color));
                    }
                    _ => {
                        ui.label(line);
                    }
                }
            }
        });
}

fn stage_path(ui: &mut egui::Ui, report: &Report, network: bool, p: Palette) {
    let wide = ui.available_width() >= 370.0;
    let stage = |ui: &mut egui::Ui, group: Stage, last: bool| {
        let (status, label) = group.result(report, network);
        let color = status_color(status, p);
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(16.0), egui::Sense::hover());
            let dot = rect.center();
            ui.painter()
                .circle_stroke(dot, 6.0, Stroke::new(1.5_f32, color));
            if status == Status::Pass {
                ui.painter().circle_filled(dot, 3.0, color);
            }
            ui.label(RichText::new(group.title()).strong());
            if wide && !last && ui.available_width() > 8.0 {
                let (rect, _) = ui.allocate_exact_size(
                    Vec2::new(ui.available_width() - 4.0, 14.0),
                    egui::Sense::hover(),
                );
                ui.painter().line_segment(
                    [rect.left_center(), rect.right_center()],
                    Stroke::new(1.0_f32, p.line),
                );
            }
            if !wide {
                ui.label(RichText::new(label).small().color(color));
            }
        });
        if wide {
            ui.label(RichText::new(label).small().color(color));
        }
    };
    if wide {
        ui.columns(3, |columns| {
            for (i, (ui, group)) in columns.iter_mut().zip(Stage::ALL).enumerate() {
                stage(ui, group, i == 2);
            }
        });
    } else {
        for group in Stage::ALL {
            stage(ui, group, true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: &str, status: Status) -> Finding {
        Finding {
            id: id.into(),
            status,
            title: "Test".into(),
            detail: String::new(),
            advice: String::new(),
            action: None,
        }
    }

    #[test]
    fn coverage_limits_stay_in_details_but_incomplete_access_stays_visible() {
        for id in [
            "nm_dns",
            "subscription",
            "firewall",
            "endpoint_route",
            "scope",
        ] {
            assert!(!needs_attention(&finding(id, Status::Unknown)));
        }
        assert!(needs_attention(&finding("https", Status::Unknown)));
        assert!(needs_attention(&finding("resolver", Status::Error)));
        assert!(needs_attention(&finding("target_route", Status::Warning)));
    }

    #[test]
    fn success_requires_finished_access_checks_and_never_masks_a_fault() {
        let mut state = State::default();
        state.last_network_tests = true;
        state.report = Some(Report {
            findings: vec![
                finding("https", Status::Pass),
                finding("firewall", Status::Unknown),
            ],
            ..Default::default()
        });
        assert_eq!(summary(&state).0, "Сайт отвечает");
        // The time budget can run out after the proxy responds but before
        // the system TUN probe starts, leaving no second HTTPS finding.
        state
            .report
            .as_mut()
            .unwrap()
            .findings
            .push(finding("state", Status::Unknown));
        assert_eq!(summary(&state).2, Status::Unknown);
        state.report.as_mut().unwrap().findings.pop();
        state
            .report
            .as_mut()
            .unwrap()
            .findings
            .push(finding("https", Status::Unknown));
        assert_eq!(summary(&state).2, Status::Unknown);
        state
            .report
            .as_mut()
            .unwrap()
            .findings
            .push(finding("resolver", Status::Error));
        assert_eq!(summary(&state).2, Status::Error);
        state.stale = true;
        assert_eq!(summary(&state).0, "Повторите проверку");
    }

    #[test]
    fn local_result_does_not_claim_internet_access() {
        let mut state = State::default();
        state.report = Some(Report {
            findings: vec![finding("resolver", Status::Pass)],
            ..Default::default()
        });
        assert_eq!(summary(&state).0, "Проверка завершена");
        assert!(summary(&state).1.contains("проверенных настройках"));
    }

    #[test]
    fn local_timeout_supersedes_partial_success_but_optional_evidence_does_not() {
        let mut state = State::default();
        state.report = Some(Report {
            findings: vec![
                finding("resolver", Status::Pass),
                finding("firewall", Status::Unknown),
            ],
            ..Default::default()
        });
        assert_eq!(summary(&state).0, "Проверка завершена");
        state
            .report
            .as_mut()
            .unwrap()
            .findings
            .push(finding("state", Status::Unknown));
        assert_eq!(
            summary(&state),
            (
                "Не удалось завершить проверку".into(),
                "Повторите проверку.".into(),
                Status::Unknown
            )
        );
    }

    #[test]
    fn information_opens_details_without_starting_a_check_and_wraps_on_narrow_windows() {
        let mut app = App::model(Settings::default(), None, None);
        let mut evidence = finding("firewall", Status::Unknown);
        evidence.title =
            "Длинное название технического результата, которое должно переноситься внутри окна"
                .into();
        app.diagnostics.report = Some(Report {
            findings: vec![evidence],
            ..Default::default()
        });
        app.diagnostics.open_technical();
        let ctx = egui::Context::default();
        crate::emoji::install(&ctx);
        for pass in 0..3 {
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(320.0, 760.0),
                    )),
                    time: Some(pass as f64),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        let right = ui.max_rect().right();
                        app.information_page(ui, ctx, app.palette());
                        assert!(ui.min_rect().right() <= right + 1.0);
                    });
                },
            );
        }
        assert!(!app.diagnostics.show_technical);
        assert!(!app.diagnostics.busy());
    }
}
