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
        } else if report.findings.iter().any(|f| f.status == Status::Error) {
            (
                "Найдены проблемы",
                "Посмотрите, что мешает соединению.",
                Status::Error,
            )
        } else if report.findings.iter().any(|f| f.status == Status::Warning) {
            (
                "Есть что проверить",
                "Причина может быть в сети или её настройках.",
                Status::Warning,
            )
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
                "Соединение работает",
                "Проверка HTTPS прошла успешно.",
                Status::Pass,
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
        ui.label(heading("Диагностика", 26.0));
        ui.label(RichText::new("Узнайте, что мешает подключению.").color(p.muted));
        ui.add_space(22.0);
        egui::ScrollArea::vertical()
            .id_salt("diagnostics-page")
            .show(ui, |ui| {
                self.diagnostic_controls(ui, ctx, p);
                if let Some(error) = &self.diagnostics.repair_error {
                    ui.add_space(12.0);
                    ui.colored_label(p.error, error);
                }
                if let Some(notice) = &self.diagnostics.notice {
                    ui.add_space(10.0);
                    ui.label(RichText::new(notice).color(p.muted));
                }
                if self.diagnostics.report.is_some() || self.diagnostics.busy() {
                    ui.add_space(26.0);
                    let (title, subtitle, status) = summary(&self.diagnostics);
                    ui.horizontal_top(|ui| {
                        status_symbol(ui, status, p, 34.0);
                        ui.add_space(6.0);
                        ui.vertical(|ui| {
                            ui.label(heading(title, 21.0));
                            if !subtitle.is_empty() {
                                ui.label(RichText::new(subtitle).color(p.muted));
                            }
                        });
                    });
                }
                if self.diagnostics.busy() {
                    ui.add_space(12.0);
                    ui.label(
                        RichText::new(&self.diagnostics.progress)
                            .small()
                            .color(p.muted),
                    );
                }
                // Only the small visible subset needs owning across UI actions.
                let mut findings: Vec<_> = self
                    .diagnostics
                    .report
                    .as_ref()
                    .into_iter()
                    .flat_map(|r| r.findings.iter().enumerate())
                    .filter(|(_, f)| needs_attention(f))
                    .map(|(i, f)| (i, f.clone()))
                    .collect();
                findings.sort_by_key(|(_, f)| match f.status {
                    Status::Error => 0,
                    Status::Warning => 1,
                    _ => 2,
                });
                if !findings.is_empty() {
                    ui.add_space(20.0);
                    egui::Frame::new()
                        .fill(p.card)
                        .corner_radius(12)
                        .inner_margin(16)
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            for (i, (index, finding)) in findings.iter().enumerate() {
                                if i > 0 {
                                    ui.add_space(8.0);
                                    ui.separator();
                                    ui.add_space(8.0);
                                }
                                self.diagnostic_row(ui, ctx, finding, *index, p, false);
                            }
                        });
                }
                if self.diagnostics.report.is_some() {
                    ui.add_space(16.0);
                    if command(
                        ui,
                        "Технические сведения →",
                        ButtonTone::Quiet,
                        Vec2::ZERO,
                        p,
                    )
                    .clicked()
                    {
                        self.diagnostics.open_technical();
                        self.navigate(Page::Information, ctx);
                    }
                }
            });
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

    fn diagnostic_row(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        finding: &Finding,
        index: usize,
        p: Palette,
        technical: bool,
    ) {
        ui.push_id(("diagnostic-row", technical, index, &finding.id), |ui| {
            let title = if technical {
                finding.title.as_str()
            } else {
                user_title(finding)
            };
            disclosure(ui, "finding", RichText::new(title).strong(), None, |ui| {
                if !finding.detail.is_empty() {
                    ui.label(&finding.detail);
                }
                if !finding.advice.is_empty() {
                    ui.add_space(6.0);
                    ui.label(RichText::new(&finding.advice).color(p.muted));
                }
                // Existing confirmed actions stay inside their finding;
                // this presentation change adds no repair capability.
                if let Some(action) = &finding.action {
                    ui.add_space(8.0);
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
                        match action {
                            Action::OpenRoutes => self.navigate(Page::Routes, ctx),
                            Action::OpenSettings => self.navigate(Page::Settings, ctx),
                            _ => self.diagnostics.confirmation = Some(action.clone()),
                        }
                    }
                }
            });
            if !technical {
                ui.label(
                    RichText::new(user_hint(finding))
                        .small()
                        .color(status_color(finding.status, p)),
                );
            }
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
        egui::ScrollArea::vertical().id_salt("information-page").show(ui, |ui| {
            for (question, answer) in [
                ("Как проверить соединение?", "Откройте «Диагностика» → «Доступ к сайту» и нажмите «Проверить». Можно указать сайт, который не открывается."),
                ("Можно проверить сеть без интернета?", "Да. Режим «На устройстве» проверяет местные настройки DNS, маршруты и Eivro. Запросы к сайтам не отправляются."),
                ("Приложение изменит мои настройки?", "Сама проверка ничего не меняет. Доступные действия выполняются только после отдельного подтверждения."),
                ("Какие данные попадают в отчёт?", "Только версия Eivro, названия проверок и результаты. Адреса, ключи и ссылки подписок исключены. Перед копированием доступен просмотр."),
            ] {
                disclosure(ui, question, RichText::new(question).strong(), None, |ui| {
                    ui.label(RichText::new(answer).color(p.muted));
                });
                ui.add_space(8.0);
            }
            ui.add_space(16.0);
            ui.separator();
            ui.add_space(16.0);
            let open = std::mem::take(&mut self.diagnostics.show_technical).then_some(true);
            disclosure(ui, "technical-evidence", heading("Технические сведения", 18.0), open, |ui| {
                if let Some(report) = self.diagnostics.report.clone() {
                    ui.label(RichText::new(if self.diagnostics.stale { "Сохранённый результат устарел. Повторите диагностику." } else if report.cancelled { "Проверка была отменена. Сведения неполные." } else { "Последняя проверка. Справочные пункты сами по себе не означают неисправность." }).small().color(p.muted));
                    ui.add_space(10.0);
                    if command(ui, "Просмотреть отчёт…", ButtonTone::Secondary, Vec2::ZERO, p).clicked() {
                        let mut text = report.sanitized_text();
                        if self.diagnostics.stale { text.push_str("Результат устарел.\n"); }
                        self.diagnostics.export = Some(text);
                    }
                    ui.add_space(14.0);
                    for (index, finding) in report.findings.iter().enumerate() {
                        ui.label(RichText::new(status_label(finding.status)).small().color(status_color(finding.status, p)));
                        self.diagnostic_row(ui, ctx, finding, index, p, true);
                        ui.add_space(8.0);
                    }
                } else {
                    ui.label(RichText::new("Здесь появится результат диагностики.").color(p.muted));
                    ui.add_space(8.0);
                    if command(ui, "Открыть диагностику", ButtonTone::Secondary, Vec2::ZERO, p).clicked() {
                        self.navigate(Page::Diagnostics, ctx);
                    }
                }
            });
        });
    }
}

fn user_title(finding: &Finding) -> &str {
    match finding.id.as_str() {
        "nm_dns" | "resolver" | "dns_route" => "Проверьте настройки DNS",
        "uplink" | "routes4" | "routes6" => "Проверьте подключение к сети",
        "settings_file" => "Не удалось проверить настройки Eivro",
        "firewall" => "Нужна проверка сетевого фильтра",
        "endpoint_route" | "target_route" | "policy" => "Нужна проверка маршрута",
        "dns_probe" => "Не удалось получить адрес сайта",
        "core" | "xray" | "helper" => "Проверьте компоненты Eivro",
        _ => &finding.title,
    }
}

fn user_hint(finding: &Finding) -> &'static str {
    match finding.status {
        Status::Error => "Ошибка",
        Status::Warning => "Рекомендация",
        _ => "Можно повторить проверку",
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
        assert_eq!(summary(&state).0, "Соединение работает");
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
