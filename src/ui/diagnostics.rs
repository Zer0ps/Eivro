use super::design::{ButtonTone, command, enabled_command, heading, mix, modal};
use super::*;
use eivro::diagnostics::{self as engine, Action, Finding, Report, Request, Status};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Default)]
pub(super) struct State {
    report: Option<Report>,
    context: Option<Context>,
    receiver: Option<Receiver<Message>>,
    cancel: Option<Arc<AtomicBool>>,
    user_cancelled: bool,
    repairing: bool,
    progress: String,
    stale: bool,
    network_tests: bool,
    last_network_tests: bool,
    direct_test: bool,
    address: String,
    confirmation: Option<Action>,
    export: Option<String>,
    notice: Option<String>,
    repair_error: Option<String>,
    recheck_when_idle: bool,
}

struct Context {
    settings: Settings,
    running: bool,
    wanted: bool,
    session: bool,
    stopping: bool,
}

enum Message {
    Progress(String),
    Report(Report),
    Repaired(eivro::Result<()>),
    ReconnectReady(eivro::Result<()>),
}

impl State {
    pub(super) fn has_context(&self) -> bool {
        self.context.is_some()
    }

    pub(super) fn invalidate(&mut self) {
        if self.has_context() {
            self.stale = true;
            self.confirmation = None;
            // A confirmed repair can emit its own DNS/link notification. Its
            // transaction revalidates the network before committing changes.
            if !self.repairing {
                self.cancel();
            }
        }
    }

    pub(super) fn invalidate_and_cancel(&mut self) {
        self.invalidate();
        self.cancel();
    }

    fn cancel(&self) {
        if let Some(cancel) = &self.cancel {
            cancel.store(true, Ordering::Relaxed);
        }
    }

    fn cancel_by_user(&mut self) {
        self.user_cancelled = true;
        self.cancel();
    }

    fn busy(&self) -> bool {
        self.receiver.is_some()
    }

    pub(super) fn modal_open(&self) -> bool {
        self.confirmation.is_some() || self.export.is_some()
    }

    fn actionable(&self) -> bool {
        !self.busy() && !self.stale && self.report.as_ref().is_some_and(|r| !r.cancelled)
    }
}

impl Drop for State {
    fn drop(&mut self) {
        self.cancel();
    }
}

impl Context {
    fn capture(app: &App) -> Self {
        Self {
            settings: app.settings.clone(),
            running: app.running,
            wanted: app.want_connected,
            session: app.session.is_some(),
            stopping: app.stopping,
        }
    }

    fn matches(&self, app: &App) -> bool {
        // Called on UI frames: compare the saved inputs, without reparsing URI
        // configurations or allocating gateway sets during animations.
        self.settings.mode == app.settings.mode
            && self.settings.port == app.settings.port
            && self.settings.kill_switch == app.settings.kill_switch
            && self.settings.selected_profile().map(|p| &p.uri)
                == app.settings.selected_profile().map(|p| &p.uri)
            && self
                .settings
                .routing_profiles
                .get(self.settings.selected_routing)
                .map(|p| (&p.rules, &p.ru_preset))
                == app
                    .settings
                    .routing_profiles
                    .get(app.settings.selected_routing)
                    .map(|p| (&p.rules, &p.ru_preset))
            && self.settings.connections == app.settings.connections
            && self.running == app.running
            && self.wanted == app.want_connected
            && self.session == app.session.is_some()
            && self.stopping == app.stopping
    }
}

impl App {
    pub(super) fn diagnostics_connection_blocked(&mut self) -> bool {
        if !self.diagnostics.repairing || !self.diagnostics.busy() {
            return false;
        }
        // Cancellation can arrive after COMMIT; wait for the worker to release
        // the helper lock before a new session can acquire it.
        self.diagnostics.invalidate_and_cancel();
        self.diagnostics.cancel_by_user();
        self.diagnostics.recheck_when_idle = false;
        self.want_connected = false;
        self.error = Some("Дождитесь завершения исправления и повторите подключение.".into());
        true
    }

    fn diagnostics_session_busy(&self) -> bool {
        self.quitting
            || self.stopping
            || self.install_result.is_some()
            || (self.session.is_some() && !self.running)
            || self.recovery.due.is_some()
    }

    fn start_diagnostics(&mut self, ctx: &egui::Context) {
        self.start_diagnostics_with(ctx, false);
    }

    fn start_diagnostics_with(&mut self, ctx: &egui::Context, local_only: bool) {
        if self.diagnostics.busy() || self.diagnostics_session_busy() {
            return;
        }
        let request = Request {
            settings: self.settings.clone(),
            connected: self.running,
            busy: self.diagnostics_session_busy(),
            network_tests: !local_only && self.diagnostics.network_tests,
            direct_test: !local_only
                && self.diagnostics.network_tests
                && self.diagnostics.direct_test
                && !self.settings.kill_switch,
            address: (!self.diagnostics.address.trim().is_empty())
                .then(|| self.diagnostics.address.trim().to_owned()),
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::sync_channel(32);
        self.diagnostics.context = Some(Context::capture(self));
        self.diagnostics.last_network_tests = request.network_tests;
        self.diagnostics.user_cancelled = false;
        self.diagnostics.repairing = false;
        self.diagnostics.report = None;
        self.diagnostics.stale = false;
        self.diagnostics.progress = "Читаем состояние сети…".into();
        self.diagnostics.notice = None;
        self.diagnostics.repair_error = None;
        self.diagnostics.receiver = Some(rx);
        self.diagnostics.cancel = Some(cancel.clone());
        let wake = ctx.clone();
        std::thread::spawn(move || {
            let report = engine::run(request, cancel, |stage| {
                let _ = tx.try_send(Message::Progress(stage.to_owned()));
                wake.request_repaint();
            });
            let _ = tx.send(Message::Report(report));
            wake.request_repaint();
        });
    }

    pub(super) fn poll_diagnostics(&mut self, ctx: &egui::Context) {
        if self.quitting
            || self
                .diagnostics
                .context
                .as_ref()
                .is_some_and(|c| !c.matches(self))
        {
            self.diagnostics.invalidate_and_cancel();
        }
        let mut done = false;
        let mut recheck = false;
        let mut reconnect = false;
        let cancelled = self
            .diagnostics
            .cancel
            .as_ref()
            .is_some_and(|cancel| cancel.load(Ordering::Relaxed));
        if let Some(receiver) = &self.diagnostics.receiver {
            loop {
                match receiver.try_recv() {
                    Ok(Message::Progress(progress)) => self.diagnostics.progress = progress,
                    Ok(Message::Report(mut report)) => {
                        report.cancelled |= cancelled;
                        self.diagnostics.report = Some(report);
                        done = true;
                    }
                    Ok(Message::Repaired(result)) => {
                        recheck = !self.diagnostics.user_cancelled;
                        match result {
                            Ok(()) => {
                                self.diagnostics.notice = Some(
                                    if recheck {
                                        "Действие выполнено. Повторяем локальную проверку."
                                    } else {
                                        "Действие завершено. Для нового снимка запустите проверку."
                                    }
                                    .into(),
                                )
                            }
                            Err(error) => self.diagnostics.repair_error = Some(error),
                        }
                        done = true;
                    }
                    Ok(Message::ReconnectReady(result)) => {
                        match result {
                            Ok(()) if !self.diagnostics.stale && !cancelled => reconnect = true,
                            Ok(()) if cancelled => {
                                self.diagnostics.repair_error =
                                    Some("Переподключение отменено.".into())
                            }
                            Ok(()) => {
                                self.diagnostics.repair_error =
                                    Some("Сеть изменилась. Сначала повторите проверку.".into())
                            }
                            Err(error) => self.diagnostics.repair_error = Some(error),
                        }
                        done = true;
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        if !done {
                            self.diagnostics.repair_error =
                                Some("Проверка прервана. Попробуйте ещё раз.".into());
                        }
                        done = true;
                        break;
                    }
                }
            }
        }
        if done {
            self.diagnostics.receiver = None;
            self.diagnostics.cancel = None;
        }
        if reconnect && !self.diagnostics_session_busy() {
            self.diagnostics.invalidate_and_cancel();
            self.diagnostics.recheck_when_idle = true;
            if self.want_connected {
                self.reconfigure();
            } else {
                self.connect(ctx);
            }
            ctx.request_repaint();
        }
        if self.diagnostics.recheck_when_idle && !self.diagnostics_session_busy() {
            self.diagnostics.recheck_when_idle = false;
            recheck = true;
        }
        if recheck && !self.quitting {
            if self.diagnostics_session_busy() {
                self.diagnostics.recheck_when_idle = true;
            } else {
                let error = self.diagnostics.repair_error.take();
                let notice = self.diagnostics.notice.take();
                self.start_diagnostics_with(ctx, true);
                self.diagnostics.repair_error = error;
                self.diagnostics.notice = notice;
            }
        }
    }

    fn apply_diagnostics_action(&mut self, action: Action, ctx: &egui::Context) {
        if !self.diagnostics_action_available(&action) {
            return;
        }
        let Some(report) = &self.diagnostics.report else {
            return;
        };
        let fingerprint = report.network_fingerprint.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::sync_channel(8);
        self.diagnostics.receiver = Some(rx);
        self.diagnostics.cancel = Some(cancel.clone());
        self.diagnostics.user_cancelled = false;
        self.diagnostics.repairing = true;
        self.diagnostics.repair_error = None;
        self.diagnostics.notice = None;
        self.diagnostics.progress = "Проверяем актуальность сети…".into();
        let wake = ctx.clone();
        let tun = self.tun.clone();
        std::thread::spawn(move || {
            let message = if matches!(action, Action::Reconnect) {
                let result = engine::fingerprint_cancelled(cancel.clone()).and_then(|current| {
                    if cancel.load(Ordering::Relaxed) {
                        Err("Действие отменено.".into())
                    } else if current != fingerprint {
                        Err("Сеть изменилась. Сначала повторите проверку.".into())
                    } else {
                        Ok(())
                    }
                });
                Message::ReconnectReady(result)
            } else {
                let prepared = if matches!(action, Action::RestoreDns { .. }) {
                    engine::fingerprint_cancelled(cancel.clone()).and_then(|current| {
                        if cancel.load(Ordering::Relaxed) {
                            Err("Действие отменено.".into())
                        } else if current != fingerprint {
                            Err("Сеть изменилась. Сначала повторите проверку.".into())
                        } else {
                            // A disconnected helper otherwise retains the global helper lock.
                            let _ = tx.try_send(Message::Progress(
                                "Останавливаем неактивный помощник TUN…".into(),
                            ));
                            wake.request_repaint();
                            tun.retire()
                        }
                    })
                } else {
                    Ok(())
                };
                Message::Repaired(prepared.and_then(|()| {
                    if cancel.load(Ordering::Relaxed) {
                        Err("Действие отменено.".into())
                    } else {
                        let _ = tx.try_send(Message::Progress("Применяем исправление…".into()));
                        wake.request_repaint();
                        engine::repair::apply(&action, &fingerprint, cancel)
                    }
                }))
            };
            let _ = tx.send(message);
            wake.request_repaint();
        });
    }

    fn diagnostics_action_available(&self, action: &Action) -> bool {
        self.diagnostics.actionable()
            && !self.diagnostics_session_busy()
            && (!matches!(action, Action::RestoreDns { .. } | Action::RecoverProxy)
                || (!self.running
                    && !self.want_connected
                    && self.session.is_none()
                    && !self.guard_session))
    }

    pub(super) fn diagnostics_page(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, p: Palette) {
        ui.label(heading("Диагностика", 26.0));
        ui.label(RichText::new("Проверим соединение и подскажем следующий шаг.").color(p.muted));
        ui.add_space(20.0);
        egui::ScrollArea::vertical().id_salt("diagnostics-page").show(ui, |ui| {
            let busy = self.diagnostics.busy();
            let session_busy = self.diagnostics_session_busy();
            egui::Frame::new().fill(p.card).corner_radius(12).inner_margin(20).show(ui, |ui| {
                ui.set_width(ui.available_width());
                let (title, subtitle, status) = summary(&self.diagnostics);
                ui.horizontal_top(|ui| {
                    status_symbol(ui, status, p, 34.0);
                    ui.add_space(5.0);
                    ui.vertical(|ui| {
                        ui.label(heading(title, 21.0));
                        ui.label(RichText::new(subtitle).color(p.muted));
                    });
                });
                ui.add_space(16.0);
                ui.horizontal_wrapped(|ui| {
                    if busy {
                        ui.spinner();
                        ui.label(&self.diagnostics.progress);
                        let cancelling = self.diagnostics.cancel.as_ref()
                            .is_some_and(|c| c.load(Ordering::Relaxed));
                        if enabled_command(ui, !cancelling, if cancelling { "Отменяем…" } else { "Отменить" }, ButtonTone::Secondary, Vec2::ZERO, p).clicked() {
                            self.diagnostics.cancel_by_user();
                        }
                    } else {
                        let label = if self.diagnostics.network_tests { "Проверить доступ" } else if self.diagnostics.report.is_some() { "Проверить снова" } else { "Проверить" };
                        if enabled_command(ui, !session_busy, label, ButtonTone::Primary, Vec2::new(158.0, 40.0), p).clicked() {
                            self.start_diagnostics(ctx);
                        }
                        if let Some(report) = &self.diagnostics.report
                            && command(ui, "Отчёт…", ButtonTone::Quiet, Vec2::ZERO, p).clicked()
                        {
                            let mut text = report.sanitized_text();
                            if self.diagnostics.stale {
                                text.push_str("Результаты устарели после изменения сети или настроек.\n");
                            }
                            self.diagnostics.export = Some(text);
                        }
                    }
                });
                if session_busy && !busy {
                    ui.add_space(8.0);
                    ui.label(RichText::new("Дождитесь завершения подключения или отключения.").small().color(p.muted));
                }
            });
            ui.add_space(12.0);
            let previous_options = (
                self.diagnostics.network_tests,
                self.diagnostics.direct_test,
                self.diagnostics.address.clone(),
            );
            egui::CollapsingHeader::new("Что проверять")
                .id_salt("diagnostics-options")
                .show(ui, |ui| {
                    ui.add_enabled_ui(!busy, |ui| {
                        ui.label(RichText::new("Всегда: интерфейсы, DNS, маршруты, локальный прокси и компоненты Eivro.").color(p.muted));
                        ui.add_space(8.0);
                        ui.label("Сайт или IP-адрес · необязательно");
                        ui.add(egui::TextEdit::singleline(&mut self.diagnostics.address)
                            .id_salt("diagnostics-address")
                            .hint_text("example.org")
                            .desired_width(ui.available_width())
                            .char_limit(253));
                        ui.label(RichText::new("Покажем применимое правило. Для запроса к сайту включите проверку доступа.").small().color(p.muted));
                        ui.add_space(10.0);
                        ui.checkbox(&mut self.diagnostics.network_tests, "Проверить доступ DNS и HTTPS");
                        if self.diagnostics.network_tests {
                            ui.label(RichText::new("Короткие запросы к указанному сайту или к example.com, если поле пустое. HTTPS использует Eivro, когда соединение активно.").small().color(p.muted));
                            ui.label(RichText::new(if self.running && self.settings.mode != Mode::Tun {
                                "Системный DNS не идёт через локальный прокси. Для его проверки нужно разрешить запросы вне VPN ниже."
                            } else {
                                "DNS проверяется по системным настройкам."
                            }).small().color(p.muted));
                            ui.add_space(6.0);
                            if self.settings.kill_switch { self.diagnostics.direct_test = false; }
                            ui.add_enabled(!self.settings.kill_switch, egui::Checkbox::new(&mut self.diagnostics.direct_test, "Сравнить с прямым доступом вне VPN"));
                            ui.label(RichText::new(if self.settings.kill_switch {
                                "Недоступно при включённом kill switch. Защита останется включённой."
                            } else {
                                "Отдельный запрос пойдёт через физический интерфейс вне VPN."
                            }).small().color(p.muted));
                        }
                    });
                });
            if previous_options != (
                self.diagnostics.network_tests,
                self.diagnostics.direct_test,
                self.diagnostics.address.clone(),
            ) {
                self.diagnostics.invalidate_and_cancel();
            }
            if let Some(error) = &self.diagnostics.repair_error {
                ui.add_space(10.0);
                ui.colored_label(p.error, error);
            }
            if let Some(notice) = &self.diagnostics.notice {
                ui.add_space(8.0);
                ui.label(RichText::new(notice).color(p.muted));
            }
            if self.diagnostics.stale {
                ui.add_space(10.0);
                ui.label(RichText::new("Сеть или настройки изменились. Повторите проверку перед исправлением.").color(p.muted));
            }
            let report = self.diagnostics.report.clone();
            if let Some(report) = report {
                ui.add_space(18.0);
                let mut findings: Vec<_> = report.findings.iter().filter(|f| f.status != Status::Pass).collect();
                findings.sort_by_key(|f| match f.status { Status::Error => 0, Status::Warning => 1, _ => 2 });
                if !findings.is_empty() {
                    ui.label(heading("Результаты проверки", 17.0));
                    ui.add_space(10.0);
                    egui::Frame::new().fill(p.card).corner_radius(12).inner_margin(16).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        for (index, finding) in findings.iter().enumerate() {
                            if index > 0 { ui.add_space(8.0); ui.separator(); ui.add_space(8.0); }
                            self.diagnostic_finding(ui, ctx, finding, index, p);
                        }
                    });
                }
                let passed: Vec<_> = report.findings.iter().filter(|f| f.status == Status::Pass).collect();
                if !passed.is_empty() {
                    ui.add_space(14.0);
                    egui::CollapsingHeader::new(format!("В порядке · {}", passed.len()))
                        .id_salt("diagnostics-passed")
                        .show(ui, |ui| {
                            for (index, finding) in passed.iter().enumerate() {
                                self.diagnostic_finding(ui, ctx, finding, index + 100, p);
                                ui.add_space(8.0);
                            }
                        });
                }
            } else if !busy {
                ui.add_space(22.0);
                ui.label(heading("Сначала — состояние вашего устройства", 17.0));
                ui.add_space(8.0);
                ui.label(RichText::new("Проверка ничего не меняет. Каждое исправление потребует отдельного подтверждения.").color(p.muted));
                ui.add_space(18.0);
                for (title, detail) in [
                    ("Сеть и DNS", "Интерфейс, адреса DNS и доступные маршруты"),
                    ("Eivro и правила", "Сервер, сетевые выходы, прокси и помощник TUN"),
                ] {
                    ui.label(RichText::new(title).strong());
                    ui.label(RichText::new(detail).color(p.muted));
                    ui.add_space(12.0);
                }
            }
            ui.add_space(18.0);
            ui.label(RichText::new("Данные остаются в приложении. Отчёт можно просмотреть и скопировать без адресов и параметров доступа.").small().color(p.muted));
        });
    }

    fn diagnostic_finding(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        finding: &Finding,
        index: usize,
        p: Palette,
    ) {
        ui.push_id(("diagnostic-finding", index, &finding.id), |ui| {
            ui.horizontal_wrapped(|ui| {
                let color = status_color(finding.status, p);
                ui.label(
                    RichText::new(status_label(finding.status))
                        .small()
                        .color(color),
                );
                ui.label(RichText::new(&finding.title).strong());
            });
            if !finding.advice.is_empty() {
                ui.label(RichText::new(&finding.advice).color(p.muted));
            }
            if !finding.detail.is_empty() {
                egui::CollapsingHeader::new("Подробности")
                    .id_salt("details")
                    .show(ui, |ui| {
                        ui.label(&finding.detail);
                    });
            }
            if let Some(action) = &finding.action {
                let actionable = self.diagnostics_action_available(action);
                if enabled_command(
                    ui,
                    actionable,
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
    }

    pub(super) fn diagnostics_dialog(&mut self, ctx: &egui::Context, p: Palette) {
        if let Some(action) = self.diagnostics.confirmation.clone() {
            let mut close = false;
            let mut apply = false;
            let response = modal(ctx, "diagnostics-confirm").show(ctx, |ui| {
                ui.set_width((ctx.content_rect().width() - 64.0).clamp(220.0, 460.0));
                ui.label(heading(action_label(&action), 23.0));
                ui.add_space(10.0);
                egui::ScrollArea::vertical()
                    .id_salt("diagnostics-confirm-body")
                    .max_height((ctx.content_rect().height() - 200.0).max(80.0))
                    .show(ui, |ui| {
                        if let Action::RestoreDns { interface } = &action {
                            ui.label(RichText::new(format!("Интерфейс: {interface}")).strong());
                            ui.label("Источник DNS: активное подключение NetworkManager.");
                            if let Some(finding) = self.diagnostics.report.as_ref().and_then(|report| {
                                report.findings.iter().find(|finding| finding.action.as_ref() == Some(&action))
                            }) {
                                ui.add_space(8.0);
                                ui.label(RichText::new(&finding.detail).color(p.muted));
                            }
                            ui.add_space(10.0);
                        }
                        ui.label(action_explanation(&action));
                        ui.add_space(10.0);
                        ui.label(RichText::new("Перед действием Eivro сверит состояние сети. Затем проверка запустится снова.").color(p.muted));
                    });
                ui.add_space(20.0);
                ui.horizontal_wrapped(|ui| {
                    close = command(ui, "Отмена", ButtonTone::Secondary, Vec2::ZERO, p).clicked();
                    apply = enabled_command(ui, self.diagnostics_action_available(&action), "Продолжить", ButtonTone::Primary, Vec2::ZERO, p).clicked();
                });
            });
            if close || apply || response.should_close() {
                self.diagnostics.confirmation = None;
            }
            if apply {
                self.apply_diagnostics_action(action, ctx);
            }
        }
        if let Some(mut text) = self.diagnostics.export.clone() {
            let mut close = false;
            let response = modal(ctx, "diagnostics-export").show(ctx, |ui| {
                ui.set_width((ctx.content_rect().width() - 64.0).clamp(220.0, 540.0));
                ui.label(heading("Отчёт без личных данных", 23.0));
                ui.add_space(8.0);
                ui.label(RichText::new("В буфер обмена попадёт только этот текст. Адреса, имена интерфейсов и параметры доступа исключены.").color(p.muted));
                ui.add_space(14.0);
                egui::ScrollArea::vertical().max_height((ctx.content_rect().height() - 280.0).max(80.0)).show(ui, |ui| {
                    ui.add(egui::TextEdit::multiline(&mut text).interactive(false).desired_width(f32::INFINITY).font(egui::TextStyle::Monospace));
                });
                ui.add_space(18.0);
                ui.horizontal_wrapped(|ui| {
                    close = command(ui, "Закрыть", ButtonTone::Secondary, Vec2::ZERO, p).clicked();
                    if command(ui, "Скопировать отчёт", ButtonTone::Primary, Vec2::ZERO, p).clicked() {
                        ctx.copy_text(text.clone());
                        self.diagnostics.notice = Some("Обезличенный отчёт скопирован.".into());
                        close = true;
                    }
                });
            });
            if close || response.should_close() {
                self.diagnostics.export = None;
            }
        }
    }
}

fn summary(state: &State) -> (String, String, Status) {
    if state.busy() && state.repairing {
        return (
            "Выполняем действие".into(),
            "Отмена остановит оставшиеся шаги. Выполненные изменения сохранятся.".into(),
            Status::Unknown,
        );
    }
    if state.busy() {
        return (
            "Проверяем соединение".into(),
            "Можно отменить в любой момент.".into(),
            Status::Unknown,
        );
    }
    if state.stale {
        return (
            "Нужна новая проверка".into(),
            "Предыдущий снимок больше не актуален.".into(),
            Status::Unknown,
        );
    }
    let Some(report) = &state.report else {
        return (
            "Готовы проверить сеть".into(),
            if state.network_tests {
                "Локальные проверки и короткие запросы DNS / HTTPS."
            } else {
                "Локальная проверка без отправки запросов в интернет."
            }
            .into(),
            Status::Unknown,
        );
    };
    if report.cancelled {
        return (
            "Проверка отменена".into(),
            "Ниже — только успевшие завершиться проверки.".into(),
            Status::Unknown,
        );
    }
    let errors = report
        .findings
        .iter()
        .filter(|f| f.status == Status::Error)
        .count();
    let warnings = report
        .findings
        .iter()
        .filter(|f| f.status == Status::Warning)
        .count();
    let unknown = report
        .findings
        .iter()
        .filter(|f| f.status == Status::Unknown)
        .count();
    let passed = report
        .findings
        .iter()
        .filter(|f| f.status == Status::Pass)
        .count();
    let status = if errors > 0 {
        Status::Error
    } else if warnings > 0 {
        Status::Warning
    } else if unknown > 0 {
        Status::Unknown
    } else {
        Status::Pass
    };
    let title = match status {
        Status::Error => "Есть препятствия для соединения",
        Status::Warning => "Есть что проверить",
        Status::Unknown => "Проверка завершена не полностью",
        Status::Pass => "Проверки пройдены",
    };
    (
        title.into(),
        format!(
            "{} · В порядке: {passed} · Внимание: {} · Не проверено: {unknown}",
            if state.last_network_tests {
                "С проверкой доступа"
            } else {
                "Локальный снимок"
            },
            errors + warnings
        ),
        status,
    )
}

fn status_label(status: Status) -> &'static str {
    match status {
        Status::Pass => "✓ В порядке",
        Status::Warning => "! Внимание",
        Status::Error => "! Ошибка",
        Status::Unknown => "? Не проверено",
    }
}

fn status_color(status: Status, p: Palette) -> Color32 {
    match status {
        Status::Error => p.error,
        Status::Warning => {
            if p.bg.r() < 100 {
                Color32::from_rgb(230, 190, 124)
            } else {
                Color32::from_rgb(133, 84, 27)
            }
        }
        Status::Pass => p.accent,
        Status::Unknown => p.muted,
    }
}

fn status_symbol(ui: &mut egui::Ui, status: Status, p: Palette, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
    let color = status_color(status, p);
    ui.painter()
        .circle_filled(rect.center(), size * 0.5, mix(p.card, color, 0.10));
    ui.painter().circle_stroke(
        rect.center(),
        size * 0.5 - 0.5,
        Stroke::new(1.0_f32, mix(p.card, color, 0.35)),
    );
    ui.painter().text(
        rect.center(),
        Align2::CENTER_CENTER,
        match status {
            Status::Pass => "✓",
            Status::Unknown => "?",
            _ => "!",
        },
        FontId::proportional(21.0),
        color,
    );
}

fn action_label(action: &Action) -> &'static str {
    match action {
        Action::FlushDns => "Очистить кэш DNS",
        Action::RecoverProxy => "Восстановить системный прокси",
        Action::Reconnect => "Переподключить Eivro",
        Action::OpenRoutes => "Открыть маршруты",
        Action::OpenSettings => "Открыть настройки",
        Action::RestoreDns { .. } => "Восстановить DNS интерфейса",
    }
}

fn action_explanation(action: &Action) -> &'static str {
    match action {
        Action::FlushDns => {
            "Будет очищен кэш systemd-resolved. Следующие обращения к сайтам заново запросят DNS; настройки серверов не изменятся."
        }
        Action::RecoverProxy => {
            "Eivro восстановит сохранённые настройки системного прокси, оставшиеся после завершённого сеанса. Действие недоступно, пока этот прокси используется активным сеансом."
        }
        Action::Reconnect => {
            "Текущий сеанс Eivro будет перезапущен с выбранным сервером и правилами. Соединения могут ненадолго прерваться."
        }
        Action::RestoreDns { .. } => {
            "Eivro применит DNS только этого подключения, остановит неактивный помощник TUN и очистит его сохранённые DNS-имена. Разрешение имён может ненадолго прерваться. Система может запросить права администратора."
        }
        Action::OpenRoutes | Action::OpenSettings => "Открыть настройки Eivro.",
    }
}

#[cfg(feature = "qa")]
impl State {
    pub(super) fn fixture(&mut self, page: &str, settings: &Settings) {
        if page == "diagnostics" {
            return;
        }
        self.context = Some(Context {
            settings: settings.clone(),
            running: false,
            wanted: false,
            session: false,
            stopping: false,
        });
        let mut findings = vec![
            Finding {
                id: "uplink".into(),
                status: Status::Pass,
                title: "Физическое подключение доступно".into(),
                detail: "Интерфейс активен, маршрут по умолчанию найден.".into(),
                advice: String::new(),
                action: None,
            },
            Finding {
                id: "core".into(),
                status: Status::Pass,
                title: "Компоненты Eivro готовы".into(),
                detail: "Ядро и помощник TUN доступны.".into(),
                advice: String::new(),
                action: None,
            },
            Finding {
                id: "proxy_port".into(),
                status: Status::Pass,
                title: "Локальный порт свободен".into(),
                detail: "Приложение сможет открыть локальный прокси.".into(),
                advice: String::new(),
                action: None,
            },
        ];
        if page == "diagnostics-error" {
            findings.extend([
                Finding { id: "resolver".into(), status: Status::Error, title: "DNS остался от завершённого VPN".into(), detail: "Сервер DNS интерфейса недоступен по текущему маршруту. Активное подключение NetworkManager содержит исходные DNS-серверы.".into(), advice: "Восстановите DNS активного подключения и повторите проверку.".into(), action: Some(Action::RestoreDns { interface: "test0".into() }) },
                Finding { id: "rule".into(), status: Status::Warning, title: "Для сайта выбран недоступный сетевой выход".into(), detail: "Правило направляет запросы через интерфейс, который сейчас отключён.".into(), advice: "Подключите нужную сеть или измените правило для сайта.".into(), action: Some(Action::OpenRoutes) },
                Finding { id: "policy".into(), status: Status::Unknown, title: "Правила ядра недоступны".into(), detail: "Для чтения этой части состояния недостаточно прав.".into(), advice: "Остальные проверки завершены; отсутствие доступа не означает ошибку сети.".into(), action: None },
            ]);
        }
        self.report = Some(Report {
            findings,
            cancelled: false,
            network_fingerprint: "qa-only".into(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changing_selected_server_revokes_diagnostic_context() {
        let mut settings = Settings::default();
        settings
            .apply_document(
                None,
                catalog::Document {
                    name: "Synthetic".into(),
                    source: None,
                    profiles: vec![eivro::import::Profile {
                        name: "Test".into(),
                        uri: "ss://chacha20-ietf-poly1305:synthetic@192.0.2.1:443".into(),
                    }],
                    metadata: Default::default(),
                },
            )
            .unwrap();
        let mut app = App::model(settings, None, None);
        let context = Context::capture(&app);
        assert!(context.matches(&app));
        app.settings.current_mut().unwrap().profiles[0].uri =
            "ss://chacha20-ietf-poly1305:replacement@192.0.2.1:443".into();
        assert!(!context.matches(&app));
    }

    #[test]
    fn invalidation_cancels_worker_and_revokes_confirmation() {
        let mut app = App::model(Settings::default(), None, None);
        app.diagnostics.context = Some(Context::capture(&app));
        let cancel = Arc::new(AtomicBool::new(false));
        app.diagnostics.cancel = Some(cancel.clone());
        app.diagnostics.report = Some(Report::default());
        app.diagnostics.confirmation = Some(Action::FlushDns);
        assert!(app.diagnostics.actionable());
        app.diagnostics.invalidate();
        assert!(cancel.load(Ordering::Relaxed));
        assert!(!app.diagnostics.actionable());
        assert!(!app.diagnostics.modal_open());
    }

    #[test]
    fn repair_network_notification_preserves_completion_and_schedules_local_recheck() {
        let mut app = App::model(Settings::default(), None, None);
        // Hold the follow-up so this test observes scheduling without host checks.
        app.stopping = true;
        app.diagnostics.context = Some(Context::capture(&app));
        app.diagnostics.repairing = true;
        let cancel = Arc::new(AtomicBool::new(false));
        app.diagnostics.cancel = Some(cancel.clone());
        app.diagnostics.confirmation = Some(Action::FlushDns);
        let (tx, rx) = mpsc::channel();
        app.diagnostics.receiver = Some(rx);

        app.diagnostics.invalidate();
        assert!(app.diagnostics.stale);
        assert!(!app.diagnostics.modal_open());
        assert!(!cancel.load(Ordering::Relaxed));
        tx.send(Message::Repaired(Ok(()))).unwrap();
        app.poll_diagnostics(&egui::Context::default());

        assert!(!app.diagnostics.busy());
        assert!(app.diagnostics.recheck_when_idle);
        assert!(app.diagnostics.repair_error.is_none());
        assert!(
            app.diagnostics
                .notice
                .as_ref()
                .unwrap()
                .contains("выполнено")
        );
    }

    #[test]
    fn explicit_cancellation_still_revokes_an_active_repair() {
        for user_cancel in [false, true] {
            let mut app = App::model(Settings::default(), None, None);
            app.diagnostics.context = Some(Context::capture(&app));
            app.diagnostics.repairing = true;
            let cancel = Arc::new(AtomicBool::new(false));
            app.diagnostics.cancel = Some(cancel.clone());
            if user_cancel {
                app.diagnostics.cancel_by_user();
                assert!(app.diagnostics.user_cancelled);
            } else {
                app.diagnostics.invalidate_and_cancel();
                assert!(app.diagnostics.stale);
            }
            assert!(cancel.load(Ordering::Relaxed));
        }
    }

    #[test]
    fn new_connection_cancels_repair_and_waits_without_reconnecting_automatically() {
        let mut app = App::model(Settings::default(), None, None);
        app.diagnostics.context = Some(Context::capture(&app));
        app.diagnostics.repairing = true;
        let cancel = Arc::new(AtomicBool::new(false));
        app.diagnostics.cancel = Some(cancel.clone());
        let (tx, rx) = mpsc::channel();
        app.diagnostics.receiver = Some(rx);
        let ctx = egui::Context::default();

        app.connect(&ctx);
        assert!(app.session.is_none());
        assert!(!app.want_connected);
        assert!(cancel.load(Ordering::Relaxed));
        assert!(app.diagnostics.user_cancelled);
        assert!(
            app.error
                .as_ref()
                .unwrap()
                .contains("повторите подключение")
        );

        // Even a repair committed just before cancellation must not auto-connect.
        tx.send(Message::Repaired(Ok(()))).unwrap();
        app.poll_diagnostics(&ctx);
        assert!(app.session.is_none());
        assert!(!app.want_connected);
        assert!(!app.diagnostics.recheck_when_idle);
        assert!(!app.diagnostics_connection_blocked());
    }

    #[test]
    fn read_only_check_does_not_block_a_new_connection() {
        let mut app = App::model(Settings::default(), None, None);
        let (_tx, rx) = mpsc::channel();
        app.diagnostics.receiver = Some(rx);
        assert!(!app.diagnostics_connection_blocked());
        assert!(app.error.is_none());
    }

    #[test]
    fn stale_worker_result_cannot_enable_a_repair() {
        let mut app = App::model(Settings::default(), None, None);
        app.diagnostics.context = Some(Context::capture(&app));
        let (tx, rx) = mpsc::channel();
        app.diagnostics.receiver = Some(rx);
        app.settings.port += 1;
        tx.send(Message::Report(Report::default())).unwrap();
        app.poll_diagnostics(&egui::Context::default());
        assert!(app.diagnostics.report.is_some());
        assert!(app.diagnostics.stale);
        assert!(!app.diagnostics.actionable());
    }

    #[test]
    fn cancellation_preserves_partial_results_without_actions() {
        let mut app = App::model(Settings::default(), None, None);
        app.diagnostics.context = Some(Context::capture(&app));
        let (tx, rx) = mpsc::channel();
        app.diagnostics.receiver = Some(rx);
        tx.send(Message::Report(Report {
            cancelled: true,
            ..Default::default()
        }))
        .unwrap();
        app.poll_diagnostics(&egui::Context::default());
        assert!(!app.diagnostics.busy());
        assert!(!app.diagnostics.actionable());
        assert_eq!(summary(&app.diagnostics).0, "Проверка отменена");
    }

    #[test]
    fn unknown_checks_do_not_claim_success() {
        let mut state = State::default();
        state.report = Some(Report {
            findings: vec![Finding {
                id: "policy".into(),
                status: Status::Unknown,
                title: String::new(),
                detail: String::new(),
                advice: String::new(),
                action: None,
            }],
            ..Default::default()
        });
        assert_eq!(summary(&state).2, Status::Unknown);
    }

    #[test]
    fn cancellation_revokes_a_queued_reconnect() {
        let mut app = App::model(Settings::default(), None, None);
        app.diagnostics.context = Some(Context::capture(&app));
        let (tx, rx) = mpsc::channel();
        app.diagnostics.receiver = Some(rx);
        app.diagnostics.cancel = Some(Arc::new(AtomicBool::new(true)));
        tx.send(Message::ReconnectReady(Ok(()))).unwrap();
        app.poll_diagnostics(&egui::Context::default());
        assert!(app.session.is_none());
        assert!(!app.want_connected);
        assert!(
            app.diagnostics
                .repair_error
                .as_ref()
                .unwrap()
                .contains("отменено")
        );
    }

    #[test]
    fn dns_and_proxy_repair_preserve_disconnected_kill_switch_intent() {
        let mut app = App::model(Settings::default(), None, None);
        app.diagnostics.report = Some(Report::default());
        let restore = Action::RestoreDns {
            interface: "test0".into(),
        };
        assert!(app.diagnostics_action_available(&restore));
        app.want_connected = true;
        assert!(!app.diagnostics_action_available(&restore));
        assert!(!app.diagnostics_action_available(&Action::RecoverProxy));
        app.want_connected = false;
        app.guard_session = true;
        assert!(!app.diagnostics_action_available(&restore));
        assert!(!app.diagnostics_action_available(&Action::RecoverProxy));
    }

    #[test]
    fn failed_repair_defers_recheck_during_a_session_transition_unless_cancelled() {
        for cancelled in [false, true] {
            let mut app = App::model(Settings::default(), None, None);
            app.stopping = true;
            app.diagnostics.context = Some(Context::capture(&app));
            app.diagnostics.user_cancelled = cancelled;
            let (tx, rx) = mpsc::channel();
            app.diagnostics.receiver = Some(rx);
            tx.send(Message::Repaired(Err("Test failure".into())))
                .unwrap();
            app.poll_diagnostics(&egui::Context::default());
            assert!(!app.diagnostics.busy());
            assert_eq!(app.diagnostics.recheck_when_idle, !cancelled);
            assert_eq!(
                app.diagnostics.repair_error.as_deref(),
                Some("Test failure")
            );
        }
    }

    #[test]
    fn displaying_diagnostics_stays_idle_without_starting_a_check() {
        let mut app = App::model(Settings::default(), None, None);
        let ctx = egui::Context::default();
        crate::emoji::install(&ctx);
        for width in [320.0, 650.0, 960.0] {
            for pass in 0..15 {
                let output = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            Vec2::new(width, 760.0),
                        )),
                        time: Some(pass as f64),
                        ..Default::default()
                    },
                    |ctx| {
                        egui::CentralPanel::default().show(ctx, |ui| {
                            app.diagnostics_page(ui, ctx, app.palette());
                        });
                    },
                );
                if pass > 10 {
                    assert!(
                        output.viewport_output[&egui::ViewportId::ROOT].repaint_delay
                            > std::time::Duration::from_secs(60)
                    );
                }
                assert!(!app.diagnostics.busy());
                assert!(!app.diagnostics.has_context());
            }
        }
    }
}
