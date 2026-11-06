use super::*;

impl App {
    pub(super) fn request_quit(&mut self, ctx: &egui::Context) {
        if self.quitting {
            return;
        }
        #[cfg(target_os = "linux")]
        self.diagnostics.invalidate_and_cancel();
        self.quitting = true;
        self.want_connected = false;
        self.reconnect_pending = false;
        self.recovery.cancel();
        if let Some(session) = self.session.as_mut() {
            session.stop();
            self.stopping = true;
            self.running = false;
        }
        #[cfg(target_os = "linux")]
        {
            self.exit_error = None;
            self.poll_quit(ctx);
        }
        #[cfg(not(target_os = "linux"))]
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    }

    #[cfg(target_os = "linux")]
    pub(super) fn poll_quit(&mut self, ctx: &egui::Context) {
        if !self.quitting || self.session.is_some() || self.exit_ready {
            return;
        }
        if self.exit_result.is_none() {
            let (tx, rx) = mpsc::channel();
            self.exit_result = Some(rx);
            let controller = self.tun.clone();
            let ctx = ctx.clone();
            std::thread::spawn(move || {
                let _ = tx.send(controller.retire());
                ctx.request_repaint();
            });
        }
        let result = self
            .exit_result
            .as_ref()
            .and_then(|rx| match rx.try_recv() {
                Ok(result) => Some(result),
                Err(mpsc::TryRecvError::Empty) => None,
                Err(mpsc::TryRecvError::Disconnected) => {
                    Some(Err("Очистка памяти DNS прервана.".into()))
                }
            });
        if let Some(result) = result {
            self.exit_result = None;
            match result {
                Ok(()) => self.finish_quit(ctx),
                Err(error) => {
                    self.quitting = false;
                    self.exit_error = Some(error);
                    self.hidden = false;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn finish_quit(&mut self, ctx: &egui::Context) {
        self.diagnostics.invalidate_and_cancel();
        self.quitting = true;
        self.exit_ready = true;
        self.exit_error = None;
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    }

    #[cfg(target_os = "linux")]
    pub(super) fn quit_dialog(&mut self, ctx: &egui::Context, p: Palette) {
        use super::design::{ButtonTone, command, heading};
        let Some(error) = self.exit_error.as_deref() else {
            return;
        };
        let mut retry = false;
        let mut exit = false;
        let response = super::design::modal(ctx, "exit-cleanup-error").show(ctx, |ui| {
            ui.set_width((ctx.content_rect().width() - 64.0).min(440.0));
            ui.label(heading("Очистка не завершена", 22.0));
            ui.add_space(8.0);
            ui.label(error);
            ui.label(
                RichText::new("Доменные имена могут остаться в памяти до перезагрузки системы.")
                    .color(p.muted),
            );
            ui.add_space(12.0);
            ui.horizontal_wrapped(|ui| {
                retry = command(ui, "Повторить", ButtonTone::Primary, Vec2::ZERO, p).clicked();
                exit = command(
                    ui,
                    "Выйти без очистки",
                    ButtonTone::Secondary,
                    Vec2::ZERO,
                    p,
                )
                .clicked();
            });
        });
        if exit {
            self.finish_quit(ctx);
        } else if retry {
            self.request_quit(ctx);
        } else if response.should_close() {
            self.exit_error = None;
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    fn has_close(output: &egui::FullOutput) -> bool {
        output.viewport_output[&egui::ViewportId::ROOT]
            .commands
            .iter()
            .any(|command| matches!(command, egui::ViewportCommand::Close))
    }
    #[test]
    fn exit_waits_for_cleanup_and_failure_never_silently_closes() {
        let mut app = App::model(Settings::default(), None, None);
        let ctx = egui::Context::default();
        let (tx, rx) = mpsc::channel();
        app.exit_result = Some(rx);
        app.want_connected = true;
        let out = ctx.run(Default::default(), |ctx| app.request_quit(ctx));
        assert!(app.quitting && !app.want_connected && !app.exit_ready);
        assert!(!has_close(&out));
        app.connect(&ctx);
        assert!(!app.want_connected, "connection restarted during cleanup");
        tx.send(Err("fixture cleanup failure".into())).unwrap();
        let out = ctx.run(Default::default(), |ctx| app.poll_quit(ctx));
        assert!(!has_close(&out));
        assert!(!app.quitting && app.exit_error.is_some() && !app.exit_ready);
        let (tx, rx) = mpsc::channel();
        app.exit_result = Some(rx);
        app.request_quit(&ctx);
        tx.send(Ok(())).unwrap();
        let out = ctx.run(Default::default(), |ctx| app.poll_quit(ctx));
        assert!(has_close(&out) && app.exit_ready && app.exit_error.is_none());
    }
    #[test]
    fn exit_without_cleanup_is_an_explicit_separate_action() {
        let mut app = App::model(Settings::default(), None, None);
        let ctx = egui::Context::default();
        app.exit_error = Some("fixture failure".into());
        let out = ctx.run(Default::default(), |ctx| app.finish_quit(ctx));
        assert!(has_close(&out) && app.exit_ready && app.quitting);
    }
}
