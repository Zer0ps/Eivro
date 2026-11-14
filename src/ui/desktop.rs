use super::*;
use eivro::desktop::Event as DesktopEvent;
use std::time::Instant;
impl App {
    pub(super) fn desktop_events(&mut self, ctx: &egui::Context) {
        if self
            .instance
            .as_ref()
            .is_some_and(|i| i.events.try_iter().count() > 0)
        {
            self.show_window(ctx);
        }
        let events: Vec<_> = self
            .desktop
            .as_ref()
            .map(|d| d.events.try_iter().collect())
            .unwrap_or_default();
        for event in events {
            match event {
                DesktopEvent::Show => self.show_window(ctx),
                #[cfg(any(target_os = "macos", windows))]
                DesktopEvent::Settings => {
                    self.show_window(ctx);
                    self.catalog_open = false;
                    self.page = Page::Settings;
                }
                DesktopEvent::Toggle => self.connect(ctx),
                DesktopEvent::Quit => {
                    self.request_quit(ctx);
                }
                DesktopEvent::TrayOnline(online) => {
                    self.tray_online = online;
                    if !online && self.hidden {
                        self.show_window(ctx);
                    }
                    if online && self.background_start && self.window_hiding {
                        self.background_start = false;
                        self.hidden = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                    }
                }
                DesktopEvent::Network(online) => {
                    self.diagnostics.invalidate();
                    #[cfg(any(target_os = "macos", windows))]
                    self.schedule_network_scan(ctx);
                    self.recovery.offline = !online;
                    let initial = !self.network_seen;
                    self.network_seen = true;
                    if self.want_connected && self.settings.reconnect && (!initial || !online) {
                        self.network_reconnect();
                    }
                }
                DesktopEvent::Sleep(sleeping) => {
                    self.diagnostics.invalidate();
                    self.recovery.sleeping = sleeping;
                    if self.want_connected && self.settings.reconnect {
                        self.network_reconnect();
                    }
                }
                DesktopEvent::DnsChanged => self.schedule_network_scan(ctx),
                DesktopEvent::MonitorUnavailable => self.monitor_unavailable = true,
            }
        }
    }
    pub(super) fn show_window(&mut self, ctx: &egui::Context) {
        self.hidden = false;
        self.background_start = false;
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }
    fn network_reconnect(&mut self) {
        // Network changes during authorization or session setup can be generated
        // by that setup itself. Let its first attempt finish before reconnecting.
        if self.session.is_some() && !self.running && !self.stopping {
            return;
        }
        self.recovery.schedule(Instant::now());
        if let Some(session) = &mut self.session {
            session.restart();
            self.stopping = true;
            self.running = false;
            self.reconnect_pending = true;
        }
    }
    pub(super) fn recover(&mut self, ctx: &egui::Context) {
        if !self.want_connected || self.quitting {
            self.recovery.cancel();
            return;
        }
        if self.session.is_none()
            && let Some(due) = self.recovery.due
        {
            ctx.request_repaint_after(due.saturating_duration_since(Instant::now()));
        }
        if self.session.is_none() && self.recovery.ready(Instant::now()) {
            self.start_connection(ctx);
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    #[test]
    fn tray_toggle_with_no_server_opens_the_picker_without_starting_a_session() {
        let mut app = App::model(Settings::default(), None, None);
        app.hidden = true;
        app.connect(&egui::Context::default());
        assert!(app.catalog_open && !app.hidden);
        assert!(!app.want_connected && app.session.is_none());
    }

    #[test]
    fn cancelled_autoconnect_stays_idle_after_network_and_wake_events() {
        let ctx = egui::Context::default();
        let mut app = App::model(
            Settings {
                autoconnect: true,
                mode: Mode::Tun,
                ..Default::default()
            },
            None,
            None,
        );
        app.want_connected = true;
        app.recovery.schedule(Instant::now());
        let (tx, rx) = mpsc::channel();
        app.events = Some(rx);
        tx.send(Event::Failed(eivro::tun::AUTHORIZATION_DENIED.into()))
            .unwrap();
        app.receive(&ctx);
        assert!(!app.want_connected && app.error.is_none() && app.recovery.due.is_none());
        // Even stale notifications/timers cannot turn cancellation into consent.
        for _ in 0..3 {
            app.network_reconnect();
            app.recover(&ctx);
            assert!(!app.want_connected && app.session.is_none() && app.recovery.due.is_none());
        }
        assert!(
            app.settings.autoconnect,
            "Next-login preference must not be changed"
        );
        assert!(!app.quitting);
    }
}
