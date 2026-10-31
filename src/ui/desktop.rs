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
                DesktopEvent::Toggle => self.connect(ctx),
                DesktopEvent::Quit => {
                    self.quitting = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
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
                    self.recovery.offline = !online;
                    let initial = !self.network_seen;
                    self.network_seen = true;
                    if self.want_connected && self.settings.reconnect && (!initial || !online) {
                        self.network_reconnect();
                    }
                }
                DesktopEvent::Sleep(sleeping) => {
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
    fn show_window(&mut self, ctx: &egui::Context) {
        self.hidden = false;
        self.background_start = false;
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }
    fn network_reconnect(&mut self) {
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
