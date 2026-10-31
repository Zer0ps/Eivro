use super::*;
use egui::{Pos2, Rect, Shape, epaint::Mesh};
use std::{f32::consts::TAU, time::Duration};

const FRAME: Duration = Duration::from_nanos(16_666_667);

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Ripple,
    Tear,
}

impl Kind {
    fn duration(self) -> f64 {
        match self {
            Self::Ripple => 4.0,
            Self::Tear => 1.8,
        }
    }
}

struct Burst {
    kind: Kind,
    started: f64,
}

pub(super) struct Origins {
    pub power: Pos2,
    pub button: Pos2,
}

#[derive(Default)]
pub(super) struct ConnectionEffect {
    observed_running: bool,
    active: Option<Burst>,
}

impl ConnectionEffect {
    fn sync(&mut self, ctx: &egui::Context, running: bool, wanted: bool, visible: bool) {
        if !visible {
            self.active = None;
        } else if running != self.observed_running {
            // Switching/recovery is not a disconnect. Failed initial attempts
            // never produce either effect, and repeated status events cannot loop it.
            self.active = if running || !wanted {
                ctx.request_repaint();
                Some(Burst {
                    kind: if running { Kind::Ripple } else { Kind::Tear },
                    started: ctx.input(|i| i.time),
                })
            } else {
                None
            };
        } else if wanted && !running {
            self.active = None;
        }
        // Observe even when hidden: returning from the tray must not replay history.
        self.observed_running = running;
    }

    pub(super) fn paint(
        &mut self,
        ctx: &egui::Context,
        bounds: Rect,
        origins: Origins,
        accent: Color32,
    ) -> Shape {
        let Some(burst) = &self.active else {
            return Shape::Noop;
        };
        let elapsed = (ctx.input(|i| i.time) - burst.started).max(0.0);
        if elapsed >= burst.kind.duration() {
            self.active = None;
            return Shape::Noop;
        }
        let origin = match burst.kind {
            Kind::Ripple => origins.power,
            Kind::Tear => origins.button,
        };
        if !bounds.is_positive() || !bounds.contains(origin) {
            self.active = None;
            return Shape::Noop;
        }
        // Bounded wakeups only while the burst is visible, including one last
        // frame to clear it. No timer, worker, shader or network sampling in idle.
        ctx.request_repaint_after(
            FRAME.min(Duration::from_secs_f64(burst.kind.duration() - elapsed)),
        );
        match burst.kind {
            Kind::Ripple => ripple(bounds, origin, elapsed as f32, accent),
            Kind::Tear => tear(
                bounds,
                origin,
                (elapsed / Kind::Tear.duration()) as f32,
                accent,
            ),
        }
    }
}

impl App {
    pub(super) fn sync_connection_effect(&mut self, ctx: &egui::Context) {
        let visible = self.page == Page::Connection
            && !self.hidden
            && !self.quitting
            && !self.recovery.sleeping
            && !self.settings.reduced_motion
            && !self.catalog_open
            && !self.navigation_overlay
            && !self.import_open
            && !self.delete_server
            && self.delete_subscription.is_none()
            && self.rename_subscription.is_none()
            && ctx.input(|i| i.viewport().minimized != Some(true))
            && ctx.memory(|m| m.top_modal_layer().is_none());
        self.connection_effect
            .sync(ctx, self.running, self.want_connected, visible);
    }
}

fn smooth(start: f32, end: f32, value: f32) -> f32 {
    let t = ((value - start) / (end - start)).clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}

fn ripple(bounds: Rect, origin: Pos2, elapsed: f32, accent: Color32) -> Shape {
    let reach = [
        bounds.left_top(),
        bounds.right_top(),
        bounds.left_bottom(),
        bounds.right_bottom(),
    ]
    .into_iter()
    .map(|p| p.distance(origin))
    .fold(0.0, f32::max);
    let mut mesh = Mesh::default();
    const SEGMENTS: usize = 144;
    for wave in 0..3 {
        let age = elapsed - wave as f32 * 0.28;
        if !(0.0..3.44).contains(&age) {
            continue;
        }
        let t = age / 3.44;
        let travel = 0.72 * t + 0.28 * (1.0 - (1.0 - t).powi(3));
        let radius = 34.0 + reach * travel;
        let strength = smooth(0.0, 0.16, age) * (1.0 - smooth(0.50, 1.0, t));
        let width = 13.0 + 14.0 * t;
        let base = mesh.vertices.len() as u32;
        // A fine crest and a soft inner wake, expressed as one small mesh.
        // Transparency falls to zero on both sides; there is no full-screen blur.
        let bands = [
            (-width, 0.0),
            (-3.0, 0.045),
            (0.0, 0.26),
            (2.0, 0.055),
            (width * 0.4, 0.0),
        ];
        for step in 0..=SEGMENTS {
            let direction = Vec2::angled(TAU * step as f32 / SEGMENTS as f32);
            for (offset, opacity) in bands {
                mesh.colored_vertex(
                    origin + direction * (radius + offset),
                    accent.gamma_multiply(opacity * strength),
                );
            }
            if step > 0 {
                let a = base + (step as u32 - 1) * 5;
                for band in 0..4 {
                    mesh.add_triangle(a + band, a + band + 5, a + band + 1);
                    mesh.add_triangle(a + band + 1, a + band + 5, a + band + 6);
                }
            }
        }
    }
    Shape::mesh(mesh)
}

fn tear(bounds: Rect, origin: Pos2, t: f32, accent: Color32) -> Shape {
    let mut mesh = Mesh::default();
    // Fixed geometry reveals once; it never flickers or changes randomly per frame.
    for (ray, angle) in [-2.82_f32, -2.08, -1.18, -0.36, 0.53, 1.63, 2.55]
        .into_iter()
        .enumerate()
    {
        let direction = Vec2::angled(angle);
        let across = Vec2::new(-direction.y, direction.x);
        let horizontal = if direction.x > 0.0 {
            bounds.right() - origin.x
        } else {
            origin.x - bounds.left()
        } / direction.x.abs();
        let vertical = if direction.y > 0.0 {
            bounds.bottom() - origin.y
        } else {
            origin.y - bounds.top()
        } / direction.y.abs();
        let reach = horizontal.min(vertical);
        let phase = ((t - ray as f32 * 0.012) / 0.92).clamp(0.0, 1.0);
        let head = 1.0 - (1.0 - (phase / 0.48).min(1.0)).powi(2);
        let tail = smooth(0.18, 1.0, phase);
        let strength = smooth(0.0, 0.06, phase) * (1.0 - smooth(0.40, 1.0, phase));
        let point = |u: f32| {
            let bend = ((u * 39.0 + ray as f32 * 2.7).sin() + 0.45 * (u * 73.0 + ray as f32).sin())
                * reach
                * 0.027
                * (std::f32::consts::PI * u).sin();
            origin + direction * (12.0 + u * (reach - 12.0)) + across * bend
        };
        for step in 0..18 {
            let lo = step as f32 / 18.0;
            let hi = (step + 1) as f32 / 18.0;
            let from = lo.max(tail);
            let to = hi.min(head);
            if from >= to {
                continue;
            }
            let a = point(lo);
            let b = point(hi);
            let from_pos = a.lerp(b, (from - lo) * 18.0);
            let to_pos = a.lerp(b, (to - lo) * 18.0);
            let opacity = |u| {
                0.36 * strength
                    * smooth(tail, tail + 0.10, u)
                    * (1.0 - smooth(head - 0.04, head, u))
            };
            let normal = (b - a).normalized().rot90() * 2.5;
            let base = mesh.vertices.len() as u32;
            for (pos, alpha) in [(from_pos, opacity(from)), (to_pos, opacity(to))] {
                mesh.colored_vertex(pos - normal, Color32::TRANSPARENT);
                mesh.colored_vertex(pos, accent.gamma_multiply(alpha));
                mesh.colored_vertex(pos + normal, Color32::TRANSPARENT);
            }
            for band in 0..2 {
                mesh.add_triangle(base + band, base + band + 3, base + band + 1);
                mesh.add_triangle(base + band + 1, base + band + 3, base + band + 4);
            }
        }
    }
    Shape::mesh(mesh)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(
        effect: &mut ConnectionEffect,
        ctx: &egui::Context,
        now: f64,
        running: bool,
        wanted: bool,
        visible: bool,
    ) -> egui::FullOutput {
        ctx.run(
            egui::RawInput {
                time: Some(now),
                ..Default::default()
            },
            |ctx| {
                effect.sync(ctx, running, wanted, visible);
                let shape = effect.paint(
                    ctx,
                    Rect::from_min_size(Pos2::ZERO, Vec2::new(960.0, 760.0)),
                    Origins {
                        power: egui::pos2(480.0, 195.0),
                        button: egui::pos2(480.0, 546.0),
                    },
                    Color32::WHITE,
                );
                ctx.layer_painter(egui::LayerId::background()).add(shape);
            },
        )
    }

    #[test]
    fn effects_follow_confirmed_state_and_replace_instead_of_queueing() {
        let ctx = egui::Context::default();
        let mut effect = ConnectionEffect::default();
        frame(&mut effect, &ctx, 0.0, false, false, true);
        frame(&mut effect, &ctx, 1.0, false, true, true);
        frame(&mut effect, &ctx, 2.0, false, false, true);
        assert!(
            effect.active.is_none(),
            "a failed initial attempt is not a connection"
        );
        frame(&mut effect, &ctx, 3.0, true, true, true);
        frame(&mut effect, &ctx, 3.2, true, true, true);
        assert_eq!(effect.active.as_ref().unwrap().started, 3.0);
        frame(&mut effect, &ctx, 3.3, false, true, true);
        assert!(
            effect.active.is_none(),
            "switching must not show a disconnect"
        );
        frame(&mut effect, &ctx, 3.4, true, true, true);
        frame(&mut effect, &ctx, 3.5, false, false, true);
        assert_eq!(effect.active.as_ref().unwrap().kind, Kind::Tear);
        frame(&mut effect, &ctx, 3.6, true, true, true);
        assert_eq!(effect.active.as_ref().unwrap().kind, Kind::Ripple);
    }

    #[test]
    fn effects_end_and_never_wake_idle_or_replay_after_hiding() {
        let ctx = egui::Context::default();
        let mut effect = ConnectionEffect::default();
        frame(&mut effect, &ctx, 0.0, true, true, true);
        for n in 1..=45 {
            let output = frame(&mut effect, &ctx, n as f64 / 10.0, true, true, true);
            let delay = output.viewport_output[&egui::ViewportId::ROOT].repaint_delay;
            if n < 40 {
                assert!(delay <= FRAME);
            }
            if n > 42 {
                assert!(delay > Duration::from_secs(60));
            }
        }
        assert!(effect.active.is_none());
        frame(&mut effect, &ctx, 5.0, false, false, true);
        frame(&mut effect, &ctx, 5.1, false, false, false);
        assert!(effect.active.is_none());
        frame(&mut effect, &ctx, 5.2, true, true, false);
        for n in 6..9 {
            let output = frame(&mut effect, &ctx, n as f64, true, true, true);
            assert!(effect.active.is_none());
            assert!(
                output.viewport_output[&egui::ViewportId::ROOT].repaint_delay
                    > Duration::from_secs(60)
            );
        }
        frame(&mut effect, &ctx, 10.0, false, false, true);
        for n in 0..4 {
            frame(&mut effect, &ctx, 12.0 + n as f64, false, false, true);
        }
        assert!(effect.active.is_none());
    }

    #[test]
    fn effect_geometry_is_finite_and_bounded_at_any_window_size() {
        for size in [
            Vec2::new(320.0, 600.0),
            Vec2::new(960.0, 760.0),
            Vec2::new(2560.0, 1440.0),
        ] {
            let bounds = Rect::from_min_size(Pos2::ZERO, size);
            for n in 0..=80 {
                for shape in [
                    ripple(bounds, bounds.center(), n as f32 / 20.0, Color32::WHITE),
                    tear(bounds, bounds.center(), n as f32 / 80.0, Color32::WHITE),
                ] {
                    let Shape::Mesh(mesh) = shape else {
                        panic!("expected mesh")
                    };
                    assert!(mesh.is_valid());
                    assert!(mesh.vertices.len() <= 2175);
                    assert!(
                        mesh.vertices
                            .iter()
                            .all(|v| v.pos.x.is_finite() && v.pos.y.is_finite())
                    );
                }
            }
        }
    }

    #[test]
    fn app_cancels_effect_for_reduced_motion_tray_minimize_and_other_pages() {
        let ctx = egui::Context::default();
        for reason in 0..5 {
            let mut app = App::model(Settings::default(), None, None);
            app.running = true;
            app.want_connected = true;
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                app.sync_connection_effect(ctx)
            });
            assert!(app.connection_effect.active.is_some());
            match reason {
                0 => app.settings.reduced_motion = true,
                1 => app.hidden = true,
                2 => app.page = Page::Routes,
                3 => app.catalog_open = true,
                _ => {}
            }
            let mut input = egui::RawInput::default();
            if reason == 4 {
                input
                    .viewports
                    .get_mut(&egui::ViewportId::ROOT)
                    .unwrap()
                    .minimized = Some(true);
            }
            let _ = ctx.run(input, |ctx| app.sync_connection_effect(ctx));
            assert!(app.connection_effect.active.is_none());
            app.settings.reduced_motion = false;
            app.hidden = false;
            app.page = Page::Connection;
            app.catalog_open = false;
            let mut input = egui::RawInput::default();
            input
                .viewports
                .get_mut(&egui::ViewportId::ROOT)
                .unwrap()
                .minimized = Some(false);
            let _ = ctx.run(input, |ctx| app.sync_connection_effect(ctx));
            assert!(
                app.connection_effect.active.is_none(),
                "returning must not replay the effect"
            );
        }
    }

    #[test]
    fn real_ui_waits_for_running_event_and_returns_to_idle() {
        use eframe::App as _;
        let ctx = egui::Context::default();
        crate::emoji::install(&ctx);
        let mut app = App::model(Settings::default(), None, None);
        let mut native = eframe::Frame::_new_kittest();
        let (tx, rx) = mpsc::channel();
        app.events = Some(rx);
        app.want_connected = true;
        tx.send(Event::Progress("Проверка соединения…")).unwrap();
        for step in 0..65 {
            if step == 10 {
                tx.send(Event::Running).unwrap();
            }
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(960.0, 760.0))),
                    time: Some(step as f64 / 10.0),
                    ..Default::default()
                },
                |ctx| app.update(ctx, &mut native),
            );
            if step < 10 {
                assert!(app.connection_effect.active.is_none());
            } else if step < 50 {
                assert_eq!(
                    app.connection_effect.active.as_ref().unwrap().kind,
                    Kind::Ripple
                );
            } else if step > 54 {
                assert!(app.connection_effect.active.is_none());
                assert!(
                    output.viewport_output[&egui::ViewportId::ROOT].repaint_delay
                        > Duration::from_secs(60)
                );
            }
        }
        assert!(app.running && app.want_connected);
    }
}
