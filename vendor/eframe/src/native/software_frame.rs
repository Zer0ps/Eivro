//! The Windows software renderer can spend several CPU cores repainting an
//! unchanged client area. Compare the output after egui has handled input.

use crate::egui::epaint::{ClippedShape, ColorMode, Shape, TextureId};

#[derive(Clone, Copy, PartialEq)]
pub(super) struct Surface {
    pub size: [u32; 2],
    pub scale: f32,
    pub clear: [f32; 4],
}

#[derive(Default)]
pub(super) struct FrameCache {
    last: Option<(Surface, Vec<ClippedShape>)>,
}

impl FrameCache {
    pub fn clear(&mut self) {
        self.last = None;
    }

    pub fn active(&self) -> bool {
        self.last.is_some()
    }

    /// A candidate is retained only for this viewport. Never treat a draw
    /// callback or an externally updated texture as a constant pixel source.
    pub fn unchanged(&mut self, eligible: bool, surface: Surface, shapes: &[ClippedShape]) -> bool {
        if !eligible || !shapes.iter().all(|item| static_shape(&item.shape)) {
            self.clear();
            return false;
        }
        if self
            .last
            .as_ref()
            .is_some_and(|(old, geometry)| *old == surface && geometry == shapes)
        {
            return true;
        }
        self.last = Some((surface, shapes.to_vec()));
        false
    }
}

fn static_shape(shape: &Shape) -> bool {
    match shape {
        Shape::Callback(_) => false,
        Shape::Vec(parts) => parts.iter().all(static_shape),
        Shape::Path(path) => matches!(path.stroke.color, ColorMode::Solid(_)),
        Shape::QuadraticBezier(path) => matches!(path.stroke.color, ColorMode::Solid(_)),
        Shape::CubicBezier(path) => matches!(path.stroke.color, ColorMode::Solid(_)),
        _ => matches!(shape.texture_id(), TextureId::Managed(_)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egui::{Color32, Rect, pos2, vec2};

    #[test]
    fn changes_to_pixels_or_surface_require_a_present() {
        let mut cache = FrameCache::default();
        let mut surface = Surface {
            size: [800, 600],
            scale: 1.,
            clear: [0.; 4],
        };
        let clip_rect = Rect::from_min_size(pos2(0., 0.), vec2(100., 60.));
        let mut shapes = vec![ClippedShape {
            clip_rect,
            shape: Shape::rect_filled(clip_rect, 3., Color32::BLUE),
        }];
        assert!(!cache.unchanged(true, surface, &shapes));
        assert!(cache.unchanged(true, surface, &shapes));
        shapes[0].clip_rect.max.x -= 1.;
        assert!(!cache.unchanged(true, surface, &shapes));
        shapes[0].shape = Shape::rect_filled(clip_rect, 3., Color32::RED);
        assert!(!cache.unchanged(true, surface, &shapes));
        surface.scale = 2.;
        assert!(!cache.unchanged(true, surface, &shapes));
        surface.size[0] += 1;
        assert!(!cache.unchanged(true, surface, &shapes));
        surface.clear[0] = 1.;
        assert!(!cache.unchanged(true, surface, &shapes));
        assert!(cache.unchanged(true, surface, &shapes));
        assert!(!cache.unchanged(false, surface, &shapes));
        assert!(!cache.unchanged(true, surface, &shapes));
        let external = Shape::image(TextureId::User(1), clip_rect, clip_rect, Color32::WHITE);
        shapes[0].shape = Shape::Vec(vec![external]);
        assert!(!cache.unchanged(true, surface, &shapes));
        assert!(!cache.active());
    }
}
