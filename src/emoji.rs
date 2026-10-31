use eframe::egui;
use std::{collections::HashMap, sync::LazyLock};

static MAP: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../assets/emoji-map.json")).expect("bundled emoji map")
});

pub fn install(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "inter".into(),
        egui::FontData::from_static(include_bytes!("../assets/Inter-Regular.ttf")).into(),
    );
    fonts.font_data.insert(
        "inter-display".into(),
        egui::FontData::from_static(include_bytes!("../assets/Inter-SemiBold.ttf")).into(),
    );
    fonts
        .families
        .get_mut(&egui::FontFamily::Proportional)
        .unwrap()
        .insert(0, "inter".into());
    fonts.families.insert(
        egui::FontFamily::Name("display".into()),
        vec!["inter-display".into(), "inter".into()],
    );
    fonts.font_data.insert(
        "emoji".into(),
        egui::FontData::from_static(include_bytes!("../assets/EivroEmoji.ttf")).into(),
    );
    for family in [
        egui::FontFamily::Proportional,
        egui::FontFamily::Monospace,
        egui::FontFamily::Name("display".into()),
    ] {
        fonts
            .families
            .entry(family)
            .or_default()
            .push("emoji".into());
    }
    ctx.set_fonts(fonts);
}

/// Display-only conversion. Stored subscription names remain Unicode.
pub fn text(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut rest = input;
    while !rest.is_empty() {
        let end = rest.char_indices().nth(16).map_or(rest.len(), |(i, _)| i);
        let found = rest[..end]
            .char_indices()
            .map(|(i, c)| i + c.len_utf8())
            .rev()
            .find_map(|n| MAP.get(&rest[..n]).map(|s| (n, s)));
        if let Some((n, alias)) = found {
            result.push_str(alias);
            rest = &rest[n..];
        } else {
            let c = rest.chars().next().unwrap();
            result.push(c);
            rest = &rest[c.len_utf8()..];
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn flags_faces_and_joined_sequences_use_single_glyphs() {
        for s in ["🇩🇪", "🇷🇺", "🇪🇺", "😎", "⚡", "👩‍💻", "👍🏽", "🏳️‍🌈"]
        {
            assert_eq!(text(s).chars().count(), 1, "{s}");
            assert_ne!(text(s), s, "{s}");
        }
        assert!(text("🇩🇪 Германия · 1").ends_with(" Германия · 1"));
    }
}
