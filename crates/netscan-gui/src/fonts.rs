use std::sync::Arc;

use egui::{FontData, FontDefinitions, FontFamily};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Weight {
    pub name: &'static str,
    bytes: &'static [u8],
}

pub const REGULAR: Weight = Weight {
    name: "ember",
    bytes: include_bytes!("../../../assets/AmazonEmberDisplay_Rg.ttf"),
};

pub const MEDIUM: Weight = Weight {
    name: "ember-medium",
    bytes: include_bytes!("../../../assets/AmazonEmberDisplay_Md.ttf"),
};

pub const BOLD: Weight = Weight {
    name: "ember-bold",
    bytes: include_bytes!("../../../assets/AmazonEmberDisplay_Bd.ttf"),
};

pub const HEAVY: Weight = Weight {
    name: "ember-heavy",
    bytes: include_bytes!("../../../assets/AmazonEmberDisplay_He.ttf"),
};

pub const LIGHT: Weight = Weight {
    name: "ember-light",
    bytes: include_bytes!("../../../assets/AmazonEmberDisplay_Lt.ttf"),
};

pub const ITALIC: Weight = Weight {
    name: "ember-italic",
    bytes: include_bytes!("../../../assets/AmazonEmber_RgIt.ttf"),
};

pub const ALL: &[Weight] = &[REGULAR, MEDIUM, BOLD, HEAVY, LIGHT, ITALIC];

pub fn embedded_bytes() -> usize {
    ALL.iter().map(|weight| weight.bytes.len()).sum()
}

pub fn family(weight: Weight) -> FontFamily {
    FontFamily::Name(Arc::from(weight.name))
}

pub fn definitions() -> FontDefinitions {
    let mut fonts = FontDefinitions::default();

    for weight in ALL {
        fonts
            .font_data
            .insert(weight.name.to_owned(), FontData::from_static(weight.bytes));
    }

    let proportional = fonts.families.entry(FontFamily::Proportional).or_default();
    proportional.insert(0, REGULAR.name.to_owned());

    let fallbacks: Vec<String> = fonts
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();

    for weight in ALL {
        let mut chain = vec![weight.name.to_owned()];
        chain.extend(
            fallbacks
                .iter()
                .filter(|name| *name != weight.name)
                .cloned(),
        );
        fonts.families.insert(family(*weight), chain);
    }

    fonts.families.entry(FontFamily::Monospace).or_default();

    fonts
}

pub fn install(ctx: &egui::Context) {
    ctx.set_fonts(definitions());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_weight_is_embedded_and_non_empty() {
        for weight in ALL {
            assert!(!weight.bytes.is_empty(), "{} is empty", weight.name);
            assert!(
                weight.bytes.len() > 10_000,
                "{} looks too small to be a font ({} bytes)",
                weight.name,
                weight.bytes.len()
            );
        }
        assert!(embedded_bytes() > 500_000);
    }

    #[test]
    fn every_embedded_file_is_a_truetype_font() {
        for weight in ALL {
            let magic = &weight.bytes[..4];
            assert!(
                magic == [0x00, 0x01, 0x00, 0x00]
                    || magic == b"true"
                    || magic == b"ttcf"
                    || magic == b"OTTO",
                "{} does not look like a font: {magic:?}",
                weight.name
            );
        }
    }

    #[test]
    fn weight_names_are_unique() {
        let mut names: Vec<&str> = ALL.iter().map(|w| w.name).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(before, names.len(), "two weights share a name");
    }

    #[test]
    fn definitions_register_every_weight() {
        let fonts = definitions();
        for weight in ALL {
            assert!(
                fonts.font_data.contains_key(weight.name),
                "{} was not registered",
                weight.name
            );
            assert!(
                fonts.families.contains_key(&family(*weight)),
                "{} has no family handle",
                weight.name
            );
        }
    }

    #[test]
    fn ember_leads_the_proportional_chain_but_keeps_fallbacks() {
        let fonts = definitions();
        let proportional = &fonts.families[&FontFamily::Proportional];
        assert_eq!(proportional[0], REGULAR.name);
        assert!(
            proportional.len() > 1,
            "egui's fallback faces must survive, or unsupported glyphs render as tofu"
        );
    }

    #[test]
    fn each_named_family_starts_with_its_own_weight() {
        let fonts = definitions();
        for weight in ALL {
            let chain = &fonts.families[&family(*weight)];
            assert_eq!(chain[0], weight.name);
            assert!(chain.len() > 1, "{} has no fallbacks", weight.name);
            assert_eq!(
                chain.iter().filter(|name| *name == weight.name).count(),
                1,
                "{} appears twice in its own chain",
                weight.name
            );
        }
    }

    #[test]
    fn monospace_is_left_to_the_bundled_face() {
        let fonts = definitions();
        let monospace = &fonts.families[&FontFamily::Monospace];
        assert!(!monospace.is_empty());
        assert!(
            !ALL.iter()
                .any(|w| monospace.first().is_some_and(|first| first == w.name)),
            "monospace must not lead with a proportional face"
        );
    }

    #[test]
    fn text_lays_out_in_every_bundled_weight() {
        let ctx = egui::Context::default();
        install(&ctx);
        let _ = ctx.run(Default::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |_| {});
        });

        ctx.fonts(|fonts| {
            for weight in ALL {
                let width = fonts
                    .layout_no_wrap(
                        "192.168.1.1".to_string(),
                        egui::FontId::new(12.0, family(*weight)),
                        egui::Color32::WHITE,
                    )
                    .size()
                    .x;
                assert!(width > 0.0, "{} laid out nothing", weight.name);
            }
        });
    }

    #[test]
    fn heavier_cuts_are_wider_than_lighter_ones() {
        let ctx = egui::Context::default();
        install(&ctx);
        let _ = ctx.run(Default::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |_| {});
        });

        let width = |weight: Weight| {
            ctx.fonts(|fonts| {
                fonts
                    .layout_no_wrap(
                        "netscan".to_string(),
                        egui::FontId::new(32.0, family(weight)),
                        egui::Color32::WHITE,
                    )
                    .size()
                    .x
            })
        };
        assert!(
            width(HEAVY) > width(LIGHT),
            "heavy ({}) should be wider than light ({})",
            width(HEAVY),
            width(LIGHT)
        );
    }
}
