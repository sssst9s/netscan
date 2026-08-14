use egui::{Color32, Context, FontFamily, FontId, Rounding, Stroke, TextStyle, Visuals};

use crate::fonts;

#[allow(dead_code)]
pub mod blueprint {
    use egui::Color32;

    const fn hex(rgb: u32) -> Color32 {
        Color32::from_rgb((rgb >> 16) as u8, (rgb >> 8) as u8, rgb as u8)
    }

    pub const BLACK: Color32 = hex(0x111418);

    pub const DARK_GRAY1: Color32 = hex(0x1C2127);
    pub const DARK_GRAY2: Color32 = hex(0x252A31);
    pub const DARK_GRAY3: Color32 = hex(0x2F343C);
    pub const DARK_GRAY4: Color32 = hex(0x383E47);
    pub const DARK_GRAY5: Color32 = hex(0x404854);

    pub const GRAY1: Color32 = hex(0x5F6B7C);
    pub const GRAY2: Color32 = hex(0x738091);
    pub const GRAY3: Color32 = hex(0x8F99A8);
    pub const GRAY4: Color32 = hex(0xABB3BF);
    pub const GRAY5: Color32 = hex(0xC5CBD3);

    pub const LIGHT_GRAY1: Color32 = hex(0xD3D8DE);
    pub const LIGHT_GRAY2: Color32 = hex(0xDCE0E5);
    pub const LIGHT_GRAY3: Color32 = hex(0xE5E8EB);
    pub const LIGHT_GRAY4: Color32 = hex(0xEDEFF2);
    pub const LIGHT_GRAY5: Color32 = hex(0xF6F7F9);

    pub const WHITE: Color32 = hex(0xFFFFFF);

    pub const BLUE1: Color32 = hex(0x184A90);
    pub const BLUE2: Color32 = hex(0x215DB0);
    pub const BLUE3: Color32 = hex(0x2D72D2);
    pub const BLUE4: Color32 = hex(0x4C90F0);
    pub const BLUE5: Color32 = hex(0x8ABBFF);

    pub const GREEN1: Color32 = hex(0x165A36);
    pub const GREEN2: Color32 = hex(0x1C6E42);
    pub const GREEN3: Color32 = hex(0x238551);
    pub const GREEN4: Color32 = hex(0x32A467);
    pub const GREEN5: Color32 = hex(0x72CA9B);

    pub const ORANGE1: Color32 = hex(0x77450D);
    pub const ORANGE2: Color32 = hex(0x935610);
    pub const ORANGE3: Color32 = hex(0xC87619);
    pub const ORANGE4: Color32 = hex(0xEC9A3C);
    pub const ORANGE5: Color32 = hex(0xFBB360);

    pub const RED1: Color32 = hex(0x8E292C);
    pub const RED2: Color32 = hex(0xAC2F33);
    pub const RED3: Color32 = hex(0xCD4246);
    pub const RED4: Color32 = hex(0xE76A6E);
    pub const RED5: Color32 = hex(0xFA999C);

    pub const CERULEAN3: Color32 = hex(0x147EB3);
    pub const CERULEAN4: Color32 = hex(0x3FA6DA);

    pub const FOREST3: Color32 = hex(0x29A634);
    pub const FOREST4: Color32 = hex(0x43BF4D);

    pub const GOLD3: Color32 = hex(0xD1980B);
    pub const GOLD4: Color32 = hex(0xF0B726);

    pub const INDIGO3: Color32 = hex(0x7961DB);
    pub const INDIGO4: Color32 = hex(0x9881F3);

    pub const LIME3: Color32 = hex(0x8EB125);
    pub const LIME4: Color32 = hex(0xB6D94C);

    pub const ROSE3: Color32 = hex(0xDB2C6F);
    pub const ROSE4: Color32 = hex(0xF5498B);

    pub const SEPIA3: Color32 = hex(0x946638);
    pub const SEPIA4: Color32 = hex(0xAF855A);

    pub const TURQUOISE3: Color32 = hex(0x00A396);
    pub const TURQUOISE4: Color32 = hex(0x13C9BA);

    pub const VERMILION3: Color32 = hex(0xD33D17);
    pub const VERMILION4: Color32 = hex(0xEB6847);

    pub const VIOLET3: Color32 = hex(0x9D3F9D);
    pub const VIOLET4: Color32 = hex(0xBD6BBD);
}

use blueprint as bp;
use palette_tokens as tokens;

pub mod palette_tokens {
    use egui::Color32;

    const fn hex(rgb: u32) -> Color32 {
        Color32::from_rgb((rgb >> 16) as u8, (rgb >> 8) as u8, rgb as u8)
    }

    pub const TITLEBAR: Color32 = hex(0x31363B);

    pub const MAIN_BG: Color32 = hex(0x2A2E32);

    pub const INPUT_BG: Color32 = hex(0x1B1E20);

    pub const INPUT_BORDER: Color32 = hex(0x121415);

    pub const BUTTON_BG: Color32 = hex(0x33373B);

    pub const BUTTON_BORDER: Color32 = hex(0x43474C);

    pub const BORDER: Color32 = hex(0x5F6265);

    pub const TABLE_BG: Color32 = hex(0xE7E6FF);

    pub const SELECTION: Color32 = hex(0x266BE5);

    pub const TEXT: Color32 = hex(0xEFF0F1);

    pub const TEXT_MUTED: Color32 = hex(0xA7ACB1);

    pub const TEXT_FAINT: Color32 = hex(0x7F8489);
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Ink {
    pub text: Color32,
    pub muted: Color32,
    pub faint: Color32,
    pub success: Color32,
    pub warning: Color32,
    pub danger: Color32,
    pub info: Color32,
    pub accent: Color32,
}

pub const TABLE_INK: Ink = Ink {
    text: bp::DARK_GRAY1,
    muted: bp::GRAY1,
    faint: bp::GRAY2,
    success: bp::GREEN2,
    warning: bp::ORANGE2,
    danger: bp::RED2,
    info: bp::BLUE2,
    accent: bp::BLUE2,
};

pub const SELECTED_INK: Ink = Ink {
    text: bp::WHITE,
    muted: bp::LIGHT_GRAY1,
    faint: bp::LIGHT_GRAY1,
    success: bp::WHITE,
    warning: bp::WHITE,
    danger: bp::WHITE,
    info: bp::WHITE,
    accent: bp::WHITE,
};

#[derive(Debug, Clone, Copy)]
pub struct Palette {
    pub titlebar: Color32,
    pub window: Color32,
    pub panel: Color32,
    pub raised: Color32,
    pub sunken: Color32,
    pub hover: Color32,
    pub active: Color32,
    pub line: Color32,
    pub button_border: Color32,
    pub sunken_border: Color32,
    pub focus: Color32,
    pub text: Color32,
    pub muted: Color32,
    pub faint: Color32,
    pub accent: Color32,
    pub on_accent: Color32,
    pub accent_text: Color32,
    pub success: Color32,
    pub warning: Color32,
    pub danger: Color32,
    pub info: Color32,
    pub info_fill: Color32,
    pub success_fill: Color32,
    pub warning_fill: Color32,
    pub danger_fill: Color32,
    pub table: Color32,
    pub selected: Color32,
}

impl Palette {
    pub fn ink(&self) -> Ink {
        Ink {
            text: self.text,
            muted: self.muted,
            faint: self.faint,
            success: self.success,
            warning: self.warning,
            danger: self.danger,
            info: self.info,
            accent: self.accent_text,
        }
    }

    pub fn band(&self, intent: Intent) -> (Color32, Ink) {
        let fill = match intent {
            Intent::Info => self.info_fill,
            Intent::Success => self.success_fill,
            Intent::Warning => self.warning_fill,
            Intent::Danger => self.danger_fill,
        };
        (fill, SELECTED_INK)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    Info,
    Success,
    Warning,
    Danger,
}

pub const DARK: Palette = Palette {
    titlebar: tokens::TITLEBAR,
    window: tokens::MAIN_BG,
    panel: tokens::MAIN_BG,
    raised: tokens::INPUT_BG,
    sunken: tokens::INPUT_BG,
    hover: tokens::BUTTON_BG,
    active: tokens::BUTTON_BORDER,
    line: tokens::BUTTON_BORDER,
    button_border: tokens::INPUT_BORDER,
    sunken_border: tokens::INPUT_BORDER,
    focus: tokens::BORDER,
    text: tokens::TEXT,
    muted: tokens::TEXT_MUTED,
    faint: tokens::TEXT_FAINT,
    accent: bp::BLUE3,
    on_accent: bp::WHITE,
    accent_text: bp::BLUE5,
    success: bp::GREEN5,
    warning: bp::ORANGE4,
    danger: bp::RED4,
    info: bp::BLUE5,
    info_fill: bp::BLUE2,
    success_fill: bp::GREEN2,
    warning_fill: bp::ORANGE2,
    danger_fill: bp::RED2,
    table: tokens::TABLE_BG,
    selected: tokens::SELECTION,
};

pub const LIGHT: Palette = Palette {
    titlebar: bp::LIGHT_GRAY3,
    window: bp::LIGHT_GRAY5,
    panel: bp::LIGHT_GRAY5,
    raised: bp::WHITE,
    sunken: bp::WHITE,
    hover: bp::LIGHT_GRAY3,
    active: bp::LIGHT_GRAY2,
    line: bp::LIGHT_GRAY1,
    button_border: bp::LIGHT_GRAY1,
    sunken_border: bp::LIGHT_GRAY1,
    focus: bp::GRAY2,
    text: bp::DARK_GRAY1,
    muted: bp::GRAY1,
    faint: bp::GRAY2,
    accent: bp::BLUE3,
    on_accent: bp::WHITE,
    accent_text: bp::BLUE2,
    success: bp::GREEN2,
    warning: bp::ORANGE2,
    danger: bp::RED2,
    info: bp::BLUE2,
    info_fill: bp::BLUE2,
    success_fill: bp::GREEN2,
    warning_fill: bp::ORANGE2,
    danger_fill: bp::RED2,
    table: tokens::TABLE_BG,
    selected: tokens::SELECTION,
};

impl Palette {
    pub fn categorical(&self, index: usize, dark: bool) -> Color32 {
        const BRIGHT: &[Color32] = &[
            bp::BLUE4,
            bp::TURQUOISE4,
            bp::VIOLET4,
            bp::LIME4,
            bp::ROSE4,
            bp::CERULEAN4,
            bp::GOLD4,
            bp::INDIGO4,
            bp::FOREST4,
            bp::VERMILION4,
            bp::SEPIA4,
        ];
        const DEEP: &[Color32] = &[
            bp::BLUE3,
            bp::TURQUOISE3,
            bp::VIOLET3,
            bp::LIME3,
            bp::ROSE3,
            bp::CERULEAN3,
            bp::GOLD3,
            bp::INDIGO3,
            bp::FOREST3,
            bp::VERMILION3,
            bp::SEPIA3,
        ];
        let series = if dark { BRIGHT } else { DEEP };
        series[index % series.len()]
    }
}

pub fn palette(ctx: &Context) -> Palette {
    if ctx.style().visuals.dark_mode {
        DARK
    } else {
        LIGHT
    }
}

static ACTIVE: std::sync::RwLock<Palette> = std::sync::RwLock::new(DARK);

static ACTIVE_DARK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

pub fn current() -> Palette {
    *ACTIVE
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub fn sync(ctx: &Context) {
    let dark = ctx.style().visuals.dark_mode;
    if dark != ACTIVE_DARK.load(std::sync::atomic::Ordering::Relaxed) {
        apply_style(ctx);
    }
}

pub const UNIT: f32 = 4.0;

pub const RADIUS: f32 = 2.0;

pub const WINDOW_RADIUS: f32 = 13.0;

pub const TITLE_BAR_HEIGHT: f32 = 34.0;

pub fn apply(ctx: &Context) {
    fonts::install(ctx);
    apply_style(ctx);
}

pub fn apply_style(ctx: &Context) {
    let dark = ctx.style().visuals.dark_mode;
    let palette = if dark { DARK } else { LIGHT };
    let mut style = (*ctx.style()).clone();

    style.text_styles = [
        (
            TextStyle::Heading,
            FontId::new(15.0, fonts::family(fonts::BOLD)),
        ),
        (TextStyle::Body, FontId::new(13.0, FontFamily::Proportional)),
        (
            TextStyle::Button,
            FontId::new(12.5, fonts::family(fonts::MEDIUM)),
        ),
        (
            TextStyle::Small,
            FontId::new(11.0, FontFamily::Proportional),
        ),
        (
            TextStyle::Monospace,
            FontId::new(12.0, FontFamily::Monospace),
        ),
    ]
    .into();

    style.spacing.item_spacing = egui::vec2(UNIT * 1.5, UNIT);
    style.spacing.window_margin = egui::Margin::same(UNIT * 2.0);
    style.spacing.button_padding = egui::vec2(UNIT * 2.5, UNIT * 1.5);
    style.spacing.menu_margin = egui::Margin::same(UNIT);
    style.spacing.indent = UNIT * 4.0;
    style.spacing.slider_width = 140.0;
    style.spacing.combo_width = 150.0;
    style.spacing.interact_size.y = 20.0;
    style.spacing.scroll.bar_width = 8.0;
    style.spacing.scroll.floating = false;

    let mut visuals = if dark {
        Visuals::dark()
    } else {
        Visuals::light()
    };
    visuals.dark_mode = dark;

    visuals.panel_fill = palette.panel;
    visuals.window_fill = palette.raised;
    visuals.extreme_bg_color = palette.sunken;

    visuals.faint_bg_color = if dark {
        Color32::from_rgba_unmultiplied(0xff, 0xff, 0xff, 5)
    } else {
        Color32::from_rgba_unmultiplied(0x00, 0x00, 0x00, 6)
    };
    visuals.code_bg_color = palette.sunken;

    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, palette.sunken_border);
    visuals.hyperlink_color = palette.accent_text;

    visuals.selection.bg_fill = palette.selected;
    visuals.selection.stroke = Stroke::new(1.0_f32, SELECTED_INK.text);
    visuals.window_stroke = Stroke::new(1.0_f32, palette.line);
    visuals.override_text_color = Some(palette.text);

    let radius = Rounding::same(RADIUS);
    let widget =
        |target: &mut egui::style::WidgetVisuals, fill: Color32, weak: Color32, stroke: Color32| {
            target.bg_fill = fill;
            target.weak_bg_fill = weak;
            target.bg_stroke = Stroke::new(1.0_f32, stroke);
            target.fg_stroke = Stroke::new(1.0_f32, palette.text);
            target.rounding = radius;
            target.expansion = 0.0;
        };

    widget(
        &mut visuals.widgets.noninteractive,
        palette.panel,
        palette.panel,
        palette.line,
    );

    widget(
        &mut visuals.widgets.inactive,
        palette.raised,
        palette.raised,
        palette.button_border,
    );
    widget(
        &mut visuals.widgets.hovered,
        palette.hover,
        palette.hover,
        palette.muted,
    );
    widget(
        &mut visuals.widgets.active,
        palette.active,
        palette.active,
        palette.focus,
    );
    widget(
        &mut visuals.widgets.open,
        palette.hover,
        palette.hover,
        palette.button_border,
    );
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, palette.muted);

    visuals.window_shadow = egui::epaint::Shadow::NONE;
    visuals.popup_shadow = egui::epaint::Shadow {
        offset: egui::vec2(0.0, 2.0),
        blur: 10.0,
        spread: 0.0,
        color: Color32::from_black_alpha(if dark { 140 } else { 40 }),
    };
    visuals.window_rounding = radius;
    visuals.menu_rounding = radius;
    visuals.striped = true;
    visuals.indent_has_left_vline = false;

    style.visuals = visuals;
    ctx.set_style(style);

    match ACTIVE.write() {
        Ok(mut active) => *active = palette,
        Err(poisoned) => *poisoned.into_inner() = palette,
    }
    ACTIVE_DARK.store(dark, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    static THEME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn context(dark: bool) -> (Context, std::sync::MutexGuard<'static, ()>) {
        let guard = THEME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let ctx = Context::default();
        ctx.set_visuals(if dark {
            Visuals::dark()
        } else {
            Visuals::light()
        });

        ctx.style_mut(|style| style.visuals.dark_mode = dark);
        apply_style(&ctx);
        (ctx, guard)
    }

    fn luminance(colour: Color32) -> f32 {
        let channel = |value: u8| {
            let v = f32::from(value) / 255.0;
            if v <= 0.03928 {
                v / 12.92
            } else {
                ((v + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * channel(colour.r()) + 0.7152 * channel(colour.g()) + 0.0722 * channel(colour.b())
    }

    fn contrast(a: Color32, b: Color32) -> f32 {
        let (x, y) = (luminance(a), luminance(b));
        let (high, low) = if x > y { (x, y) } else { (y, x) };
        (high + 0.05) / (low + 0.05)
    }

    fn surfaces(palette: &Palette) -> [(&'static str, Color32); 7] {
        [
            ("titlebar", palette.titlebar),
            ("window", palette.window),
            ("panel", palette.panel),
            ("raised", palette.raised),
            ("sunken", palette.sunken),
            ("hover", palette.hover),
            ("active", palette.active),
        ]
    }

    fn tokens() -> Vec<Color32> {
        vec![
            bp::BLACK,
            bp::DARK_GRAY1,
            bp::DARK_GRAY2,
            bp::DARK_GRAY3,
            bp::DARK_GRAY4,
            bp::DARK_GRAY5,
            bp::GRAY1,
            bp::GRAY2,
            bp::GRAY3,
            bp::GRAY4,
            bp::GRAY5,
            bp::LIGHT_GRAY1,
            bp::LIGHT_GRAY2,
            bp::LIGHT_GRAY3,
            bp::LIGHT_GRAY4,
            bp::LIGHT_GRAY5,
            bp::WHITE,
            bp::BLUE1,
            bp::BLUE2,
            bp::BLUE3,
            bp::BLUE4,
            bp::BLUE5,
            bp::GREEN1,
            bp::GREEN2,
            bp::GREEN3,
            bp::GREEN4,
            bp::GREEN5,
            bp::ORANGE1,
            bp::ORANGE2,
            bp::ORANGE3,
            bp::ORANGE4,
            bp::ORANGE5,
            bp::RED1,
            bp::RED2,
            bp::RED3,
            bp::RED4,
            bp::RED5,
        ]
    }

    #[test]
    fn intents_and_text_are_blueprint_tokens() {
        let tokens = tokens();
        for (name, palette) in [("dark", DARK), ("light", LIGHT)] {
            for (field, colour) in [
                ("accent", palette.accent),
                ("on_accent", palette.on_accent),
                ("accent_text", palette.accent_text),
                ("success", palette.success),
                ("warning", palette.warning),
                ("danger", palette.danger),
                ("info", palette.info),
                ("info_fill", palette.info_fill),
                ("success_fill", palette.success_fill),
                ("warning_fill", palette.warning_fill),
                ("danger_fill", palette.danger_fill),
            ] {
                assert!(
                    tokens.contains(&colour),
                    "{name}.{field} = {colour:?} is not a Blueprint token"
                );
            }
        }
    }

    #[test]
    fn light_surfaces_still_come_from_blueprints_ramp() {
        let tokens = tokens();
        for (name, colour) in surfaces(&LIGHT) {
            assert!(
                tokens.contains(&colour),
                "light.{name} = {colour:?} is not a Blueprint token"
            );
        }
    }

    #[test]
    fn the_grey_ramp_is_monotonic() {
        let dark_ramp = [
            bp::BLACK,
            bp::DARK_GRAY1,
            bp::DARK_GRAY2,
            bp::DARK_GRAY3,
            bp::DARK_GRAY4,
            bp::DARK_GRAY5,
        ];
        for pair in dark_ramp.windows(2) {
            assert!(
                luminance(pair[1]) > luminance(pair[0]),
                "{pair:?} is out of order"
            );
        }
        let light_ramp = [
            bp::LIGHT_GRAY1,
            bp::LIGHT_GRAY2,
            bp::LIGHT_GRAY3,
            bp::LIGHT_GRAY4,
            bp::LIGHT_GRAY5,
        ];
        for pair in light_ramp.windows(2) {
            assert!(
                luminance(pair[1]) > luminance(pair[0]),
                "{pair:?} is out of order"
            );
        }
    }

    #[test]
    fn body_text_is_readable_on_every_surface() {
        for (name, palette) in [("dark", DARK), ("light", LIGHT)] {
            for (surface_name, surface) in surfaces(&palette) {
                let ratio = contrast(palette.text, surface);
                assert!(
                    ratio >= 4.5,
                    "{name} text on {surface_name} is only {ratio:.2}:1"
                );
            }
        }
    }

    #[test]
    fn muted_text_stays_legible() {
        for (name, palette) in [("dark", DARK), ("light", LIGHT)] {
            for (surface_name, surface) in [
                ("window", palette.window),
                ("panel", palette.panel),
                ("raised", palette.raised),
                ("sunken", palette.sunken),
            ] {
                let ratio = contrast(palette.muted, surface);
                assert!(
                    ratio >= 3.0,
                    "{name} muted text on {surface_name} is only {ratio:.2}:1"
                );
            }
        }
    }

    #[test]
    fn intent_colours_are_readable_as_text() {
        for (name, palette) in [("dark", DARK), ("light", LIGHT)] {
            for (intent_name, intent) in [
                ("success", palette.success),
                ("warning", palette.warning),
                ("danger", palette.danger),
                ("info", palette.info),
                ("accent_text", palette.accent_text),
            ] {
                for (surface_name, surface) in [
                    ("panel", palette.panel),
                    ("raised", palette.raised),
                    ("sunken", palette.sunken),
                ] {
                    let ratio = contrast(intent, surface);
                    assert!(
                        ratio >= 3.0,
                        "{name} {intent_name} on {surface_name} is only {ratio:.2}:1"
                    );
                }
            }
        }
    }

    #[test]
    fn accent_text_is_readable_on_the_accent_fill() {
        for (name, palette) in [("dark", DARK), ("light", LIGHT)] {
            let ratio = contrast(palette.on_accent, palette.accent);
            assert!(
                ratio >= 4.5,
                "{name} on-accent contrast is only {ratio:.2}:1"
            );
        }
    }

    fn ink_colours(ink: &Ink) -> [(&'static str, Color32, f32); 8] {
        [
            ("text", ink.text, 4.5),
            ("muted", ink.muted, 3.0),
            ("faint", ink.faint, 3.0),
            ("success", ink.success, 3.0),
            ("warning", ink.warning, 3.0),
            ("danger", ink.danger, 3.0),
            ("info", ink.info, 3.0),
            ("accent", ink.accent, 3.0),
        ]
    }

    #[test]
    fn every_ink_is_readable_on_the_surface_it_belongs_to() {
        let mut cases: Vec<(&str, Color32, Ink)> = vec![
            ("the host list's band", DARK.table, TABLE_INK),
            ("a selected row", DARK.selected, SELECTED_INK),
        ];
        for (name, palette) in [("dark", DARK), ("light", LIGHT)] {
            cases.push((name, palette.sunken, palette.ink()));
            cases.push((name, palette.panel, palette.ink()));
        }
        for (surface_name, surface, ink) in cases {
            for (field, colour, minimum) in ink_colours(&ink) {
                let ratio = contrast(colour, surface);
                assert!(
                    ratio >= minimum,
                    "{field} on {surface_name} is only {ratio:.2}:1"
                );
            }
        }
    }

    #[test]
    fn a_filled_status_band_carries_its_text() {
        for (name, palette) in [("dark", DARK), ("light", LIGHT)] {
            for intent in [
                Intent::Info,
                Intent::Success,
                Intent::Warning,
                Intent::Danger,
            ] {
                let (fill, ink) = palette.band(intent);
                for (field, colour, minimum) in ink_colours(&ink) {
                    let ratio = contrast(colour, fill);
                    assert!(
                        ratio >= minimum,
                        "{name} {intent:?} band: {field} is only {ratio:.2}:1"
                    );
                }
            }
        }
    }

    #[test]
    fn the_two_tables_and_the_selection_are_told_apart() {
        assert_ne!(DARK.table, DARK.selected);
        assert_ne!(DARK.table, DARK.sunken);
        assert!(
            contrast(DARK.table, DARK.selected) >= 3.0,
            "a selected row has to stand out from the band it sits in"
        );
        assert!(
            contrast(DARK.sunken, DARK.selected) >= 1.5,
            "and from the port list's ground"
        );
    }

    #[test]
    fn one_selection_colour_is_used_everywhere() {
        let (ctx, _guard) = context(true);
        assert_eq!(ctx.style().visuals.selection.bg_fill, DARK.selected);
        assert_eq!(
            ctx.style().visuals.selection.stroke.color,
            SELECTED_INK.text
        );
        assert_eq!(DARK.selected, LIGHT.selected);
    }

    #[test]
    fn intents_are_distinguishable_from_each_other() {
        for (name, palette) in [("dark", DARK), ("light", LIGHT)] {
            let intents = [palette.success, palette.warning, palette.danger];
            for (i, a) in intents.iter().enumerate() {
                for b in intents.iter().skip(i + 1) {
                    assert_ne!(a, b, "{name} reuses a colour for two intents");
                }
            }
        }
    }

    #[test]
    fn dark_surfaces_stack_the_way_the_design_intends() {
        assert!(
            luminance(DARK.titlebar) > luminance(DARK.window),
            "the title bar should be the one surface that lifts off the ground"
        );
        assert_eq!(
            DARK.panel, DARK.window,
            "the chrome and the panes share one tone; that is the minimalism"
        );
        assert!(
            luminance(DARK.sunken) < luminance(DARK.window),
            "a field should read as a recess in the ground"
        );
        assert_eq!(
            DARK.raised, DARK.sunken,
            "a button is a recess like a field, not a raised block"
        );
        assert!(
            luminance(DARK.button_border) < luminance(DARK.raised),
            "a control's outline is darker than its face, which is what makes \
             the recess read as one"
        );
        assert!(
            luminance(DARK.line) > luminance(DARK.window),
            "a hairline must be visible against the ground it divides"
        );

        assert!(
            luminance(DARK.hover) > luminance(DARK.raised)
                && luminance(DARK.active) > luminance(DARK.hover),
            "controls should brighten through hover and press"
        );
        assert!(
            luminance(DARK.focus) > luminance(DARK.active),
            "the focused outline should be the strongest of them"
        );
    }

    #[test]
    fn the_window_wears_the_specified_colours() {
        assert_eq!(DARK.titlebar, Color32::from_rgb(0x31, 0x36, 0x3B));
        assert_eq!(DARK.window, Color32::from_rgb(0x2A, 0x2E, 0x32));
        assert_eq!(DARK.panel, Color32::from_rgb(0x2A, 0x2E, 0x32));
        assert_eq!(DARK.sunken, Color32::from_rgb(0x1B, 0x1E, 0x20));
        assert_eq!(DARK.raised, Color32::from_rgb(0x1B, 0x1E, 0x20));
        assert_eq!(DARK.sunken_border, Color32::from_rgb(0x12, 0x14, 0x15));
        assert_eq!(DARK.button_border, Color32::from_rgb(0x12, 0x14, 0x15));
        assert_eq!(DARK.table, Color32::from_rgb(0xE7, 0xE6, 0xFF));
        assert_eq!(DARK.selected, Color32::from_rgb(0x26, 0x6B, 0xE5));
    }

    #[test]
    fn dark_surfaces_are_near_neutral() {
        for (name, colour) in [
            ("window", DARK.window),
            ("panel", DARK.panel),
            ("raised", DARK.raised),
            ("sunken", DARK.sunken),
            ("hover", DARK.hover),
            ("active", DARK.active),
            ("line", DARK.line),
        ] {
            let channels = [colour.r(), colour.g(), colour.b()];
            let spread = channels.iter().max().unwrap() - channels.iter().min().unwrap();
            assert!(spread <= 12, "dark.{name} has a {spread}-point colour cast");
        }
    }

    #[test]
    fn the_ground_is_near_neutral_grey() {
        const BLUEPRINT_MAX_CAST: u8 = 20;
        for (name, palette) in [("dark", DARK), ("light", LIGHT)] {
            for (surface_name, surface) in surfaces(&palette) {
                let channels = [surface.r(), surface.g(), surface.b()];
                let spread = channels.iter().max().unwrap() - channels.iter().min().unwrap();
                assert!(
                    spread <= BLUEPRINT_MAX_CAST,
                    "{name}.{surface_name} has a {spread}-point colour cast"
                );
            }
        }
    }

    #[test]
    fn no_surface_leans_warm() {
        for (name, palette) in [("dark", DARK), ("light", LIGHT)] {
            for (surface_name, surface) in surfaces(&palette) {
                assert!(
                    surface.b() >= surface.r(),
                    "{name}.{surface_name} leans warm"
                );
            }
        }
    }

    #[test]
    fn categorical_colours_cycle_and_differ() {
        let palette = DARK;
        let first: Vec<Color32> = (0..6).map(|i| palette.categorical(i, true)).collect();
        for (i, a) in first.iter().enumerate() {
            for b in first.iter().skip(i + 1) {
                assert_ne!(a, b, "the categorical series repeats within one screen");
            }
        }

        assert_eq!(palette.categorical(0, true), palette.categorical(11, true));
        assert_ne!(palette.categorical(0, true), palette.categorical(0, false));
    }

    #[test]
    fn styling_uses_the_bundled_faces_where_it_should() {
        let (ctx, _guard) = context(true);
        let style = ctx.style();
        assert_eq!(
            style.text_styles[&TextStyle::Heading].family,
            fonts::family(fonts::BOLD)
        );
        assert_eq!(
            style.text_styles[&TextStyle::Monospace].family,
            FontFamily::Monospace
        );
    }

    #[test]
    fn spacing_follows_the_rhythm() {
        let (ctx, _guard) = context(true);
        let spacing = &ctx.style().spacing;
        for value in [
            spacing.item_spacing.x,
            spacing.item_spacing.y,
            spacing.indent,
            spacing.button_padding.x,
            spacing.button_padding.y,
        ] {
            let steps = value / (UNIT / 2.0);
            assert!(
                (steps - steps.round()).abs() < 1e-4,
                "{value} is not on the {UNIT}-pixel rhythm"
            );
        }
    }

    #[test]
    fn controls_use_blueprints_two_pixel_radius() {
        let (ctx, _guard) = context(true);
        let widgets = &ctx.style().visuals.widgets;
        for (name, visuals) in [
            ("inactive", &widgets.inactive),
            ("hovered", &widgets.hovered),
            ("active", &widgets.active),
            ("open", &widgets.open),
            ("noninteractive", &widgets.noninteractive),
        ] {
            assert_eq!(
                visuals.rounding,
                Rounding::same(RADIUS),
                "{name} does not use the system radius"
            );
        }
        assert_eq!(ctx.style().visuals.window_rounding, Rounding::same(RADIUS));
    }

    #[test]
    fn interaction_targets_stay_clickable() {
        let (ctx, _guard) = context(true);
        assert!(ctx.style().spacing.interact_size.y >= 20.0);
    }

    #[test]
    fn both_themes_apply_their_own_palette() {
        {
            let (ctx, _guard) = context(true);
            assert_eq!(ctx.style().visuals.panel_fill, DARK.panel);
            assert_eq!(palette(&ctx).panel, DARK.panel);
        }
        let (ctx, _guard) = context(false);
        assert_eq!(ctx.style().visuals.panel_fill, LIGHT.panel);
        assert_eq!(palette(&ctx).panel, LIGHT.panel);
    }

    #[test]
    fn window_shadows_are_off_because_the_frame_is_ours() {
        let (ctx, _guard) = context(true);
        assert_eq!(
            ctx.style().visuals.window_shadow,
            egui::epaint::Shadow::NONE
        );
    }

    #[test]
    fn the_active_palette_follows_the_applied_theme() {
        {
            let (_ctx, _guard) = context(false);
            assert_eq!(current().panel, LIGHT.panel);
        }
        let (_ctx, _guard) = context(true);
        assert_eq!(current().panel, DARK.panel);
    }

    #[test]
    fn switching_theme_moves_the_active_palette_with_it() {
        let (ctx, _guard) = context(true);
        assert_eq!(current().window, DARK.window);

        ctx.style_mut(|style| style.visuals.dark_mode = false);
        sync(&ctx);
        assert_eq!(current().window, LIGHT.window, "sync did not follow");
        assert_eq!(
            palette(&ctx).window,
            current().window,
            "the two ways of asking for the palette must agree"
        );

        ctx.style_mut(|style| style.visuals.dark_mode = true);
        sync(&ctx);
        assert_eq!(current().window, DARK.window, "and back again");
    }

    #[test]
    fn syncing_an_unchanged_theme_leaves_everything_alone() {
        let (ctx, _guard) = context(true);
        let before = ctx.style().spacing.item_spacing;
        sync(&ctx);
        sync(&ctx);
        assert_eq!(ctx.style().spacing.item_spacing, before);
        assert_eq!(current().window, DARK.window);
    }

    #[test]
    fn applying_the_style_twice_is_stable() {
        let (ctx, _guard) = context(true);
        let first = ctx.style().spacing.item_spacing;
        apply_style(&ctx);
        assert_eq!(ctx.style().spacing.item_spacing, first);
    }
}
