pub mod path;
pub mod raster;

use std::collections::HashMap;

use egui::{Color32, Context, Painter, Rect, TextureHandle, TextureOptions};

const SOURCE_BOX: f32 = 16.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Icon {
    Play,
    Stop,
    Refresh,
    Gear,
    Folder,
    Save,
    Search,
    ArrowLeft,
    ArrowRight,
    SkipStart,
    SkipEnd,
    Eye,
    Compare,
    Help,
    CaretUp,
    CaretDown,
}

impl Icon {
    #[allow(dead_code)]
    pub const ALL: &'static [Icon] = &[
        Icon::Play,
        Icon::Stop,
        Icon::Refresh,
        Icon::Gear,
        Icon::Folder,
        Icon::Save,
        Icon::Search,
        Icon::ArrowLeft,
        Icon::ArrowRight,
        Icon::SkipStart,
        Icon::SkipEnd,
        Icon::Eye,
        Icon::Compare,
        Icon::Help,
        Icon::CaretUp,
        Icon::CaretDown,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Icon::Play => "play",
            Icon::Stop => "stop",
            Icon::Refresh => "refresh",
            Icon::Gear => "cog",
            Icon::Folder => "folder-open",
            Icon::Save => "floppy-disk",
            Icon::Search => "search",
            Icon::ArrowLeft => "arrow-left",
            Icon::ArrowRight => "arrow-right",
            Icon::SkipStart => "step-backward",
            Icon::SkipEnd => "step-forward",
            Icon::Eye => "eye-open",
            Icon::Compare => "comparison",
            Icon::Help => "help",
            Icon::CaretUp => "caret-up",
            Icon::CaretDown => "caret-down",
        }
    }

    pub fn data(self) -> &'static str {
        match self {
            Icon::Play => include_str!("../../../../assets/blueprint-icons/play.path"),
            Icon::Stop => include_str!("../../../../assets/blueprint-icons/stop.path"),
            Icon::Refresh => include_str!("../../../../assets/blueprint-icons/refresh.path"),
            Icon::Gear => include_str!("../../../../assets/blueprint-icons/cog.path"),
            Icon::Folder => include_str!("../../../../assets/blueprint-icons/folder-open.path"),
            Icon::Save => include_str!("../../../../assets/blueprint-icons/floppy-disk.path"),
            Icon::Search => include_str!("../../../../assets/blueprint-icons/search.path"),
            Icon::ArrowLeft => include_str!("../../../../assets/blueprint-icons/arrow-left.path"),
            Icon::ArrowRight => include_str!("../../../../assets/blueprint-icons/arrow-right.path"),
            Icon::SkipStart => {
                include_str!("../../../../assets/blueprint-icons/step-backward.path")
            }
            Icon::SkipEnd => include_str!("../../../../assets/blueprint-icons/step-forward.path"),
            Icon::Eye => include_str!("../../../../assets/blueprint-icons/eye-open.path"),
            Icon::Compare => include_str!("../../../../assets/blueprint-icons/comparison.path"),
            Icon::Help => include_str!("../../../../assets/blueprint-icons/help.path"),
            Icon::CaretUp => include_str!("../../../../assets/blueprint-icons/caret-up.path"),
            Icon::CaretDown => include_str!("../../../../assets/blueprint-icons/caret-down.path"),
        }
    }

    pub fn outline(self, size: usize) -> path::Subpaths {
        let tolerance = SOURCE_BOX / (size.max(1) as f32 * 2.0);
        let mut subpaths = path::Subpaths::new();
        for line in self.data().lines() {
            let line = line.trim();
            if !line.is_empty() {
                subpaths.extend(path::parse(line, tolerance));
            }
        }
        subpaths
    }

    pub fn render(self, size: usize) -> egui::ColorImage {
        raster::fill(&self.outline(size), SOURCE_BOX, size)
    }
}

#[derive(Default, Clone)]
struct Cache(HashMap<(Icon, usize), TextureHandle>);

pub fn paint(ctx: &Context, painter: &Painter, rect: Rect, icon: Icon, colour: Color32) {
    let side = rect.width().min(rect.height());
    if side < 1.0 {
        return;
    }
    let square = Rect::from_center_size(rect.center(), egui::Vec2::splat(side));

    let pixels = ((side * ctx.pixels_per_point()).round() as usize).clamp(4, 512);
    let texture = texture(ctx, icon, pixels);
    painter.image(
        texture.id(),
        square,
        Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
        colour,
    );
}

fn texture(ctx: &Context, icon: Icon, pixels: usize) -> TextureHandle {
    let key = (icon, pixels);
    if let Some(handle) = ctx.data(|data| {
        data.get_temp::<Cache>(egui::Id::NULL)
            .and_then(|cache| cache.0.get(&key).cloned())
    }) {
        return handle;
    }

    let handle = ctx.load_texture(
        format!("icon:{}:{pixels}", icon.name()),
        icon.render(pixels),
        TextureOptions::LINEAR,
    );
    ctx.data_mut(|data| {
        data.get_temp_mut_or_default::<Cache>(egui::Id::NULL)
            .0
            .insert(key, handle.clone());
    });
    handle
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coverage(image: &egui::ColorImage) -> f32 {
        let total: u32 = image.pixels.iter().map(|pixel| u32::from(pixel.a())).sum();
        total as f32 / (image.pixels.len() as f32 * 255.0)
    }

    #[test]
    fn every_icon_has_path_data_and_a_name() {
        for icon in Icon::ALL {
            assert!(!icon.name().is_empty(), "{icon:?} has no name");
            let data = icon.data().trim();
            assert!(!data.is_empty(), "{} has no path data", icon.name());
            assert!(
                data.starts_with('M') || data.starts_with('m'),
                "{} does not begin with a moveto: {data:.20}",
                icon.name()
            );
        }
    }

    #[test]
    fn no_two_icons_share_a_name_or_their_data() {
        let mut names: Vec<&str> = Icon::ALL.iter().map(|icon| icon.name()).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(before, names.len(), "two icons share a Blueprint name");

        for (index, icon) in Icon::ALL.iter().enumerate() {
            for other in Icon::ALL.iter().skip(index + 1) {
                assert_ne!(
                    icon.data(),
                    other.data(),
                    "{} and {} are the same drawing",
                    icon.name(),
                    other.name()
                );
            }
        }
    }

    #[test]
    fn every_icon_parses_into_a_closed_outline() {
        for icon in Icon::ALL {
            let outline = icon.outline(32);
            assert!(!outline.is_empty(), "{} parsed to nothing", icon.name());
            for subpath in &outline {
                assert!(
                    subpath.len() >= 3,
                    "{} has a subpath of {} points",
                    icon.name(),
                    subpath.len()
                );
            }
        }
    }

    #[test]
    fn every_icon_stays_inside_its_sixteen_unit_box() {
        for icon in Icon::ALL {
            let mut bounds = egui::Rect::NOTHING;
            for subpath in icon.outline(32) {
                for point in subpath {
                    bounds.extend_with(point);
                }
            }
            assert!(
                bounds.min.x >= -0.5 && bounds.min.y >= -0.5,
                "{} starts at {:?}",
                icon.name(),
                bounds.min
            );
            assert!(
                bounds.max.x <= SOURCE_BOX + 0.5 && bounds.max.y <= SOURCE_BOX + 0.5,
                "{} reaches {:?}",
                icon.name(),
                bounds.max
            );
        }
    }

    #[test]
    fn every_icon_actually_covers_some_of_its_box() {
        for icon in Icon::ALL {
            let filled = coverage(&icon.render(32));
            assert!(
                filled > 0.05,
                "{} covers only {:.1}% of its box",
                icon.name(),
                filled * 100.0
            );
            assert!(
                filled < 0.95,
                "{} covers {:.1}% of its box, which suggests a hole was filled in",
                icon.name(),
                filled * 100.0
            );
        }
    }

    #[test]
    fn icons_with_holes_keep_them() {
        let cog = Icon::Gear.render(64);
        let centre = cog.pixels[32 * 64 + 32].a();
        assert_eq!(centre, 0, "the cog's centre should be open");

        let help = Icon::Help.render(64);
        assert!(
            help.pixels.iter().any(|pixel| pixel.a() == 0),
            "the help mark should not be a solid disc"
        );
    }

    #[test]
    fn rendering_is_stable_and_scales() {
        for size in [8_usize, 16, 32, 64] {
            let image = Icon::Play.render(size);
            assert_eq!(image.size, [size, size]);
        }

        assert_eq!(
            Icon::Search.render(24).pixels,
            Icon::Search.render(24).pixels
        );

        let small = coverage(&Icon::Play.render(16));
        let large = coverage(&Icon::Play.render(64));
        assert!(
            (small - large).abs() < 0.05,
            "coverage drifted from {small:.3} to {large:.3} with size"
        );
    }

    #[test]
    fn a_tiny_size_still_renders_something() {
        for size in [1_usize, 2, 4] {
            let image = Icon::Stop.render(size);
            assert_eq!(image.pixels.len(), size * size);
        }
    }

    #[test]
    fn textures_are_cached_per_icon_and_size() {
        let ctx = Context::default();
        let first = texture(&ctx, Icon::Play, 32);
        let again = texture(&ctx, Icon::Play, 32);
        assert_eq!(first.id(), again.id(), "the mask was uploaded twice");

        let bigger = texture(&ctx, Icon::Play, 64);
        assert_ne!(
            first.id(),
            bigger.id(),
            "a different size needs its own mask"
        );
        let other = texture(&ctx, Icon::Stop, 32);
        assert_ne!(first.id(), other.id(), "two icons shared one texture");
    }
}
