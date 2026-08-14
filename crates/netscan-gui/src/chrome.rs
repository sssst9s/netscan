use egui::{
    Align2, Color32, Context, CursorIcon, FontId, Id, Rect, Rounding, Sense, Stroke, Ui, Vec2,
    ViewportCommand,
};

use crate::theme::{self, Palette};

const RESIZE_MARGIN: f32 = 6.0;

const BUTTON_SIZE: Vec2 = Vec2::new(30.0, 22.0);

pub const BUTTONS_ON_LEFT: bool = cfg!(target_os = "macos");

pub const OWNS_WINDOW_FRAME: bool = !cfg!(target_os = "macos");

pub const MODIFIER_SYMBOL: &str = if cfg!(target_os = "macos") {
    "⌘"
} else {
    "^"
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChromeResponse {
    pub close_requested: bool,
}

pub fn window_frame(ctx: &Context, palette: &Palette) -> egui::Frame {
    let _ = ctx;
    egui::Frame {
        fill: palette.window,
        rounding: if OWNS_WINDOW_FRAME {
            Rounding::same(theme::WINDOW_RADIUS)
        } else {
            Rounding::ZERO
        },
        stroke: if OWNS_WINDOW_FRAME {
            Stroke::new(1.0_f32, palette.line)
        } else {
            Stroke::NONE
        },
        outer_margin: egui::Margin::same(0.0),
        inner_margin: egui::Margin::same(0.0),
        ..Default::default()
    }
}

pub fn title_bar(
    ui: &mut Ui,
    title: &str,
    palette: &Palette,
    content: impl FnOnce(&mut Ui),
) -> ChromeResponse {
    let mut response = ChromeResponse::default();
    let bar_rect = ui.max_rect();

    let drag = ui.interact(bar_rect, Id::new("title-bar-drag"), Sense::click_and_drag());
    if drag.is_pointer_button_down_on() {
        ui.ctx().send_viewport_cmd(ViewportCommand::StartDrag);
    }
    if drag.double_clicked() {
        let maximized = ui.input(|i| i.viewport().maximized.unwrap_or(false));
        ui.ctx()
            .send_viewport_cmd(ViewportCommand::Maximized(!maximized));
    }

    ui.painter().rect_filled(
        bar_rect,
        if OWNS_WINDOW_FRAME {
            Rounding {
                nw: theme::WINDOW_RADIUS,
                ne: theme::WINDOW_RADIUS,
                sw: 0.0,
                se: 0.0,
            }
        } else {
            Rounding::ZERO
        },
        palette.titlebar,
    );

    wordmark(ui, title, palette, bar_rect);

    ui.horizontal_centered(|ui| {
        ui.add_space(theme::UNIT * 2.0);
        if BUTTONS_ON_LEFT {
            response = window_buttons(ui, palette);
            ui.add_space(theme::UNIT * 2.0);
            content(ui);
        } else {
            content(ui);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                response = window_buttons(ui, palette);
            });
        }
    });

    response
}

fn wordmark(ui: &mut Ui, title: &str, palette: &Palette, bar: Rect) {
    ui.painter().text(
        bar.center(),
        Align2::CENTER_CENTER,
        title,
        FontId::new(12.5, crate::fonts::family(crate::fonts::MEDIUM)),
        palette.text,
    );
}

fn window_buttons(ui: &mut Ui, palette: &Palette) -> ChromeResponse {
    let mut response = ChromeResponse::default();

    let order: [Button; 3] = if BUTTONS_ON_LEFT {
        [Button::Close, Button::Minimise, Button::Maximise]
    } else {
        [Button::Close, Button::Maximise, Button::Minimise]
    };

    for button in order {
        if window_button(ui, button, palette) {
            match button {
                Button::Close => response.close_requested = true,
                Button::Minimise => ui.ctx().send_viewport_cmd(ViewportCommand::Minimized(true)),
                Button::Maximise => {
                    let maximized = ui.input(|i| i.viewport().maximized.unwrap_or(false));
                    ui.ctx()
                        .send_viewport_cmd(ViewportCommand::Maximized(!maximized));
                }
            }
        }
    }

    response
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Button {
    Close,
    Minimise,
    Maximise,
}

impl Button {
    fn dot_colour(self) -> Color32 {
        match self {
            Button::Close => Color32::from_rgb(0xff, 0x5f, 0x57),
            Button::Minimise => Color32::from_rgb(0xfe, 0xbc, 0x2e),
            Button::Maximise => Color32::from_rgb(0x28, 0xc8, 0x40),
        }
    }

    fn tooltip(self) -> &'static str {
        match self {
            Button::Close => "Close",
            Button::Minimise => "Minimise",
            Button::Maximise => "Maximise",
        }
    }
}

fn window_button(ui: &mut Ui, button: Button, palette: &Palette) -> bool {
    let size = if BUTTONS_ON_LEFT {
        Vec2::new(20.0, 20.0)
    } else {
        BUTTON_SIZE
    };
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());
    let hovered = response.hovered();
    if hovered {
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }
    let painter = ui.painter();

    if BUTTONS_ON_LEFT {
        let centre = rect.center();
        painter.circle_filled(centre, 6.0, button.dot_colour());
        if hovered {
            let ink = Color32::from_black_alpha(160);
            let stroke = Stroke::new(1.2_f32, ink);
            match button {
                Button::Close => {
                    let d = 3.0;
                    painter.line_segment(
                        [centre + Vec2::new(-d, -d), centre + Vec2::new(d, d)],
                        stroke,
                    );
                    painter.line_segment(
                        [centre + Vec2::new(d, -d), centre + Vec2::new(-d, d)],
                        stroke,
                    );
                }
                Button::Minimise => {
                    painter.line_segment(
                        [centre + Vec2::new(-3.5, 0.0), centre + Vec2::new(3.5, 0.0)],
                        stroke,
                    );
                }
                Button::Maximise => {
                    painter.rect_stroke(
                        Rect::from_center_size(centre, Vec2::splat(6.0)),
                        Rounding::same(1.0),
                        stroke,
                    );
                }
            }
        }
    } else {
        if hovered {
            let fill = if button == Button::Close {
                Color32::from_rgb(0xc4, 0x2b, 0x1c)
            } else {
                palette.hover
            };
            painter.rect_filled(rect, Rounding::same(theme::RADIUS), fill);
        }
        let ink = if hovered && button == Button::Close {
            Color32::WHITE
        } else {
            palette.text
        };
        let glyph = match button {
            Button::Close => "✕",
            Button::Minimise => "–",
            Button::Maximise => "▢",
        };
        painter.text(
            rect.center(),
            Align2::CENTER_CENTER,
            glyph,
            FontId::proportional(12.0),
            ink,
        );
    }

    response.on_hover_text(button.tooltip()).clicked()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edge {
    North,
    South,
    East,
    West,
    NorthWest,
    NorthEast,
    SouthWest,
    SouthEast,
}

impl Edge {
    pub const ALL: &'static [Edge] = &[
        Edge::NorthWest,
        Edge::NorthEast,
        Edge::SouthWest,
        Edge::SouthEast,
        Edge::North,
        Edge::South,
        Edge::East,
        Edge::West,
    ];

    pub fn cursor(self) -> CursorIcon {
        match self {
            Edge::North | Edge::South => CursorIcon::ResizeVertical,
            Edge::East | Edge::West => CursorIcon::ResizeHorizontal,
            Edge::NorthWest | Edge::SouthEast => CursorIcon::ResizeNwSe,
            Edge::NorthEast | Edge::SouthWest => CursorIcon::ResizeNeSw,
        }
    }

    pub fn direction(self) -> egui::viewport::ResizeDirection {
        use egui::viewport::ResizeDirection as D;
        match self {
            Edge::North => D::North,
            Edge::South => D::South,
            Edge::East => D::East,
            Edge::West => D::West,
            Edge::NorthWest => D::NorthWest,
            Edge::NorthEast => D::NorthEast,
            Edge::SouthWest => D::SouthWest,
            Edge::SouthEast => D::SouthEast,
        }
    }

    pub fn hit_area(self, window: Rect, margin: f32) -> Rect {
        let Rect { min, max } = window;
        match self {
            Edge::North => Rect::from_min_max(min, egui::pos2(max.x, min.y + margin)),
            Edge::South => Rect::from_min_max(egui::pos2(min.x, max.y - margin), max),
            Edge::West => Rect::from_min_max(min, egui::pos2(min.x + margin, max.y)),
            Edge::East => Rect::from_min_max(egui::pos2(max.x - margin, min.y), max),
            Edge::NorthWest => Rect::from_min_max(min, egui::pos2(min.x + margin, min.y + margin)),
            Edge::NorthEast => Rect::from_min_max(
                egui::pos2(max.x - margin, min.y),
                egui::pos2(max.x, min.y + margin),
            ),
            Edge::SouthWest => Rect::from_min_max(
                egui::pos2(min.x, max.y - margin),
                egui::pos2(min.x + margin, max.y),
            ),
            Edge::SouthEast => Rect::from_min_max(egui::pos2(max.x - margin, max.y - margin), max),
        }
    }
}

pub fn resize_handles(ctx: &Context, window: Rect) {
    if !OWNS_WINDOW_FRAME {
        return;
    }

    if ctx.input(|i| i.viewport().maximized.unwrap_or(false)) {
        return;
    }

    for edge in Edge::ALL {
        let area = edge.hit_area(window, RESIZE_MARGIN);

        egui::Area::new(Id::new(("resize-edge", *edge as u8)))
            .order(egui::Order::Foreground)
            .fixed_pos(area.min)
            .interactable(true)
            .show(ctx, |ui| {
                let response = ui.allocate_rect(area, Sense::drag());
                if response.hovered() || response.dragged() {
                    ui.ctx().set_cursor_icon(edge.cursor());
                }
                if response.drag_started() {
                    ui.ctx()
                        .send_viewport_cmd(ViewportCommand::BeginResize(edge.direction()));
                }
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window() -> Rect {
        Rect::from_min_size(egui::pos2(0.0, 0.0), Vec2::new(800.0, 600.0))
    }

    #[test]
    fn every_edge_has_a_hit_area_inside_the_window() {
        for edge in Edge::ALL {
            let area = edge.hit_area(window(), RESIZE_MARGIN);
            assert!(
                area.width() > 0.0 && area.height() > 0.0,
                "{edge:?} has no area"
            );
            assert!(window().contains_rect(area), "{edge:?} escapes the window");
        }
    }

    #[test]
    fn edge_strips_are_thin_and_corners_are_small() {
        let window = window();
        assert_eq!(
            Edge::North.hit_area(window, RESIZE_MARGIN).height(),
            RESIZE_MARGIN
        );
        assert_eq!(
            Edge::North.hit_area(window, RESIZE_MARGIN).width(),
            window.width()
        );
        assert_eq!(
            Edge::West.hit_area(window, RESIZE_MARGIN).width(),
            RESIZE_MARGIN
        );

        let corner = Edge::SouthEast.hit_area(window, RESIZE_MARGIN);
        assert_eq!(corner.width(), RESIZE_MARGIN);
        assert_eq!(corner.height(), RESIZE_MARGIN);
        assert_eq!(corner.max, window.max);
    }

    #[test]
    fn corners_are_tested_before_the_edges_they_overlap() {
        let corners = [
            Edge::NorthWest,
            Edge::NorthEast,
            Edge::SouthWest,
            Edge::SouthEast,
        ];
        let first_edge = Edge::ALL
            .iter()
            .position(|e| !corners.contains(e))
            .expect("there are plain edges");
        let last_corner = Edge::ALL
            .iter()
            .rposition(|e| corners.contains(e))
            .expect("there are corners");
        assert!(last_corner < first_edge, "corners must precede edges");
    }

    #[test]
    fn each_edge_maps_to_its_own_direction_and_cursor() {
        let mut directions = Vec::new();
        for edge in Edge::ALL {
            directions.push(format!("{:?}", edge.direction()));

            assert_ne!(
                edge.cursor(),
                CursorIcon::Default,
                "{edge:?} has no resize cursor"
            );
        }
        let before = directions.len();
        directions.sort();
        directions.dedup();
        assert_eq!(
            before,
            directions.len(),
            "two edges share a resize direction"
        );
    }

    #[test]
    fn opposite_edges_do_not_overlap() {
        let window = window();
        let north = Edge::North.hit_area(window, RESIZE_MARGIN);
        let south = Edge::South.hit_area(window, RESIZE_MARGIN);
        assert!(!north.intersects(south));

        let east = Edge::East.hit_area(window, RESIZE_MARGIN);
        let west = Edge::West.hit_area(window, RESIZE_MARGIN);
        assert!(!east.intersects(west));
    }

    #[test]
    fn the_resize_margin_is_reachable_but_not_intrusive() {
        assert!((4.0..=8.0).contains(&RESIZE_MARGIN));
    }

    #[test]
    fn window_buttons_follow_the_platform() {
        assert_eq!(BUTTONS_ON_LEFT, cfg!(target_os = "macos"));
    }

    #[test]
    fn the_modifier_symbol_matches_the_platform() {
        assert_eq!(
            MODIFIER_SYMBOL,
            if cfg!(target_os = "macos") {
                "⌘"
            } else {
                "^"
            }
        );
        assert!(!MODIFIER_SYMBOL.is_empty());
    }

    #[test]
    fn window_buttons_are_distinguishable() {
        let buttons = [Button::Close, Button::Minimise, Button::Maximise];
        let mut colours: Vec<_> = buttons.iter().map(|b| b.dot_colour()).collect();
        let before = colours.len();
        colours.sort_by_key(|c| c.to_array());
        colours.dedup();
        assert_eq!(before, colours.len(), "two window buttons look the same");

        for button in buttons {
            assert!(!button.tooltip().is_empty());
        }
    }

    #[test]
    fn the_window_frame_is_opaque() {
        let ctx = Context::default();
        let frame = window_frame(&ctx, &theme::DARK);
        assert_eq!(frame.fill, theme::DARK.window);
        assert_eq!(frame.fill.a(), 255, "the window must not be see-through");
    }

    #[test]
    fn only_the_platform_that_owns_the_frame_draws_one() {
        let frame = window_frame(&Context::default(), &theme::DARK);
        if OWNS_WINDOW_FRAME {
            assert_eq!(frame.rounding, Rounding::same(theme::WINDOW_RADIUS));
            assert_ne!(
                frame.stroke,
                Stroke::NONE,
                "a borderless window needs an outline"
            );
        } else {
            assert_eq!(frame.rounding, Rounding::ZERO);
            assert_eq!(frame.stroke, Stroke::NONE);
        }
    }

    #[test]
    fn macos_lets_the_system_own_the_frame() {
        assert_eq!(OWNS_WINDOW_FRAME, !cfg!(target_os = "macos"));
    }
}
