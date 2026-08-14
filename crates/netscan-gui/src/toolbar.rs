use egui::{Response, Ui};

use crate::icons::Icon;
use crate::session::Status;
use crate::theme::Palette;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Scan,
    Stop,
    Rescan,
    Options,
    Open,
    Save,
    Find,
    Previous,
    Next,
    First,
    Last,
    ShowDown,
    Compare,
}

impl Action {
    pub fn icon(self) -> Icon {
        match self {
            Action::Scan => Icon::Play,
            Action::Stop => Icon::Stop,
            Action::Rescan => Icon::Refresh,
            Action::Options => Icon::Gear,
            Action::Open => Icon::Folder,
            Action::Save => Icon::Save,
            Action::Find => Icon::Search,
            Action::Previous => Icon::ArrowLeft,
            Action::Next => Icon::ArrowRight,
            Action::First => Icon::SkipStart,
            Action::Last => Icon::SkipEnd,
            Action::ShowDown => Icon::Eye,
            Action::Compare => Icon::Compare,
        }
    }

    pub fn tooltip(self) -> &'static str {
        match self {
            Action::Scan => "Start scan  (Cmd/Ctrl+Enter)",
            Action::Stop => "Stop scan  (Esc)",
            Action::Rescan => "Run the same scan again",
            Action::Options => "Scan configuration…  (Cmd/Ctrl+,)",
            Action::Open => "Open a saved scan…  (Cmd/Ctrl+O)",
            Action::Save => "Save results…  (Cmd/Ctrl+S)",
            Action::Find => "Filter results  (Cmd/Ctrl+F)",
            Action::Previous => "Previous host",
            Action::Next => "Next host",
            Action::First => "First host",
            Action::Last => "Last host",
            Action::ShowDown => "Show hosts that are down",
            Action::Compare => "Compare with a saved scan",
        }
    }
}

pub struct Group(pub &'static [Action]);

pub const GROUPS: &[Group] = &[
    Group(&[Action::Scan, Action::Stop, Action::Rescan, Action::Options]),
    Group(&[Action::Open, Action::Save]),
    Group(&[
        Action::Find,
        Action::First,
        Action::Previous,
        Action::Next,
        Action::Last,
    ]),
    Group(&[Action::ShowDown, Action::Compare]),
];

#[derive(Debug, Clone, Copy)]
pub struct Availability {
    pub can_scan: bool,
    pub is_running: bool,
    pub can_rescan: bool,
    pub has_results: bool,
    pub has_hosts: bool,
}

impl Availability {
    pub fn enabled(&self, action: Action) -> bool {
        match action {
            Action::Scan => self.can_scan && !self.is_running,
            Action::Stop => self.is_running,
            Action::Rescan => self.can_rescan && !self.is_running,
            Action::Options => !self.is_running,
            Action::Open => !self.is_running,
            Action::Save => self.has_results,
            Action::Find => true,
            Action::Previous | Action::Next | Action::First | Action::Last => self.has_hosts,
            Action::ShowDown => true,
            Action::Compare => true,
        }
    }

    pub fn from_session(
        status: Status,
        form_valid: bool,
        has_results: bool,
        host_count: usize,
        has_previous_config: bool,
    ) -> Self {
        Self {
            can_scan: form_valid,
            is_running: status.is_active(),
            can_rescan: has_previous_config,
            has_results,
            has_hosts: host_count > 0,
        }
    }
}

pub const BUTTON: f32 = 26.0;

pub fn show(
    ui: &mut Ui,
    availability: &Availability,
    show_down: bool,
    palette: &Palette,
) -> Option<Action> {
    let mut pressed = None;

    ui.horizontal_centered(|ui| {
        ui.spacing_mut().item_spacing.x = 1.0;
        for (index, group) in GROUPS.iter().enumerate() {
            if index > 0 {
                separator(ui, palette);
            }
            for action in group.0 {
                if *action == Action::Scan && availability.is_running {
                    continue;
                }
                if *action == Action::Stop && !availability.is_running {
                    continue;
                }

                let enabled = availability.enabled(*action);
                let active = *action == Action::ShowDown && show_down;
                if button(ui, *action, enabled, active, palette).clicked() {
                    pressed = Some(*action);
                }
            }
        }
    });

    pressed
}

fn button(ui: &mut Ui, action: Action, enabled: bool, active: bool, palette: &Palette) -> Response {
    let sense = if enabled {
        egui::Sense::click()
    } else {
        egui::Sense::hover()
    };
    let (rect, response) = ui.allocate_exact_size(egui::vec2(BUTTON, BUTTON), sense);

    let rounding = egui::Rounding::same(crate::theme::RADIUS);
    if enabled && response.is_pointer_button_down_on() {
        ui.painter().rect_filled(rect, rounding, palette.active);
    } else if enabled && response.hovered() {
        ui.painter().rect_filled(rect, rounding, palette.hover);
    } else if active {
        ui.painter().rect_filled(rect, rounding, palette.raised);
        ui.painter().rect_stroke(
            rect,
            rounding,
            egui::Stroke::new(1.0_f32, palette.button_border),
        );
    }

    let tint = match action {
        _ if !enabled => palette.faint.gamma_multiply(0.6),
        Action::Scan => palette.success,
        Action::Stop => palette.danger,
        _ if active => palette.accent_text,
        _ => palette.text,
    };

    let inner = egui::Rect::from_center_size(rect.center(), egui::Vec2::splat(BUTTON * 0.62));
    let ctx = ui.ctx().clone();
    crate::icons::paint(&ctx, ui.painter(), inner, action.icon(), tint);

    if enabled {
        response.on_hover_text(action.tooltip())
    } else {
        response
    }
}

fn separator(ui: &mut Ui, palette: &Palette) {
    ui.add_space(4.0);
    let (rect, _) = ui.allocate_exact_size(egui::vec2(1.0, BUTTON - 8.0), egui::Sense::hover());
    ui.painter().rect_filled(rect, 0.0, palette.line);
    ui.add_space(4.0);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn availability() -> Availability {
        Availability {
            can_scan: true,
            is_running: false,
            can_rescan: true,
            has_results: true,
            has_hosts: true,
        }
    }

    #[test]
    fn every_action_has_an_icon_and_a_tooltip() {
        for group in GROUPS {
            for action in group.0 {
                let outline = action.icon().outline(16);
                assert!(!outline.is_empty(), "{action:?} has an empty icon");
                assert!(!action.tooltip().is_empty(), "{action:?} has no tooltip");
            }
        }
    }

    #[test]
    fn no_two_actions_share_an_icon() {
        let mut seen: Vec<Icon> = Vec::new();
        for group in GROUPS {
            for action in group.0 {
                assert!(
                    !seen.contains(&action.icon()),
                    "{action:?} reuses {:?}",
                    action.icon()
                );
                seen.push(action.icon());
            }
        }
    }

    #[test]
    fn no_action_appears_in_two_groups() {
        let mut seen: Vec<Action> = Vec::new();
        for group in GROUPS {
            for action in group.0 {
                assert!(!seen.contains(action), "{action:?} appears twice");
                seen.push(*action);
            }
        }
        assert!(
            seen.len() >= 10,
            "the toolbar should carry the common actions"
        );
    }

    #[test]
    fn scan_and_stop_are_never_both_available() {
        let idle = availability();
        assert!(idle.enabled(Action::Scan));
        assert!(!idle.enabled(Action::Stop));

        let running = Availability {
            is_running: true,
            ..availability()
        };
        assert!(!running.enabled(Action::Scan));
        assert!(running.enabled(Action::Stop));
    }

    #[test]
    fn an_invalid_form_cannot_start_a_scan() {
        let invalid = Availability {
            can_scan: false,
            ..availability()
        };
        assert!(!invalid.enabled(Action::Scan));
    }

    #[test]
    fn saving_needs_results_and_navigation_needs_hosts() {
        let empty = Availability {
            has_results: false,
            has_hosts: false,
            ..availability()
        };
        assert!(!empty.enabled(Action::Save));
        for action in [Action::First, Action::Previous, Action::Next, Action::Last] {
            assert!(!empty.enabled(action), "{action:?} should need hosts");
        }

        assert!(empty.enabled(Action::Find));
    }

    #[test]
    fn a_running_scan_locks_the_actions_that_would_disturb_it() {
        let running = Availability {
            is_running: true,
            ..availability()
        };
        assert!(!running.enabled(Action::Options));
        assert!(!running.enabled(Action::Open));
        assert!(!running.enabled(Action::Rescan));

        assert!(running.enabled(Action::Save));
    }

    #[test]
    fn rescan_needs_something_to_repeat() {
        let fresh = Availability {
            can_rescan: false,
            ..availability()
        };
        assert!(!fresh.enabled(Action::Rescan));
    }

    #[test]
    fn availability_is_derived_from_the_session() {
        let idle = Availability::from_session(Status::Idle, true, false, 0, false);
        assert!(idle.enabled(Action::Scan));
        assert!(!idle.enabled(Action::Save));
        assert!(!idle.enabled(Action::Next));

        let running = Availability::from_session(Status::Running, true, false, 5, true);
        assert!(running.is_running);
        assert!(running.enabled(Action::Stop));

        let finished = Availability::from_session(Status::Finished, true, true, 5, true);
        assert!(finished.enabled(Action::Save));
        assert!(finished.enabled(Action::Rescan));
    }
}
