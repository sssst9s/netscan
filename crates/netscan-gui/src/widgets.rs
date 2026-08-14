use egui::{Color32, RichText, Ui};
use netscan_core::{Confidence, HostStatus, PortState};

use crate::theme;

pub mod palette {
    use egui::Color32;

    use crate::theme;

    pub fn open() -> Color32 {
        theme::current().success
    }

    pub fn closed() -> Color32 {
        theme::current().muted
    }

    pub fn filtered() -> Color32 {
        theme::current().warning
    }

    pub fn unknown() -> Color32 {
        theme::current().danger
    }

    pub fn down() -> Color32 {
        theme::current().faint
    }

    pub fn muted() -> Color32 {
        theme::current().muted
    }

    pub fn added() -> Color32 {
        theme::current().success
    }

    pub fn removed() -> Color32 {
        theme::current().danger
    }

    pub fn changed() -> Color32 {
        theme::current().info
    }
}

pub fn status_colour(status: HostStatus) -> Color32 {
    match status {
        HostStatus::Up => palette::open(),
        HostStatus::Down => palette::down(),
        HostStatus::Skipped => palette::muted(),
    }
}

pub fn status_badge(status: HostStatus) -> RichText {
    RichText::new(status.to_string())
        .color(status_colour(status))
        .strong()
}

pub fn muted(text: impl Into<String>) -> RichText {
    RichText::new(text.into()).color(palette::muted())
}

pub fn state_ink(ink: &theme::Ink, state: PortState) -> Color32 {
    match state {
        PortState::Open => ink.success,
        PortState::Closed => ink.muted,
        PortState::Filtered | PortState::OpenFiltered => ink.warning,
        PortState::Unknown => ink.danger,
    }
}

pub fn status_ink(ink: &theme::Ink, status: HostStatus) -> Color32 {
    match status {
        HostStatus::Up => ink.success,
        HostStatus::Down => ink.faint,
        HostStatus::Skipped => ink.muted,
    }
}

pub fn confidence_ink(ink: &theme::Ink, confidence: Confidence) -> Color32 {
    match confidence {
        Confidence::High => ink.success,
        Confidence::Medium => ink.warning,
        Confidence::Low => ink.muted,
    }
}

pub fn confidence_colour(confidence: Confidence) -> Color32 {
    match confidence {
        Confidence::High => palette::open(),
        Confidence::Medium => palette::filtered(),
        Confidence::Low => palette::muted(),
    }
}

pub fn confidence_badge(confidence: Confidence) -> RichText {
    RichText::new(confidence.to_string())
        .color(confidence_colour(confidence))
        .small()
}

pub fn spaced(text: &str) -> String {
    text.to_uppercase()
        .chars()
        .map(String::from)
        .collect::<Vec<_>>()
        .join("\u{2009}")
}

pub fn micro_label(text: &str) -> RichText {
    RichText::new(spaced(text))
        .size(10.0)
        .color(palette::muted())
}

pub fn tab(ui: &mut Ui, selected: bool, label: &str) -> egui::Response {
    let palette = theme::current();
    let font = egui::TextStyle::Button.resolve(ui.style());

    let galley = ui
        .painter()
        .layout_no_wrap(label.to_owned(), font, Color32::PLACEHOLDER);

    let width = galley.size().x + crate::theme::UNIT * 4.0;
    let height = galley.size().y + crate::theme::UNIT * 2.5;
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::click());

    let colour = if selected || response.hovered() {
        palette.text
    } else {
        palette.muted
    };
    if response.hovered() && !selected {
        ui.painter().rect_filled(
            rect,
            egui::Rounding::same(crate::theme::RADIUS),
            palette.hover,
        );
    }

    let position = rect.center() - galley.size() / 2.0;
    ui.painter().galley(position, galley, colour);

    if selected {
        let underline = egui::Rect::from_min_max(
            egui::pos2(rect.left(), rect.bottom() - 2.0),
            egui::pos2(rect.right(), rect.bottom()),
        );
        ui.painter()
            .rect_filled(underline, 0.0, palette.accent_text);
    }
    response
}

pub fn section(ui: &mut Ui, title: &str) {
    ui.add_space(8.0);
    ui.label(micro_label(title));
    ui.add_space(2.0);
    ui.separator();
}

pub fn field(ui: &mut Ui, label: &str, value: impl Into<String>) {
    ui.horizontal(|ui| {
        ui.label(muted(format!("{label}:")));
        ui.label(value.into());
    });
}

pub fn optional_field(ui: &mut Ui, label: &str, value: Option<impl Into<String>>) {
    if let Some(value) = value {
        field(ui, label, value);
    }
}

pub fn duration(value: std::time::Duration) -> String {
    let seconds = value.as_secs();
    match seconds {
        0..=9 => format!("{:.1}s", value.as_secs_f64()),
        10..=59 => format!("{seconds}s"),
        60..=3599 => format!("{}m {:02}s", seconds / 60, seconds % 60),
        _ => format!("{}h {:02}m", seconds / 3600, (seconds % 3600) / 60),
    }
}

pub fn rtt(value: Option<f64>) -> String {
    match value {
        Some(ms) if ms < 1.0 => format!("{:.2} ms", ms),
        Some(ms) if ms < 100.0 => format!("{:.1} ms", ms),
        Some(ms) => format!("{ms:.0} ms"),
        None => "—".to_string(),
    }
}

pub fn count(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub fn ellipsise(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let kept: String = text.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_port_state_has_a_distinct_colour_for_the_states_that_matter() {
        let ink = theme::DARK.ink();
        assert_ne!(
            state_ink(&ink, PortState::Open),
            state_ink(&ink, PortState::Closed)
        );
        assert_ne!(
            state_ink(&ink, PortState::Open),
            state_ink(&ink, PortState::Filtered)
        );
        assert_ne!(
            state_ink(&ink, PortState::Open),
            state_ink(&ink, PortState::Unknown)
        );
    }

    #[test]
    fn open_and_open_filtered_share_a_family_but_status_colours_differ() {
        let ink = theme::DARK.ink();
        assert_eq!(
            state_ink(&ink, PortState::Filtered),
            state_ink(&ink, PortState::OpenFiltered)
        );
        assert_ne!(
            status_colour(HostStatus::Up),
            status_colour(HostStatus::Down)
        );
    }

    #[test]
    fn a_selected_row_keeps_its_states_legible_even_though_it_loses_their_hues() {
        let ink = theme::SELECTED_INK;
        for state in [
            PortState::Open,
            PortState::Closed,
            PortState::Filtered,
            PortState::Unknown,
        ] {
            let colour = state_ink(&ink, state);
            assert!(
                colour == ink.text || colour == ink.muted,
                "{state:?} on a selected row is {colour:?}, which is neither"
            );
        }
    }

    #[test]
    fn the_host_lists_band_keeps_every_state_a_different_colour() {
        let ink = theme::TABLE_INK;
        let open = state_ink(&ink, PortState::Open);
        assert_ne!(open, state_ink(&ink, PortState::Closed));
        assert_ne!(open, state_ink(&ink, PortState::Filtered));
        assert_ne!(open, state_ink(&ink, PortState::Unknown));
        assert_ne!(
            open,
            theme::DARK.ink().success,
            "the band must not reuse the dark ground's green"
        );
    }

    #[test]
    fn durations_are_readable_at_every_scale() {
        assert_eq!(duration(std::time::Duration::from_millis(1500)), "1.5s");
        assert_eq!(duration(std::time::Duration::from_secs(45)), "45s");
        assert_eq!(duration(std::time::Duration::from_secs(125)), "2m 05s");
        assert_eq!(duration(std::time::Duration::from_secs(7300)), "2h 01m");
    }

    #[test]
    fn round_trip_times_keep_useful_precision() {
        assert_eq!(rtt(Some(0.214)), "0.21 ms");
        assert_eq!(rtt(Some(12.5)), "12.5 ms");
        assert_eq!(rtt(Some(240.0)), "240 ms");
        assert_eq!(rtt(None), "—");
    }

    #[test]
    fn counts_are_separated() {
        assert_eq!(count(0), "0");
        assert_eq!(count(999), "999");
        assert_eq!(count(1_234_567), "1,234,567");
    }

    #[test]
    fn text_is_truncated_with_an_ellipsis() {
        assert_eq!(ellipsise("short", 10), "short");
        assert_eq!(ellipsise("truncate me please", 8), "truncat…");
        assert_eq!(ellipsise("truncate me please", 8).chars().count(), 8);
    }

    #[test]
    fn truncation_handles_multibyte_text() {
        let text = "日本語のテキストです";
        assert_eq!(ellipsise(text, 4).chars().count(), 4);
    }

    #[test]
    fn micro_labels_are_uppercase_and_letter_spaced() {
        assert_eq!(spaced("Ports"), "P\u{2009}O\u{2009}R\u{2009}T\u{2009}S");
        assert_eq!(spaced(""), "");
        assert_eq!(spaced("A"), "A", "a single character needs no spacing");

        let label = micro_label("Detection");
        assert!(label.text().starts_with('D'));
        assert!(label.text().contains('\u{2009}'));
    }

    #[test]
    fn badges_carry_their_text_not_just_a_colour() {
        assert_eq!(status_badge(HostStatus::Down).text(), "down");
        assert_eq!(confidence_badge(Confidence::High).text(), "high");
    }
}
