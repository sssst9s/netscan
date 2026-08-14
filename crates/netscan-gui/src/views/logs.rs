use egui::{RichText, Ui};

use crate::session::{LogEntry, LogLevel};
use crate::widgets::{muted, palette};

#[derive(Debug)]
pub struct LogState {
    pub problems_only: bool,
    pub follow: bool,
}

impl Default for LogState {
    fn default() -> Self {
        Self {
            problems_only: false,
            follow: true,
        }
    }
}

pub fn visible<'a>(entries: &'a [LogEntry], state: &LogState) -> Vec<&'a LogEntry> {
    entries
        .iter()
        .filter(|entry| !state.problems_only || entry.level != LogLevel::Info)
        .collect()
}

pub fn level_colour(level: LogLevel) -> egui::Color32 {
    match level {
        LogLevel::Info => palette::muted(),
        LogLevel::Warning => palette::filtered(),
        LogLevel::Error => palette::unknown(),
    }
}

pub fn level_label(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Info => "info",
        LogLevel::Warning => "warn",
        LogLevel::Error => "error",
    }
}

pub fn show(ui: &mut Ui, entries: &[LogEntry], state: &mut LogState) {
    ui.horizontal(|ui| {
        ui.checkbox(&mut state.problems_only, "Warnings and errors only");
        ui.checkbox(&mut state.follow, "Follow");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let warnings = entries
                .iter()
                .filter(|e| e.level == LogLevel::Warning)
                .count();
            let errors = entries
                .iter()
                .filter(|e| e.level == LogLevel::Error)
                .count();
            if errors > 0 {
                ui.label(RichText::new(format!("{errors} error(s)")).color(palette::unknown()));
            }
            if warnings > 0 {
                ui.label(
                    RichText::new(format!("{warnings} warning(s)")).color(palette::filtered()),
                );
            }
            ui.label(muted(format!("{} entries", entries.len())));
        });
    });
    ui.separator();

    let rows = visible(entries, state);
    if rows.is_empty() {
        ui.vertical_centered(|ui| {
            ui.add_space(24.0);
            ui.label(muted(if entries.is_empty() {
                "Nothing has happened yet."
            } else {
                "No warnings or errors."
            }));
        });
        return;
    }

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .stick_to_bottom(state.follow)
        .show(ui, |ui| {
            for entry in rows {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(entry.at.format("%H:%M:%S").to_string())
                            .monospace()
                            .color(palette::muted()),
                    );
                    ui.label(
                        RichText::new(format!("{:<5}", level_label(entry.level)))
                            .monospace()
                            .color(level_colour(entry.level)),
                    );
                    ui.label(&entry.message);
                });
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<LogEntry> {
        vec![
            LogEntry {
                at: chrono::Utc::now(),
                level: LogLevel::Info,
                message: "scan started".to_string(),
            },
            LogEntry {
                at: chrono::Utc::now(),
                level: LogLevel::Warning,
                message: "icmp unavailable".to_string(),
            },
            LogEntry {
                at: chrono::Utc::now(),
                level: LogLevel::Error,
                message: "no targets".to_string(),
            },
        ]
    }

    #[test]
    fn everything_is_shown_by_default() {
        let state = LogState::default();
        assert!(!state.problems_only);
        assert_eq!(visible(&entries(), &state).len(), 3);
    }

    #[test]
    fn problems_only_hides_routine_entries() {
        let state = LogState {
            problems_only: true,
            ..Default::default()
        };
        let all = entries();
        let rows = visible(&all, &state);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|entry| entry.level != LogLevel::Info));
    }

    #[test]
    fn every_level_has_a_distinct_colour_and_label() {
        let levels = [LogLevel::Info, LogLevel::Warning, LogLevel::Error];
        for level in levels {
            assert!(!level_label(level).is_empty());
        }
        assert_ne!(
            level_colour(LogLevel::Info),
            level_colour(LogLevel::Warning)
        );
        assert_ne!(
            level_colour(LogLevel::Warning),
            level_colour(LogLevel::Error)
        );
    }

    #[test]
    fn an_empty_log_yields_no_rows() {
        assert!(visible(&[], &LogState::default()).is_empty());
    }
}
