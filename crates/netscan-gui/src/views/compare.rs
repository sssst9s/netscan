use egui::{RichText, Ui};
use netscan_core::compare::ScanDiff;
use netscan_core::ScanReport;

use crate::widgets::{self, muted, palette};

#[derive(Debug, Default)]
pub struct CompareState {
    pub baseline: Option<Box<ScanReport>>,
    pub baseline_path: Option<String>,
    pub diff: Option<ScanDiff>,
    pub error: Option<String>,
}

impl CompareState {
    pub fn set_baseline(&mut self, report: ScanReport, path: impl Into<String>) {
        self.baseline = Some(Box::new(report));
        self.baseline_path = Some(path.into());
        self.error = None;
    }

    pub fn recompute(&mut self, current: Option<&ScanReport>) {
        self.diff = match (&self.baseline, current) {
            (Some(baseline), Some(current)) => {
                Some(netscan_core::compare::compare(baseline, current))
            }
            _ => None,
        };
    }

    pub fn clear(&mut self) {
        self.baseline = None;
        self.baseline_path = None;
        self.diff = None;
        self.error = None;
    }
}

pub fn show(ui: &mut Ui, state: &CompareState, has_current: bool) {
    if let Some(error) = &state.error {
        ui.label(RichText::new(error).color(palette::unknown()));
        ui.separator();
    }

    let Some(baseline) = &state.baseline else {
        ui.vertical_centered(|ui| {
            ui.add_space(40.0);
            ui.label(muted("Load a saved scan to compare against."));
            ui.label(muted("File ▸ Open baseline for comparison…"));
        });
        return;
    };

    ui.horizontal_wrapped(|ui| {
        widgets::field(
            ui,
            "Baseline",
            state
                .baseline_path
                .clone()
                .unwrap_or_else(|| baseline.scan_id.clone()),
        );
        ui.separator();
        widgets::field(
            ui,
            "Taken",
            baseline.started_at.format("%Y-%m-%d %H:%M UTC").to_string(),
        );
        ui.separator();
        widgets::field(ui, "Hosts up", baseline.stats.hosts_up.to_string());
    });
    ui.separator();

    if !has_current {
        ui.label(muted(
            "Run a scan, or open a second saved scan, to compare against this baseline.",
        ));
        return;
    }

    let Some(diff) = &state.diff else {
        ui.label(muted("Nothing to compare yet."));
        return;
    };

    if !diff.comparable {
        ui.label(
            RichText::new("These scans are not directly comparable").color(palette::filtered()),
        );
        for note in &diff.comparability_notes {
            ui.label(muted(format!("• {note}")));
        }
        ui.label(muted(
            "Only changes that both scans measured are listed below.",
        ));
        ui.separator();
    }

    if diff.is_empty() {
        ui.label(RichText::new("No changes.").color(palette::open()).strong());
        return;
    }

    ui.label(RichText::new(diff.summary()).strong());
    ui.add_space(4.0);

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if !diff.new_hosts.is_empty() {
                widgets::section(ui, &format!("New hosts ({})", diff.new_hosts.len()));
                for host in &diff.new_hosts {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new("+")
                                .color(palette::added())
                                .strong()
                                .monospace(),
                        );
                        ui.label(RichText::new(host.address.to_string()).monospace());
                        if let Some(name) = &host.hostname {
                            ui.label(muted(name));
                        }
                        ui.label(muted(if host.open_ports.is_empty() {
                            "no open ports".to_string()
                        } else {
                            host.open_ports.join(", ")
                        }));
                    });
                }
            }

            if !diff.opened_ports.is_empty() {
                widgets::section(
                    ui,
                    &format!("Newly open ports ({})", diff.opened_ports.len()),
                );
                for port in &diff.opened_ports {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new("+")
                                .color(palette::added())
                                .strong()
                                .monospace(),
                        );
                        ui.label(RichText::new(port.label()).monospace());
                        if let Some(service) = &port.service {
                            ui.label(service);
                        }
                        ui.label(muted(format!("was {}", port.previous_state)));
                    });
                }
            }

            if !diff.removed_hosts.is_empty() {
                widgets::section(
                    ui,
                    &format!("Hosts no longer responding ({})", diff.removed_hosts.len()),
                );
                for host in &diff.removed_hosts {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new("−")
                                .color(palette::removed())
                                .strong()
                                .monospace(),
                        );
                        ui.label(RichText::new(host.address.to_string()).monospace());
                        if let Some(name) = &host.hostname {
                            ui.label(muted(name));
                        }
                    });
                }
            }

            if !diff.closed_ports.is_empty() {
                widgets::section(
                    ui,
                    &format!("Ports no longer open ({})", diff.closed_ports.len()),
                );
                for port in &diff.closed_ports {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new("−")
                                .color(palette::removed())
                                .strong()
                                .monospace(),
                        );
                        ui.label(RichText::new(port.label()).monospace());
                        ui.label(muted(format!("now {}", port.current_state)));
                    });
                }
            }

            if !diff.changed_services.is_empty() {
                widgets::section(
                    ui,
                    &format!("Service changes ({})", diff.changed_services.len()),
                );
                for change in &diff.changed_services {
                    ui.horizontal_wrapped(|ui| {
                        let marker = if change.version_only { "~" } else { "!" };
                        let colour = if change.version_only {
                            palette::changed()
                        } else {
                            palette::filtered()
                        };
                        ui.label(RichText::new(marker).color(colour).strong().monospace());
                        ui.label(
                            RichText::new(format!(
                                "{} {}/{}",
                                change.address, change.port, change.transport
                            ))
                            .monospace(),
                        );
                        ui.label(muted(&change.previous));
                        ui.label("→");
                        ui.label(&change.current);
                    });
                }
            }

            if !diff.changed_os.is_empty() {
                widgets::section(
                    ui,
                    &format!("OS inference changes ({})", diff.changed_os.len()),
                );
                for change in &diff.changed_os {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new("~")
                                .color(palette::changed())
                                .strong()
                                .monospace(),
                        );
                        ui.label(RichText::new(change.address.to_string()).monospace());
                        ui.label(muted(&change.previous));
                        ui.label("→");
                        ui.label(&change.current);
                    });
                }
            }

            if !diff.changed_states.is_empty() {
                widgets::section(
                    ui,
                    &format!("Other state changes ({})", diff.changed_states.len()),
                );
                for port in &diff.changed_states {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("~").color(palette::changed()).monospace());
                        ui.label(RichText::new(port.label()).monospace());
                        ui.label(muted(format!(
                            "{} → {}",
                            port.previous_state, port.current_state
                        )));
                    });
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use netscan_core::{HostReport, HostStatus, PortReason, PortReport, PortState, Transport};

    fn report(address: &str, ports: &[u16]) -> ScanReport {
        let mut report = ScanReport::empty();
        report.parameters.targets = vec!["10.0.0.0/24".to_string()];
        report.parameters.ports = "22,80".to_string();
        let mut host = HostReport::new(address.parse().unwrap());
        host.status = HostStatus::Up;
        for port in [22u16, 80] {
            if ports.contains(&port) {
                host.ports.push(PortReport::new(
                    port,
                    Transport::Tcp,
                    PortState::Open,
                    PortReason::ConnectionEstablished,
                ));
            } else {
                host.other_ports.record(PortState::Closed);
            }
        }
        report.hosts.push(host);
        report.recompute_stats();
        report
    }

    #[test]
    fn a_fresh_state_has_no_baseline() {
        let state = CompareState::default();
        assert!(state.baseline.is_none());
        assert!(state.diff.is_none());
    }

    #[test]
    fn setting_a_baseline_and_recomputing_produces_a_diff() {
        let mut state = CompareState::default();
        state.set_baseline(report("10.0.0.1", &[22]), "before.json");
        assert_eq!(state.baseline_path.as_deref(), Some("before.json"));

        let current = report("10.0.0.1", &[22, 80]);
        state.recompute(Some(&current));

        let diff = state.diff.expect("a diff should have been computed");
        assert_eq!(diff.opened_ports.len(), 1);
        assert_eq!(diff.opened_ports[0].port, 80);
    }

    #[test]
    fn recomputing_without_a_current_report_clears_the_diff() {
        let mut state = CompareState::default();
        state.set_baseline(report("10.0.0.1", &[22]), "before.json");
        state.recompute(Some(&report("10.0.0.1", &[22, 80])));
        assert!(state.diff.is_some());

        state.recompute(None);
        assert!(state.diff.is_none());
    }

    #[test]
    fn recomputing_without_a_baseline_produces_nothing() {
        let mut state = CompareState::default();
        state.recompute(Some(&report("10.0.0.1", &[22])));
        assert!(state.diff.is_none());
    }

    #[test]
    fn clearing_forgets_everything() {
        let mut state = CompareState::default();
        state.set_baseline(report("10.0.0.1", &[22]), "before.json");
        state.recompute(Some(&report("10.0.0.2", &[22])));
        state.error = Some("boom".to_string());

        state.clear();
        assert!(state.baseline.is_none());
        assert!(state.baseline_path.is_none());
        assert!(state.diff.is_none());
        assert!(state.error.is_none());
    }

    #[test]
    fn identical_scans_produce_an_empty_diff() {
        let mut state = CompareState::default();
        state.set_baseline(report("10.0.0.1", &[22]), "before.json");
        state.recompute(Some(&report("10.0.0.1", &[22])));
        assert!(state.diff.unwrap().is_empty());
    }

    #[test]
    fn setting_a_baseline_clears_a_previous_error() {
        let mut state = CompareState {
            error: Some("bad file".to_string()),
            ..Default::default()
        };
        state.set_baseline(report("10.0.0.1", &[22]), "good.json");
        assert!(state.error.is_none());
    }
}
