use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::scanner::port::Transport;
use crate::scanner::result::{HostReport, HostStatus, PortReport, PortState, ScanReport};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostChange {
    pub address: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub open_ports: Vec<String>,
}

impl HostChange {
    fn from_host(host: &HostReport) -> Self {
        Self {
            address: host.address,
            hostname: host.primary_hostname().map(str::to_string),
            open_ports: host.open_ports().map(|p| p.label()).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortChange {
    pub address: IpAddr,
    pub port: u16,
    pub transport: Transport,
    pub previous_state: PortState,
    pub current_state: PortState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
}

impl PortChange {
    pub fn label(&self) -> String {
        format!("{} {}/{}", self.address, self.port, self.transport)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceChange {
    pub address: IpAddr,
    pub port: u16,
    pub transport: Transport,
    pub previous: String,
    pub current: String,
    pub version_only: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OsChange {
    pub address: IpAddr,
    pub previous: String,
    pub current: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ScanDiff {
    pub previous_scan_id: String,
    pub current_scan_id: String,
    pub previous_at: Option<chrono::DateTime<chrono::Utc>>,
    pub current_at: Option<chrono::DateTime<chrono::Utc>>,
    pub comparable: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub comparability_notes: Vec<String>,
    pub new_hosts: Vec<HostChange>,
    pub removed_hosts: Vec<HostChange>,
    pub opened_ports: Vec<PortChange>,
    pub closed_ports: Vec<PortChange>,
    pub changed_states: Vec<PortChange>,
    pub changed_services: Vec<ServiceChange>,
    pub changed_os: Vec<OsChange>,
}

impl ScanDiff {
    pub fn is_empty(&self) -> bool {
        self.new_hosts.is_empty()
            && self.removed_hosts.is_empty()
            && self.opened_ports.is_empty()
            && self.closed_ports.is_empty()
            && self.changed_states.is_empty()
            && self.changed_services.is_empty()
            && self.changed_os.is_empty()
    }

    pub fn change_count(&self) -> usize {
        self.new_hosts.len()
            + self.removed_hosts.len()
            + self.opened_ports.len()
            + self.closed_ports.len()
            + self.changed_states.len()
            + self.changed_services.len()
            + self.changed_os.len()
    }

    pub fn has_new_exposure(&self) -> bool {
        !self.new_hosts.is_empty() || !self.opened_ports.is_empty()
    }

    pub fn summary(&self) -> String {
        if self.is_empty() {
            return "no changes".to_string();
        }
        let mut parts = Vec::new();
        if !self.new_hosts.is_empty() {
            parts.push(format!("{} new host(s)", self.new_hosts.len()));
        }
        if !self.removed_hosts.is_empty() {
            parts.push(format!("{} host(s) gone", self.removed_hosts.len()));
        }
        if !self.opened_ports.is_empty() {
            parts.push(format!("{} port(s) opened", self.opened_ports.len()));
        }
        if !self.closed_ports.is_empty() {
            parts.push(format!("{} port(s) closed", self.closed_ports.len()));
        }
        if !self.changed_states.is_empty() {
            parts.push(format!(
                "{} port state change(s)",
                self.changed_states.len()
            ));
        }
        if !self.changed_services.is_empty() {
            parts.push(format!("{} service change(s)", self.changed_services.len()));
        }
        if !self.changed_os.is_empty() {
            parts.push(format!("{} OS change(s)", self.changed_os.len()));
        }
        parts.join(", ")
    }
}

pub fn compare(previous: &ScanReport, current: &ScanReport) -> ScanDiff {
    let mut diff = ScanDiff {
        previous_scan_id: previous.scan_id.clone(),
        current_scan_id: current.scan_id.clone(),
        previous_at: Some(previous.started_at),
        current_at: Some(current.started_at),
        comparable: true,
        ..ScanDiff::default()
    };

    check_comparability(&mut diff, previous, current);

    let previous_hosts: BTreeMap<IpAddr, &HostReport> =
        previous.hosts.iter().map(|h| (h.address, h)).collect();
    let current_hosts: BTreeMap<IpAddr, &HostReport> =
        current.hosts.iter().map(|h| (h.address, h)).collect();

    for (address, host) in &current_hosts {
        if host.status != HostStatus::Up {
            continue;
        }
        let was_up = previous_hosts
            .get(address)
            .is_some_and(|h| h.status == HostStatus::Up);
        if !was_up {
            diff.new_hosts.push(HostChange::from_host(host));
        }
    }
    for (address, host) in &previous_hosts {
        if host.status != HostStatus::Up {
            continue;
        }
        let is_up = current_hosts
            .get(address)
            .is_some_and(|h| h.status == HostStatus::Up);
        if !is_up {
            diff.removed_hosts.push(HostChange::from_host(host));
        }
    }

    for (address, current_host) in &current_hosts {
        let Some(previous_host) = previous_hosts.get(address) else {
            continue;
        };
        if current_host.status != HostStatus::Up || previous_host.status != HostStatus::Up {
            continue;
        }

        let previous_ports = index_ports(previous_host);
        let current_ports = index_ports(current_host);

        let keys: BTreeSet<(Transport, u16)> = previous_ports
            .keys()
            .chain(current_ports.keys())
            .copied()
            .collect();

        for key in keys {
            let (transport, port) = key;
            let before = previous_ports.get(&key);
            let after = current_ports.get(&key);

            let before_state = match before {
                Some(p) => p.state,
                None if was_tested(previous_host, key) => PortState::Closed,
                None => continue,
            };
            let after_state = match after {
                Some(p) => p.state,
                None if was_tested(current_host, key) => PortState::Closed,
                None => continue,
            };

            if before_state == after_state {
                if let (Some(before), Some(after)) = (before, after) {
                    if let Some(change) = service_change(*address, transport, port, before, after) {
                        diff.changed_services.push(change);
                    }
                }
                continue;
            }

            let change = PortChange {
                address: *address,
                port,
                transport,
                previous_state: before_state,
                current_state: after_state,
                service: after
                    .and_then(|p| p.service.as_ref())
                    .map(|s| s.name.clone()),
            };

            if after_state.is_open_ish() && !before_state.is_open_ish() {
                diff.opened_ports.push(change);
            } else if before_state.is_open_ish() && !after_state.is_open_ish() {
                diff.closed_ports.push(change);
            } else {
                diff.changed_states.push(change);
            }
        }

        let before_os = previous_host
            .os
            .as_ref()
            .filter(|o| !o.is_empty())
            .map(|o| o.summary());
        let after_os = current_host
            .os
            .as_ref()
            .filter(|o| !o.is_empty())
            .map(|o| o.summary());
        if let (Some(before), Some(after)) = (before_os, after_os) {
            if before != after {
                diff.changed_os.push(OsChange {
                    address: *address,
                    previous: before,
                    current: after,
                });
            }
        }
    }

    diff
}

fn check_comparability(diff: &mut ScanDiff, previous: &ScanReport, current: &ScanReport) {
    if previous.parameters.targets != current.parameters.targets
        && !previous.parameters.targets.is_empty()
        && !current.parameters.targets.is_empty()
    {
        diff.comparable = false;
        diff.comparability_notes.push(format!(
            "targets differ: {:?} then {:?}",
            previous.parameters.targets, current.parameters.targets
        ));
    }
    if previous.parameters.ports != current.parameters.ports
        && !previous.parameters.ports.is_empty()
        && !current.parameters.ports.is_empty()
    {
        diff.comparable = false;
        diff.comparability_notes.push(format!(
            "port selections differ: {} then {}",
            previous.parameters.ports, current.parameters.ports
        ));
    }
    if previous.outcome != crate::scanner::result::ScanOutcome::Completed
        || current.outcome != crate::scanner::result::ScanOutcome::Completed
    {
        diff.comparable = false;
        diff.comparability_notes
            .push("at least one scan did not complete, so absences may not be real".to_string());
    }
}

fn index_ports(host: &HostReport) -> BTreeMap<(Transport, u16), &PortReport> {
    host.ports
        .iter()
        .map(|p| ((p.transport, p.port), p))
        .collect()
}

fn was_tested(host: &HostReport, key: (Transport, u16)) -> bool {
    if host.ports.iter().any(|p| (p.transport, p.port) == key) {
        return true;
    }
    !host.other_ports.is_empty() && host.not_scanned == 0
}

fn service_change(
    address: IpAddr,
    transport: Transport,
    port: u16,
    before: &PortReport,
    after: &PortReport,
) -> Option<ServiceChange> {
    let before_service = before.service.as_ref();
    let after_service = after.service.as_ref();

    let before_text = before_service.map(|s| s.summary()).unwrap_or_default();
    let after_text = after_service.map(|s| s.summary()).unwrap_or_default();

    if before_text == after_text {
        return None;
    }

    if before_text.is_empty() || after_text.is_empty() {
        return None;
    }

    let version_only = before_service.map(|s| s.name.as_str())
        == after_service.map(|s| s.name.as_str())
        && before_service.and_then(|s| s.product.as_deref())
            == after_service.and_then(|s| s.product.as_deref());

    Some(ServiceChange {
        address,
        port,
        transport,
        previous: before_text,
        current: after_text,
        version_only,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::result::{
        Confidence, DetectionSource, PortReason, ScanOutcome, ServiceInfo,
    };

    fn host(address: &str, ports: &[(u16, PortState)]) -> HostReport {
        let mut host = HostReport::new(address.parse().unwrap());
        host.status = HostStatus::Up;
        for (port, state) in ports {
            host.ports.push(PortReport::new(
                *port,
                Transport::Tcp,
                *state,
                PortReason::ConnectionEstablished,
            ));
        }
        host
    }

    fn report(hosts: Vec<HostReport>) -> ScanReport {
        let mut report = ScanReport::empty();
        report.parameters.targets = vec!["192.168.1.0/24".to_string()];
        report.parameters.ports = "22,80,443".to_string();
        report.outcome = ScanOutcome::Completed;
        report.hosts = hosts;
        report.recompute_stats();
        report
    }

    #[test]
    fn identical_scans_show_no_changes() {
        let a = report(vec![host("10.0.0.1", &[(22, PortState::Open)])]);
        let b = report(vec![host("10.0.0.1", &[(22, PortState::Open)])]);
        let diff = compare(&a, &b);
        assert!(diff.is_empty());
        assert_eq!(diff.change_count(), 0);
        assert_eq!(diff.summary(), "no changes");
        assert!(diff.comparable);
    }

    #[test]
    fn a_new_host_is_detected() {
        let a = report(vec![host("10.0.0.1", &[(22, PortState::Open)])]);
        let b = report(vec![
            host("10.0.0.1", &[(22, PortState::Open)]),
            host("10.0.0.2", &[(80, PortState::Open)]),
        ]);
        let diff = compare(&a, &b);
        assert_eq!(diff.new_hosts.len(), 1);
        assert_eq!(diff.new_hosts[0].address.to_string(), "10.0.0.2");
        assert_eq!(diff.new_hosts[0].open_ports, vec!["80/tcp"]);
        assert!(diff.has_new_exposure());
    }

    #[test]
    fn a_disappeared_host_is_detected() {
        let a = report(vec![
            host("10.0.0.1", &[(22, PortState::Open)]),
            host("10.0.0.2", &[(80, PortState::Open)]),
        ]);
        let b = report(vec![host("10.0.0.1", &[(22, PortState::Open)])]);
        let diff = compare(&a, &b);
        assert_eq!(diff.removed_hosts.len(), 1);
        assert_eq!(diff.removed_hosts[0].address.to_string(), "10.0.0.2");
        assert!(
            !diff.has_new_exposure(),
            "a host going away is not new exposure"
        );
    }

    #[test]
    fn a_host_going_down_counts_as_removed() {
        let a = report(vec![host("10.0.0.1", &[(22, PortState::Open)])]);
        let mut down = host("10.0.0.1", &[]);
        down.status = HostStatus::Down;
        let b = report(vec![down]);
        let diff = compare(&a, &b);
        assert_eq!(diff.removed_hosts.len(), 1);
    }

    #[test]
    fn a_newly_open_port_is_detected() {
        let a = report(vec![host(
            "10.0.0.1",
            &[(22, PortState::Open), (80, PortState::Closed)],
        )]);
        let b = report(vec![host(
            "10.0.0.1",
            &[(22, PortState::Open), (80, PortState::Open)],
        )]);
        let diff = compare(&a, &b);
        assert_eq!(diff.opened_ports.len(), 1);
        assert_eq!(diff.opened_ports[0].port, 80);
        assert_eq!(diff.opened_ports[0].previous_state, PortState::Closed);
        assert_eq!(diff.opened_ports[0].current_state, PortState::Open);
        assert_eq!(diff.opened_ports[0].label(), "10.0.0.1 80/tcp");
        assert!(diff.has_new_exposure());
    }

    #[test]
    fn a_closed_port_is_detected() {
        let a = report(vec![host("10.0.0.1", &[(22, PortState::Open)])]);
        let b = report(vec![host("10.0.0.1", &[(22, PortState::Closed)])]);
        let diff = compare(&a, &b);
        assert_eq!(diff.closed_ports.len(), 1);
        assert_eq!(diff.closed_ports[0].port, 22);
        assert!(!diff.has_new_exposure());
    }

    #[test]
    fn a_state_change_that_is_neither_opening_nor_closing_is_reported_separately() {
        let a = report(vec![host("10.0.0.1", &[(22, PortState::Closed)])]);
        let b = report(vec![host("10.0.0.1", &[(22, PortState::Filtered)])]);
        let diff = compare(&a, &b);
        assert!(diff.opened_ports.is_empty());
        assert!(diff.closed_ports.is_empty());
        assert_eq!(diff.changed_states.len(), 1);
    }

    #[test]
    fn ports_only_one_scan_tested_are_not_reported_as_changes() {
        let a = report(vec![host(
            "10.0.0.1",
            &[(22, PortState::Open), (80, PortState::Open)],
        )]);
        let mut narrower = report(vec![host("10.0.0.1", &[(22, PortState::Open)])]);
        narrower.parameters.ports = "22".to_string();

        let diff = compare(&a, &narrower);
        assert!(
            diff.closed_ports.is_empty(),
            "a port that was not scanned must not be reported as closed: {:?}",
            diff.closed_ports
        );
        assert!(!diff.comparable, "the scans covered different ports");
        assert!(diff
            .comparability_notes
            .iter()
            .any(|n| n.contains("port selections differ")));
    }

    #[test]
    fn a_version_change_is_detected_and_labelled() {
        let mut before = host("10.0.0.1", &[(22, PortState::Open)]);
        before.ports[0].service = Some(ServiceInfo {
            name: "ssh".into(),
            product: Some("OpenSSH".into()),
            version: Some("8.9".into()),
            source: DetectionSource::Probe("ssh".into()),
            confidence: Confidence::High,
            ..Default::default()
        });

        let mut after = host("10.0.0.1", &[(22, PortState::Open)]);
        after.ports[0].service = Some(ServiceInfo {
            version: Some("9.6".into()),
            ..before.ports[0].service.clone().unwrap()
        });

        let diff = compare(&report(vec![before]), &report(vec![after]));
        assert_eq!(diff.changed_services.len(), 1);
        let change = &diff.changed_services[0];
        assert!(change.version_only, "only the version moved");
        assert!(change.previous.contains("8.9"));
        assert!(change.current.contains("9.6"));
    }

    #[test]
    fn a_different_service_on_the_same_port_is_not_version_only() {
        let mut before = host("10.0.0.1", &[(8080, PortState::Open)]);
        before.ports[0].service = Some(ServiceInfo {
            name: "http".into(),
            product: Some("nginx".into()),
            ..Default::default()
        });
        let mut after = host("10.0.0.1", &[(8080, PortState::Open)]);
        after.ports[0].service = Some(ServiceInfo {
            name: "http".into(),
            product: Some("Apache httpd".into()),
            ..Default::default()
        });

        let diff = compare(&report(vec![before]), &report(vec![after]));
        assert_eq!(diff.changed_services.len(), 1);
        assert!(!diff.changed_services[0].version_only);
    }

    #[test]
    fn gaining_a_service_identification_is_not_reported_as_a_change() {
        let before = host("10.0.0.1", &[(22, PortState::Open)]);
        let mut after = host("10.0.0.1", &[(22, PortState::Open)]);
        after.ports[0].service = Some(ServiceInfo {
            name: "ssh".into(),
            product: Some("OpenSSH".into()),
            ..Default::default()
        });

        let diff = compare(&report(vec![before]), &report(vec![after]));
        assert!(
            diff.changed_services.is_empty(),
            "{:?}",
            diff.changed_services
        );
    }

    #[test]
    fn an_os_change_is_detected() {
        let mut before = host("10.0.0.1", &[(22, PortState::Open)]);
        before.os = Some(crate::scanner::result::OsGuess {
            family: Some("Linux".into()),
            confidence: Confidence::High,
            ..Default::default()
        });
        let mut after = host("10.0.0.1", &[(22, PortState::Open)]);
        after.os = Some(crate::scanner::result::OsGuess {
            family: Some("Windows".into()),
            confidence: Confidence::High,
            ..Default::default()
        });

        let diff = compare(&report(vec![before]), &report(vec![after]));
        assert_eq!(diff.changed_os.len(), 1);
        assert!(diff.changed_os[0].previous.contains("Linux"));
        assert!(diff.changed_os[0].current.contains("Windows"));
    }

    #[test]
    fn incomplete_scans_are_flagged_as_not_comparable() {
        let a = report(vec![host("10.0.0.1", &[(22, PortState::Open)])]);
        let mut b = report(vec![host("10.0.0.1", &[(22, PortState::Open)])]);
        b.outcome = ScanOutcome::Cancelled;

        let diff = compare(&a, &b);
        assert!(!diff.comparable);
        assert!(diff
            .comparability_notes
            .iter()
            .any(|n| n.contains("did not complete")));
    }

    #[test]
    fn the_summary_names_every_kind_of_change() {
        let a = report(vec![host("10.0.0.1", &[(22, PortState::Open)])]);
        let b = report(vec![
            host("10.0.0.1", &[(22, PortState::Closed)]),
            host("10.0.0.2", &[(80, PortState::Open)]),
        ]);
        let diff = compare(&a, &b);
        let summary = diff.summary();
        assert!(summary.contains("1 new host(s)"), "{summary}");
        assert!(summary.contains("1 port(s) closed"), "{summary}");
    }

    #[test]
    fn a_diff_round_trips_through_json() {
        let a = report(vec![host("10.0.0.1", &[(22, PortState::Open)])]);
        let b = report(vec![host("10.0.0.2", &[(80, PortState::Open)])]);
        let diff = compare(&a, &b);
        let text = serde_json::to_string(&diff).unwrap();
        let parsed: ScanDiff = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed, diff);
    }

    #[test]
    fn comparing_empty_reports_is_safe() {
        let diff = compare(&ScanReport::empty(), &ScanReport::empty());
        assert!(diff.is_empty());
    }
}
