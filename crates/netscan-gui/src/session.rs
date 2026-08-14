use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use netscan_core::scanner::probe::ProbeRegistry;
use netscan_core::{
    Engine, HostReport, HostStatus, Progress, ScanConfig, ScanEvent, ScanHandle, ScanReport,
    Warning,
};

const EVENTS_PER_FRAME: usize = 2_000;

const MAX_LOG_ENTRIES: usize = 2_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Idle,
    Running,
    Cancelling,
    Finished,
    Failed,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Idle => "Ready",
            Status::Running => "Scanning",
            Status::Cancelling => "Stopping",
            Status::Finished => "Finished",
            Status::Failed => "Failed",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Status::Running | Status::Cancelling)
    }
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub at: chrono::DateTime<chrono::Utc>,
    pub level: LogLevel,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Default)]
pub struct LiveResults {
    pub hosts: BTreeMap<IpAddr, HostReport>,
    pub progress: Progress,
    pub warnings: Vec<Warning>,
    pub log: Vec<LogEntry>,
    pub report: Option<Arc<ScanReport>>,
}

impl LiveResults {
    pub fn hosts_up(&self) -> impl Iterator<Item = &HostReport> {
        self.hosts
            .values()
            .filter(|host| host.status == HostStatus::Up)
    }

    pub fn up_count(&self) -> usize {
        self.hosts_up().count()
    }

    pub fn open_port_count(&self) -> usize {
        self.hosts.values().map(HostReport::open_port_count).sum()
    }

    pub fn log(&mut self, level: LogLevel, message: impl Into<String>) {
        self.log.push(LogEntry {
            at: chrono::Utc::now(),
            level,
            message: message.into(),
        });
        if self.log.len() > MAX_LOG_ENTRIES {
            self.log.drain(..MAX_LOG_ENTRIES / 2);
        }
    }

    pub fn clear(&mut self) {
        self.hosts.clear();
        self.progress = Progress::default();
        self.warnings.clear();
        self.log.clear();
        self.report = None;
    }
}

pub struct Session {
    runtime: Arc<tokio::runtime::Runtime>,
    probes: ProbeRegistry,
    handle: Option<ScanHandle>,
    pub results: LiveResults,
    pub status: Status,
    pub config: Option<ScanConfig>,
    pub error: Option<String>,
    started: Option<Instant>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("status", &self.status)
            .field("hosts", &self.results.hosts.len())
            .finish_non_exhaustive()
    }
}

impl Session {
    pub fn new(probes: ProbeRegistry) -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("netscan-engine")
            .build()
            .map_err(|e| format!("could not start the scan engine runtime: {e}"))?;

        Ok(Self {
            runtime: Arc::new(runtime),
            probes,
            handle: None,
            results: LiveResults::default(),
            status: Status::Idle,
            config: None,
            error: None,
            started: None,
        })
    }

    pub fn start(&mut self, config: ScanConfig) {
        self.stop();
        self.results.clear();
        self.error = None;
        self.config = Some(config.clone());

        let engine = match Engine::with_registry(config, self.probes.clone()) {
            Ok(engine) => engine,
            Err(err) => {
                self.status = Status::Failed;
                self.error = Some(err.to_string());
                self.results.log(LogLevel::Error, err.to_string());
                return;
            }
        };

        self.results.log(
            LogLevel::Info,
            format!(
                "scanning {}",
                engine
                    .config()
                    .targets
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );

        let _guard = self.runtime.enter();
        self.handle = Some(engine.start());
        self.status = Status::Running;
        self.started = Some(Instant::now());
    }

    pub fn cancel(&mut self) {
        if let Some(handle) = &self.handle {
            handle.cancel();
            self.status = Status::Cancelling;
            self.results.log(
                LogLevel::Info,
                "cancelling; finishing probes already in flight",
            );
        }
    }

    pub fn stop(&mut self) {
        self.handle = None;
        if self.status.is_active() {
            self.status = Status::Idle;
        }
    }

    pub fn is_running(&self) -> bool {
        self.status.is_active()
    }

    pub fn elapsed(&self) -> std::time::Duration {
        self.started.map(|s| s.elapsed()).unwrap_or_default()
    }

    pub fn poll(&mut self) -> bool {
        let Some(handle) = self.handle.as_mut() else {
            return false;
        };

        let mut changed = false;
        for _ in 0..EVENTS_PER_FRAME {
            let Some(event) = handle.try_next_event() else {
                break;
            };
            changed = true;
            apply(&mut self.results, event, &mut self.status);
        }

        if self.status == Status::Finished {
            self.handle = None;
        }
        changed
    }

    pub fn load_report(&mut self, report: ScanReport) {
        self.stop();
        self.results.clear();
        self.results.progress = Progress {
            hosts_total: report.stats.hosts_total,
            hosts_completed: report.stats.hosts_total,
            hosts_up: report.stats.hosts_up,
            probes_total: report.stats.ports_tested,
            probes_completed: report.stats.ports_tested,
            open_ports: report.stats.ports_open,
            elapsed: std::time::Duration::from_millis(report.stats.duration_ms),
            ..Progress::default()
        };
        for host in &report.hosts {
            self.results.hosts.insert(host.address, host.clone());
        }
        self.results.warnings.clone_from(&report.warnings);
        self.results.log(
            LogLevel::Info,
            format!(
                "loaded scan {} with {} host(s)",
                report.scan_id,
                report.hosts.len()
            ),
        );
        self.results.report = Some(Arc::new(report));
        self.status = Status::Finished;
    }
}

pub fn apply(results: &mut LiveResults, event: ScanEvent, status: &mut Status) {
    match event {
        ScanEvent::Started {
            hosts_total,
            ports_per_host,
            ..
        } => {
            results.progress.hosts_total = hosts_total;
            results.log(
                LogLevel::Info,
                format!("scan started: {hosts_total} host(s), {ports_per_host} port(s) each"),
            );
        }
        ScanEvent::HostDiscovered {
            address,
            status: host_status,
            rtt_ms,
        } => {
            let host = results
                .hosts
                .entry(address)
                .or_insert_with(|| HostReport::new(address));
            host.status = host_status;
            host.rtt_ms = rtt_ms;
            if host_status == HostStatus::Up {
                results.progress.hosts_up += 1;

                results.log(
                    LogLevel::Info,
                    match rtt_ms {
                        Some(rtt) => format!("host up: {address} ({rtt:.1} ms)"),
                        None => format!("host up: {address}"),
                    },
                );
            }
        }
        ScanEvent::HostStarted { address } => {
            results
                .hosts
                .entry(address)
                .or_insert_with(|| HostReport::new(address));
        }
        ScanEvent::PortResult { address, port } => {
            let line = port.state.is_open_ish().then(|| {
                format!(
                    "{} {}: {} on {address}",
                    port.state.as_str(),
                    port.label(),
                    port.service_name(),
                )
            });
            let mut first_sighting = false;

            let host = results
                .hosts
                .entry(address)
                .or_insert_with(|| HostReport::new(address));
            if port.state.is_open_ish() {
                match host
                    .ports
                    .iter_mut()
                    .find(|p| p.port == port.port && p.transport == port.transport)
                {
                    Some(existing) => *existing = *port,
                    None => {
                        host.ports.push(*port);
                        first_sighting = true;
                    }
                }
                host.sort_ports();
            } else {
                host.other_ports.record(port.state);
            }

            if let (true, Some(line)) = (first_sighting, line) {
                results.log(LogLevel::Info, line);
            }
        }
        ScanEvent::HostCompleted { host } => {
            let mut parts = vec![format!("{} open", host.open_port_count())];
            if let Some(name) = host.primary_hostname() {
                parts.push(name.to_string());
            }
            if let Some(vendor) = &host.vendor {
                parts.push(vendor.clone());
            }
            if let Some(os) = host.os.as_ref().filter(|os| !os.is_empty()) {
                parts.push(format!("{} (inferred)", os.summary()));
            }
            if host.status == HostStatus::Up {
                results.log(
                    LogLevel::Info,
                    format!("{} done: {}", host.address, parts.join(", ")),
                );
            }

            results.hosts.insert(host.address, *host);
        }
        ScanEvent::Progress(progress) => results.progress = progress,
        ScanEvent::Warning(warning) => {
            results.log(LogLevel::Warning, warning.to_string());
            results.warnings.push(warning);
        }
        ScanEvent::Finished { report } => {
            results.progress.hosts_completed = report.stats.hosts_total;
            for host in &report.hosts {
                results.hosts.insert(host.address, host.clone());
            }
            results.log(
                LogLevel::Info,
                format!(
                    "scan {}: {} host(s) up, {} open port(s) in {:.1}s",
                    format!("{:?}", report.outcome).to_lowercase(),
                    report.stats.hosts_up,
                    report.stats.ports_open,
                    report.stats.duration_ms as f64 / 1000.0
                ),
            );
            results.report = Some(Arc::new(*report));
            *status = Status::Finished;
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netscan_core::{PortReason, PortReport, PortState, Transport};

    fn address(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn open_port(port: u16) -> Box<PortReport> {
        Box::new(PortReport::new(
            port,
            Transport::Tcp,
            PortState::Open,
            PortReason::ConnectionEstablished,
        ))
    }

    #[test]
    fn discovery_populates_hosts() {
        let mut results = LiveResults::default();
        let mut status = Status::Running;

        apply(
            &mut results,
            ScanEvent::HostDiscovered {
                address: address("10.0.0.1"),
                status: HostStatus::Up,
                rtt_ms: Some(1.5),
            },
            &mut status,
        );

        assert_eq!(results.hosts.len(), 1);
        assert_eq!(results.up_count(), 1);
        assert_eq!(results.hosts[&address("10.0.0.1")].rtt_ms, Some(1.5));
    }

    #[test]
    fn open_ports_are_listed_and_closed_ports_summarised() {
        let mut results = LiveResults::default();
        let mut status = Status::Running;
        let host = address("10.0.0.1");

        apply(
            &mut results,
            ScanEvent::PortResult {
                address: host,
                port: open_port(22),
            },
            &mut status,
        );
        apply(
            &mut results,
            ScanEvent::PortResult {
                address: host,
                port: Box::new(PortReport::new(
                    23,
                    Transport::Tcp,
                    PortState::Closed,
                    PortReason::Refused,
                )),
            },
            &mut status,
        );

        let entry = &results.hosts[&host];
        assert_eq!(entry.ports.len(), 1, "only open ports are listed");
        assert_eq!(entry.other_ports.get(PortState::Closed), 1);
        assert_eq!(results.open_port_count(), 1);
    }

    #[test]
    fn a_repeated_port_result_replaces_rather_than_duplicates() {
        let mut results = LiveResults::default();
        let mut status = Status::Running;
        let host = address("10.0.0.1");

        apply(
            &mut results,
            ScanEvent::PortResult {
                address: host,
                port: open_port(22),
            },
            &mut status,
        );
        let mut second = open_port(22);
        second.rtt_ms = Some(9.9);
        apply(
            &mut results,
            ScanEvent::PortResult {
                address: host,
                port: second,
            },
            &mut status,
        );

        assert_eq!(results.hosts[&host].ports.len(), 1);
        assert_eq!(results.hosts[&host].ports[0].rtt_ms, Some(9.9));
    }

    #[test]
    fn a_completed_host_replaces_the_incremental_view() {
        let mut results = LiveResults::default();
        let mut status = Status::Running;
        let address = address("10.0.0.1");

        apply(
            &mut results,
            ScanEvent::PortResult {
                address,
                port: open_port(22),
            },
            &mut status,
        );

        let mut complete = HostReport::new(address);
        complete.status = HostStatus::Up;
        complete.add_hostname(
            "host.example",
            netscan_core::scanner::result::HostnameSource::ReverseDns,
        );
        complete.ports.push(*open_port(22));
        complete.ports.push(*open_port(443));
        apply(
            &mut results,
            ScanEvent::HostCompleted {
                host: Box::new(complete),
            },
            &mut status,
        );

        let entry = &results.hosts[&address];
        assert_eq!(entry.ports.len(), 2, "the completed report should win");
        assert_eq!(entry.primary_hostname(), Some("host.example"));
    }

    #[test]
    fn finishing_stores_the_report_and_changes_status() {
        let mut results = LiveResults::default();
        let mut status = Status::Running;

        let mut report = ScanReport::empty();
        report.hosts.push(HostReport::new(address("10.0.0.1")));
        report.recompute_stats();

        apply(
            &mut results,
            ScanEvent::Finished {
                report: Box::new(report),
            },
            &mut status,
        );

        assert_eq!(status, Status::Finished);
        assert!(results.report.is_some());
        assert_eq!(results.hosts.len(), 1);
    }

    #[test]
    fn warnings_are_logged_and_kept() {
        let mut results = LiveResults::default();
        let mut status = Status::Running;
        apply(
            &mut results,
            ScanEvent::Warning(Warning::global("test.code", "careful")),
            &mut status,
        );
        assert_eq!(results.warnings.len(), 1);
        assert_eq!(results.log.len(), 1);
        assert_eq!(results.log[0].level, LogLevel::Warning);
    }

    #[test]
    fn the_log_is_bounded() {
        let mut results = LiveResults::default();
        for i in 0..MAX_LOG_ENTRIES * 2 {
            results.log(LogLevel::Info, format!("entry {i}"));
        }
        assert!(
            results.log.len() <= MAX_LOG_ENTRIES,
            "the log grew to {} entries",
            results.log.len()
        );
        assert!(
            results
                .log
                .last()
                .unwrap()
                .message
                .contains(&format!("{}", MAX_LOG_ENTRIES * 2 - 1)),
            "the newest entry must survive"
        );
    }

    #[test]
    fn status_labels_are_present_for_every_state() {
        for status in [
            Status::Idle,
            Status::Running,
            Status::Cancelling,
            Status::Finished,
            Status::Failed,
        ] {
            assert!(!status.label().is_empty());
        }
        assert!(Status::Running.is_active());
        assert!(Status::Cancelling.is_active());
        assert!(!Status::Finished.is_active());
    }

    #[test]
    fn a_session_starts_idle_and_loads_reports() {
        let mut session = Session::new(ProbeRegistry::empty()).expect("a runtime should start");
        assert_eq!(session.status, Status::Idle);
        assert!(!session.is_running());

        let mut report = ScanReport::empty();
        let mut host = HostReport::new(address("10.0.0.1"));
        host.status = HostStatus::Up;
        report.hosts.push(host);
        report.recompute_stats();

        session.load_report(report);
        assert_eq!(session.status, Status::Finished);
        assert_eq!(session.results.hosts.len(), 1);
        assert_eq!(session.results.up_count(), 1);
    }

    #[test]
    fn a_scan_logs_what_it_finds_rather_than_only_that_it_ran() {
        let mut results = LiveResults::default();
        let mut status = Status::Running;
        let address: std::net::IpAddr = "10.0.0.5".parse().unwrap();

        apply(
            &mut results,
            ScanEvent::HostDiscovered {
                address,
                status: HostStatus::Up,
                rtt_ms: Some(3.25),
            },
            &mut status,
        );
        apply(
            &mut results,
            ScanEvent::PortResult {
                address,
                port: Box::new(PortReport::new(
                    22,
                    Transport::Tcp,
                    PortState::Open,
                    PortReason::ConnectionEstablished,
                )),
            },
            &mut status,
        );

        let lines: Vec<&str> = results
            .log
            .iter()
            .map(|entry| entry.message.as_str())
            .collect();
        assert!(
            lines.iter().any(|line| line.contains("host up: 10.0.0.5")),
            "a host coming up should be logged: {lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("22/tcp")),
            "an open port should be logged: {lines:?}"
        );
    }

    #[test]
    fn hosts_that_are_down_and_repeated_findings_are_not_logged() {
        let mut results = LiveResults::default();
        let mut status = Status::Running;
        let address: std::net::IpAddr = "10.0.0.9".parse().unwrap();

        apply(
            &mut results,
            ScanEvent::HostDiscovered {
                address,
                status: HostStatus::Down,
                rtt_ms: None,
            },
            &mut status,
        );
        assert!(results.log.is_empty(), "a host that is down is not news");

        let open = || ScanEvent::PortResult {
            address,
            port: Box::new(PortReport::new(
                80,
                Transport::Tcp,
                PortState::Open,
                PortReason::ConnectionEstablished,
            )),
        };
        apply(&mut results, open(), &mut status);
        let after_first = results.log.len();
        apply(&mut results, open(), &mut status);
        assert_eq!(
            results.log.len(),
            after_first,
            "the same port found twice should be logged once"
        );

        apply(
            &mut results,
            ScanEvent::PortResult {
                address,
                port: Box::new(PortReport::new(
                    81,
                    Transport::Tcp,
                    PortState::Closed,
                    PortReason::Refused,
                )),
            },
            &mut status,
        );
        assert_eq!(results.log.len(), after_first);
    }

    #[test]
    fn finishing_a_host_summarises_what_was_learned_about_it() {
        let mut results = LiveResults::default();
        let mut status = Status::Running;
        let mut host = HostReport::new("10.0.0.5".parse().unwrap());
        host.status = HostStatus::Up;
        host.vendor = Some("Raspberry Pi Foundation".to_string());
        host.ports.push(PortReport::new(
            22,
            Transport::Tcp,
            PortState::Open,
            PortReason::ConnectionEstablished,
        ));

        apply(
            &mut results,
            ScanEvent::HostCompleted {
                host: Box::new(host),
            },
            &mut status,
        );
        let last = &results.log.last().expect("a line was logged").message;
        assert!(last.contains("10.0.0.5"), "{last}");
        assert!(last.contains("1 open"), "{last}");
        assert!(last.contains("Raspberry Pi"), "{last}");
    }

    #[test]
    fn polling_without_a_scan_is_a_no_op() {
        let mut session = Session::new(ProbeRegistry::empty()).unwrap();
        assert!(!session.poll());
    }

    #[test]
    fn an_invalid_configuration_fails_the_session_rather_than_panicking() {
        let mut session = Session::new(ProbeRegistry::empty()).unwrap();

        session.start(ScanConfig::default());
        assert_eq!(session.status, Status::Failed);
        assert!(session.error.is_some());
        assert_eq!(session.results.log[0].level, LogLevel::Error);
    }
}
