use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::error::Warning;
use crate::scanner::result::{HostReport, HostStatus, PortReport, ScanReport};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Progress {
    pub hosts_total: u64,
    pub hosts_completed: u64,
    pub hosts_up: u64,
    pub probes_total: u64,
    pub probes_completed: u64,
    pub open_ports: u64,
    pub elapsed: Duration,
    pub rate: f64,
    pub concurrency: usize,
    pub timeout: Duration,
}

impl Default for Progress {
    fn default() -> Self {
        Self {
            hosts_total: 0,
            hosts_completed: 0,
            hosts_up: 0,
            probes_total: 0,
            probes_completed: 0,
            open_ports: 0,
            elapsed: Duration::ZERO,
            rate: 0.0,
            concurrency: 0,
            timeout: Duration::ZERO,
        }
    }
}

impl Progress {
    pub fn fraction(&self) -> f64 {
        if self.probes_total > 0 {
            (self.probes_completed as f64 / self.probes_total as f64).clamp(0.0, 1.0)
        } else if self.hosts_total > 0 {
            (self.hosts_completed as f64 / self.hosts_total as f64).clamp(0.0, 1.0)
        } else {
            0.0
        }
    }

    pub fn percent(&self) -> u8 {
        (self.fraction() * 100.0) as u8
    }

    pub fn eta(&self) -> Option<Duration> {
        if self.probes_total == 0 || self.probes_completed == 0 || self.rate <= 0.0 {
            return None;
        }
        let remaining = self.probes_total.saturating_sub(self.probes_completed);
        if remaining == 0 {
            return Some(Duration::ZERO);
        }
        let seconds = remaining as f64 / self.rate;
        if !seconds.is_finite() || seconds > 86_400.0 * 30.0 {
            return None;
        }
        Some(Duration::from_secs_f64(seconds))
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ScanEvent {
    Started {
        hosts_total: u64,
        ports_per_host: u64,
        started_at: DateTime<Utc>,
    },
    HostDiscovered {
        address: IpAddr,
        status: HostStatus,
        rtt_ms: Option<f64>,
    },
    HostStarted {
        address: IpAddr,
    },
    PortResult {
        address: IpAddr,
        port: Box<PortReport>,
    },
    HostCompleted {
        host: Box<HostReport>,
    },
    Progress(Progress),
    Warning(Warning),
    Finished {
        report: Box<ScanReport>,
    },
}

impl ScanEvent {
    pub fn address(&self) -> Option<IpAddr> {
        match self {
            ScanEvent::HostDiscovered { address, .. }
            | ScanEvent::HostStarted { address, .. }
            | ScanEvent::PortResult { address, .. } => Some(*address),
            ScanEvent::HostCompleted { host } => Some(host.address),
            ScanEvent::Warning(w) => w.host,
            _ => None,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, ScanEvent::Finished { .. })
    }

    pub fn kind(&self) -> &'static str {
        match self {
            ScanEvent::Started { .. } => "started",
            ScanEvent::HostDiscovered { .. } => "host-discovered",
            ScanEvent::HostStarted { .. } => "host-started",
            ScanEvent::PortResult { .. } => "port-result",
            ScanEvent::HostCompleted { .. } => "host-completed",
            ScanEvent::Progress(_) => "progress",
            ScanEvent::Warning(_) => "warning",
            ScanEvent::Finished { .. } => "finished",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fraction_falls_back_to_host_counts_before_probes_are_known() {
        let progress = Progress {
            hosts_total: 10,
            hosts_completed: 3,
            ..Default::default()
        };
        assert!((progress.fraction() - 0.3).abs() < f64::EPSILON);
        assert_eq!(progress.percent(), 30);
    }

    #[test]
    fn fraction_prefers_probe_counts_once_available() {
        let progress = Progress {
            hosts_total: 10,
            hosts_completed: 3,
            probes_total: 1000,
            probes_completed: 900,
            ..Default::default()
        };
        assert_eq!(progress.percent(), 90);
    }

    #[test]
    fn fraction_is_zero_with_no_information() {
        assert_eq!(Progress::default().fraction(), 0.0);
    }

    #[test]
    fn fraction_is_clamped() {
        let progress = Progress {
            probes_total: 10,
            probes_completed: 999,
            ..Default::default()
        };
        assert_eq!(progress.fraction(), 1.0);
    }

    #[test]
    fn eta_is_withheld_until_it_would_be_meaningful() {
        assert_eq!(Progress::default().eta(), None);

        let no_rate = Progress {
            probes_total: 100,
            probes_completed: 10,
            rate: 0.0,
            ..Default::default()
        };
        assert_eq!(no_rate.eta(), None);

        let no_progress = Progress {
            probes_total: 100,
            probes_completed: 0,
            rate: 5.0,
            ..Default::default()
        };
        assert_eq!(no_progress.eta(), None);
    }

    #[test]
    fn eta_uses_the_observed_rate() {
        let progress = Progress {
            probes_total: 1000,
            probes_completed: 200,
            rate: 100.0,
            ..Default::default()
        };
        assert_eq!(progress.eta(), Some(Duration::from_secs(8)));
    }

    #[test]
    fn eta_is_zero_when_done() {
        let progress = Progress {
            probes_total: 100,
            probes_completed: 100,
            rate: 10.0,
            ..Default::default()
        };
        assert_eq!(progress.eta(), Some(Duration::ZERO));
    }

    #[test]
    fn absurd_etas_are_suppressed() {
        let progress = Progress {
            probes_total: u64::MAX / 2,
            probes_completed: 1,
            rate: 0.001,
            ..Default::default()
        };
        assert_eq!(progress.eta(), None);
    }

    #[test]
    fn event_addresses_and_kinds() {
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        let event = ScanEvent::HostStarted { address: addr };
        assert_eq!(event.address(), Some(addr));
        assert_eq!(event.kind(), "host-started");
        assert!(!event.is_terminal());

        let finished = ScanEvent::Finished {
            report: Box::new(ScanReport::empty()),
        };
        assert!(finished.is_terminal());
        assert_eq!(finished.address(), None);
    }
}
