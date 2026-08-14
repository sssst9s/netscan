use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{ProbeError, Warning};
use crate::scanner::port::Transport;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub fn oui(&self) -> [u8; 3] {
        [self.0[0], self.0[1], self.0[2]]
    }

    pub fn is_locally_administered(&self) -> bool {
        self.0[0] & 0x02 != 0
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl std::str::FromStr for MacAddress {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> crate::error::Result<Self> {
        let cleaned: Vec<&str> = s.split([':', '-']).collect();
        if cleaned.len() != 6 {
            return Err(crate::error::Error::Config(format!(
                "`{s}` is not a MAC address (expected six colon-separated octets)"
            )));
        }
        let mut bytes = [0u8; 6];
        for (slot, text) in bytes.iter_mut().zip(cleaned) {
            *slot = u8::from_str_radix(text, 16).map_err(|_| {
                crate::error::Error::Config(format!("`{text}` is not a hexadecimal octet"))
            })?;
        }
        Ok(MacAddress(bytes))
    }
}

impl Serialize for MacAddress {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for MacAddress {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let text = String::deserialize(de)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostStatus {
    Up,
    Down,
    Skipped,
}

impl fmt::Display for HostStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HostStatus::Up => "up",
            HostStatus::Down => "down",
            HostStatus::Skipped => "skipped",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
    Unknown,
}

impl PortState {
    pub fn as_str(self) -> &'static str {
        match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            PortState::OpenFiltered => "open|filtered",
            PortState::Unknown => "unknown",
        }
    }

    pub fn is_open_ish(self) -> bool {
        matches!(self, PortState::Open | PortState::OpenFiltered)
    }
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PortReason {
    ConnectionEstablished,
    SynAck,
    Reset,
    Refused,
    UdpResponse,
    PortUnreachable,
    AdminProhibited,
    NoResponse,
    HostUnreachable,
    ProbeFailed,
}

impl PortReason {
    pub fn as_str(self) -> &'static str {
        match self {
            PortReason::ConnectionEstablished => "connection-established",
            PortReason::SynAck => "syn-ack",
            PortReason::Reset => "reset",
            PortReason::Refused => "refused",
            PortReason::UdpResponse => "udp-response",
            PortReason::PortUnreachable => "port-unreachable",
            PortReason::AdminProhibited => "admin-prohibited",
            PortReason::NoResponse => "no-response",
            PortReason::HostUnreachable => "host-unreachable",
            PortReason::ProbeFailed => "probe-failed",
        }
    }
}

impl fmt::Display for PortReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Confidence {
    #[default]
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn score(self) -> u8 {
        match self {
            Confidence::Low => 3,
            Confidence::Medium => 6,
            Confidence::High => 10,
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "name")]
#[derive(Default)]
pub enum DetectionSource {
    #[default]
    PortNumber,
    Banner,
    Probe(String),
    Tls,
}

impl fmt::Display for DetectionSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DetectionSource::PortNumber => f.write_str("port-number"),
            DetectionSource::Banner => f.write_str("banner"),
            DetectionSource::Probe(name) => write!(f, "probe:{name}"),
            DetectionSource::Tls => f.write_str("tls"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tls: bool,
    pub source: DetectionSource,
    pub confidence: Confidence,
}

impl ServiceInfo {
    pub fn from_port_number(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            source: DetectionSource::PortNumber,
            confidence: Confidence::Low,
            ..Self::default()
        }
    }

    pub fn product_version(&self) -> Option<String> {
        match (&self.product, &self.version) {
            (Some(p), Some(v)) => Some(format!("{p} {v}")),
            (Some(p), None) => Some(p.clone()),
            (None, Some(v)) => Some(v.clone()),
            (None, None) => None,
        }
    }

    pub fn summary(&self) -> String {
        let mut out = self.name.clone();
        if let Some(pv) = self.product_version() {
            out.push_str(" (");
            out.push_str(&pv);
            out.push(')');
        }
        out
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subject_alt_names: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub expired: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub self_signed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortReport {
    pub port: u16,
    pub transport: Transport,
    pub state: PortState,
    pub reason: PortReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<ServiceInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ProbeError>,
    #[serde(default = "one")]
    pub attempts: u8,
}

fn one() -> u8 {
    1
}

impl PortReport {
    pub fn new(port: u16, transport: Transport, state: PortState, reason: PortReason) -> Self {
        Self {
            port,
            transport,
            state,
            reason,
            rtt_ms: None,
            service: None,
            tls: None,
            banner: None,
            error: None,
            attempts: 1,
        }
    }

    pub fn service_name(&self) -> &str {
        match &self.service {
            Some(service) => &service.name,
            None => crate::detection::service::name_for_port(self.transport, self.port)
                .unwrap_or("unknown"),
        }
    }

    pub fn label(&self) -> String {
        format!("{}/{}", self.port, self.transport)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hostname {
    pub name: String,
    pub source: HostnameSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostnameSource {
    UserSupplied,
    ReverseDns,
    TlsCertificate,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsGuess {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_type: Option<String>,
    pub confidence: Confidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<OsEvidence>,
}

impl OsGuess {
    pub fn is_empty(&self) -> bool {
        self.family.is_none() && self.name.is_none() && self.device_type.is_none()
    }

    pub fn summary(&self) -> String {
        let label = self
            .name
            .clone()
            .or_else(|| self.family.clone())
            .or_else(|| self.device_type.clone())
            .unwrap_or_else(|| "unknown".to_string());
        format!("{label} ({} confidence)", self.confidence)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsEvidence {
    pub kind: String,
    pub detail: String,
    pub suggests: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortSummary {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub counts: BTreeMap<String, u64>,
}

impl PortSummary {
    pub fn record(&mut self, state: PortState) {
        *self.counts.entry(state.as_str().to_string()).or_insert(0) += 1;
    }

    pub fn get(&self, state: PortState) -> u64 {
        self.counts.get(state.as_str()).copied().unwrap_or(0)
    }

    pub fn total(&self) -> u64 {
        self.counts.values().sum()
    }

    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostReport {
    pub address: IpAddr,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<Hostname>,
    pub status: HostStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<MacAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<OsGuess>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<PortReport>,
    #[serde(default, skip_serializing_if = "PortSummary::is_empty")]
    pub other_ports: PortSummary,
    #[serde(default)]
    pub not_scanned: u64,
    pub started_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
}

impl HostReport {
    pub fn new(address: IpAddr) -> Self {
        Self {
            address,
            hostnames: Vec::new(),
            status: HostStatus::Skipped,
            status_reason: None,
            rtt_ms: None,
            mac: None,
            vendor: None,
            os: None,
            ports: Vec::new(),
            other_ports: PortSummary::default(),
            not_scanned: 0,
            started_at: Utc::now(),
            finished_at: None,
        }
    }

    pub fn primary_hostname(&self) -> Option<&str> {
        self.hostnames
            .iter()
            .find(|h| h.source == HostnameSource::ReverseDns)
            .or_else(|| self.hostnames.first())
            .map(|h| h.name.as_str())
    }

    pub fn add_hostname(&mut self, name: impl Into<String>, source: HostnameSource) {
        let name = name.into();
        if !self.hostnames.iter().any(|h| h.name == name) {
            self.hostnames.push(Hostname { name, source });
        }
    }

    pub fn open_ports(&self) -> impl Iterator<Item = &PortReport> {
        self.ports.iter().filter(|p| p.state == PortState::Open)
    }

    pub fn open_port_count(&self) -> usize {
        self.open_ports().count()
    }

    pub fn ports_tested(&self) -> u64 {
        self.ports.len() as u64 + self.other_ports.total()
    }

    pub fn sort_ports(&mut self) {
        self.ports.sort_by_key(|p| (p.transport, p.port));
    }

    pub fn duration(&self) -> Option<chrono::TimeDelta> {
        self.finished_at.map(|end| end - self.started_at)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ScanStats {
    pub hosts_total: u64,
    pub hosts_up: u64,
    pub hosts_down: u64,
    pub probes_sent: u64,
    pub ports_tested: u64,
    pub ports_open: u64,
    pub ports_closed: u64,
    pub ports_filtered: u64,
    pub retries: u64,
    pub errors: u64,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mean_rtt_ms: Option<f64>,
}

impl ScanStats {
    pub fn probes_per_second(&self) -> f64 {
        if self.duration_ms == 0 {
            return 0.0;
        }
        self.probes_sent as f64 * 1000.0 / self.duration_ms as f64
    }

    pub fn retry_rate(&self) -> f64 {
        if self.probes_sent == 0 {
            return 0.0;
        }
        self.retries as f64 / self.probes_sent as f64
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanParameters {
    pub targets: Vec<String>,
    pub ports: String,
    pub transports: Vec<String>,
    pub tcp_mode: String,
    pub timing: String,
    pub concurrency: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub service_detection: bool,
    pub os_detection: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
}

impl Default for ToolInfo {
    fn default() -> Self {
        Self {
            name: "netscan".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScanOutcome {
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: u32,
    pub tool: ToolInfo,
    pub scan_id: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub outcome: ScanOutcome,
    pub parameters: ScanParameters,
    pub hosts: Vec<HostReport>,
    pub stats: ScanStats,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Warning>,
}

impl ScanReport {
    pub fn empty() -> Self {
        let now = Utc::now();
        Self {
            schema_version: SCHEMA_VERSION,
            tool: ToolInfo::default(),
            scan_id: new_scan_id(now),
            started_at: now,
            finished_at: now,
            outcome: ScanOutcome::Completed,
            parameters: ScanParameters::default(),
            hosts: Vec::new(),
            stats: ScanStats::default(),
            warnings: Vec::new(),
        }
    }

    pub fn hosts_up(&self) -> impl Iterator<Item = &HostReport> {
        self.hosts.iter().filter(|h| h.status == HostStatus::Up)
    }

    pub fn host(&self, address: &IpAddr) -> Option<&HostReport> {
        self.hosts.iter().find(|h| &h.address == address)
    }

    pub fn open_ports(&self) -> impl Iterator<Item = (&HostReport, &PortReport)> {
        self.hosts
            .iter()
            .flat_map(|h| h.open_ports().map(move |p| (h, p)))
    }

    pub fn services_by_frequency(&self) -> Vec<(String, u64)> {
        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
        for (_, port) in self.open_ports() {
            *counts.entry(port.service_name().to_string()).or_insert(0) += 1;
        }
        let mut out: Vec<_> = counts.into_iter().collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        out
    }

    pub fn recompute_stats(&mut self) {
        let mut stats = ScanStats {
            duration_ms: (self.finished_at - self.started_at)
                .num_milliseconds()
                .max(0) as u64,
            probes_sent: self.stats.probes_sent,
            retries: self.stats.retries,
            errors: self.stats.errors,
            ..ScanStats::default()
        };

        let mut rtt_total = 0.0f64;
        let mut rtt_count = 0u64;

        stats.hosts_total = self.hosts.len() as u64;
        for host in &self.hosts {
            match host.status {
                HostStatus::Up => stats.hosts_up += 1,
                HostStatus::Down => stats.hosts_down += 1,
                HostStatus::Skipped => {}
            }
            stats.ports_tested += host.ports_tested();
            for port in &host.ports {
                match port.state {
                    PortState::Open => stats.ports_open += 1,
                    PortState::Closed => stats.ports_closed += 1,
                    PortState::Filtered | PortState::OpenFiltered => stats.ports_filtered += 1,
                    PortState::Unknown => {}
                }
                if let Some(rtt) = port.rtt_ms {
                    rtt_total += rtt;
                    rtt_count += 1;
                }
            }
            stats.ports_open += 0;
            stats.ports_closed += host.other_ports.get(PortState::Closed);
            stats.ports_filtered += host.other_ports.get(PortState::Filtered)
                + host.other_ports.get(PortState::OpenFiltered);
        }

        if rtt_count > 0 {
            stats.mean_rtt_ms = Some(rtt_total / rtt_count as f64);
        }
        self.stats = stats;
    }

    pub fn sort(&mut self) {
        self.hosts.sort_by_key(|h| h.address);
        for host in &mut self.hosts {
            host.sort_ports();
        }
    }
}

pub fn new_scan_id(now: DateTime<Utc>) -> String {
    use rand::Rng;
    let suffix: u32 = rand::thread_rng().gen();
    format!(
        "{}-{:06x}",
        now.format("%Y%m%dT%H%M%SZ"),
        suffix & 0x00ff_ffff
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_with_ports() -> HostReport {
        let mut host = HostReport::new("192.168.1.10".parse().unwrap());
        host.status = HostStatus::Up;
        host.ports.push(PortReport::new(
            22,
            Transport::Tcp,
            PortState::Open,
            PortReason::ConnectionEstablished,
        ));
        host.ports.push(PortReport::new(
            80,
            Transport::Tcp,
            PortState::Open,
            PortReason::ConnectionEstablished,
        ));
        host.ports.push(PortReport::new(
            23,
            Transport::Tcp,
            PortState::Closed,
            PortReason::Refused,
        ));
        host
    }

    #[test]
    fn mac_address_formats_and_parses() {
        let mac: MacAddress = "AA:bb:CC:00:11:22".parse().unwrap();
        assert_eq!(mac.to_string(), "aa:bb:cc:00:11:22");
        assert_eq!(mac.oui(), [0xaa, 0xbb, 0xcc]);
        assert_eq!("aa-bb-cc-00-11-22".parse::<MacAddress>().unwrap(), mac);
        assert!("aa:bb:cc".parse::<MacAddress>().is_err());
        assert!("zz:bb:cc:00:11:22".parse::<MacAddress>().is_err());
    }

    #[test]
    fn locally_administered_detection() {
        assert!("02:00:00:00:00:01"
            .parse::<MacAddress>()
            .unwrap()
            .is_locally_administered());
        assert!(!"00:1a:2b:00:00:01"
            .parse::<MacAddress>()
            .unwrap()
            .is_locally_administered());
    }

    #[test]
    fn port_state_open_ish() {
        assert!(PortState::Open.is_open_ish());
        assert!(PortState::OpenFiltered.is_open_ish());
        assert!(!PortState::Closed.is_open_ish());
        assert_eq!(PortState::OpenFiltered.to_string(), "open|filtered");
    }

    #[test]
    fn service_summary_includes_product_and_version() {
        let service = ServiceInfo {
            name: "http".into(),
            product: Some("nginx".into()),
            version: Some("1.24.0".into()),
            source: DetectionSource::Probe("http".into()),
            confidence: Confidence::High,
            ..Default::default()
        };
        assert_eq!(service.summary(), "http (nginx 1.24.0)");
        assert_eq!(service.product_version().as_deref(), Some("nginx 1.24.0"));
    }

    #[test]
    fn service_falls_back_to_port_catalog() {
        let port = PortReport::new(22, Transport::Tcp, PortState::Open, PortReason::SynAck);
        assert_eq!(port.service_name(), "ssh");
        assert_eq!(port.label(), "22/tcp");
    }

    #[test]
    fn port_number_guesses_are_low_confidence() {
        let service = ServiceInfo::from_port_number("http");
        assert_eq!(service.confidence, Confidence::Low);
        assert_eq!(service.source, DetectionSource::PortNumber);
    }

    #[test]
    fn primary_hostname_prefers_reverse_dns() {
        let mut host = HostReport::new("10.0.0.1".parse().unwrap());
        host.add_hostname("typed.example", HostnameSource::UserSupplied);
        host.add_hostname("real.example", HostnameSource::ReverseDns);
        assert_eq!(host.primary_hostname(), Some("real.example"));
    }

    #[test]
    fn adding_a_duplicate_hostname_is_a_no_op() {
        let mut host = HostReport::new("10.0.0.1".parse().unwrap());
        host.add_hostname("a.example", HostnameSource::ReverseDns);
        host.add_hostname("a.example", HostnameSource::UserSupplied);
        assert_eq!(host.hostnames.len(), 1);
    }

    #[test]
    fn port_summary_counts_by_state() {
        let mut summary = PortSummary::default();
        summary.record(PortState::Closed);
        summary.record(PortState::Closed);
        summary.record(PortState::Filtered);
        assert_eq!(summary.get(PortState::Closed), 2);
        assert_eq!(summary.total(), 3);
    }

    #[test]
    fn stats_are_recomputed_from_hosts() {
        let mut report = ScanReport::empty();
        report.hosts.push(host_with_ports());
        let mut down = HostReport::new("192.168.1.11".parse().unwrap());
        down.status = HostStatus::Down;
        report.hosts.push(down);
        report.recompute_stats();

        assert_eq!(report.stats.hosts_total, 2);
        assert_eq!(report.stats.hosts_up, 1);
        assert_eq!(report.stats.hosts_down, 1);
        assert_eq!(report.stats.ports_open, 2);
        assert_eq!(report.stats.ports_closed, 1);
    }

    #[test]
    fn summarised_ports_count_toward_stats() {
        let mut report = ScanReport::empty();
        let mut host = host_with_ports();
        for _ in 0..1000 {
            host.other_ports.record(PortState::Closed);
        }
        report.hosts.push(host);
        report.recompute_stats();
        assert_eq!(report.stats.ports_closed, 1001);
        assert_eq!(report.stats.ports_tested, 1003);
    }

    #[test]
    fn service_frequency_is_sorted_by_count() {
        let mut report = ScanReport::empty();
        report.hosts.push(host_with_ports());
        let mut other = HostReport::new("192.168.1.12".parse().unwrap());
        other.status = HostStatus::Up;
        other.ports.push(PortReport::new(
            22,
            Transport::Tcp,
            PortState::Open,
            PortReason::ConnectionEstablished,
        ));
        report.hosts.push(other);

        let freq = report.services_by_frequency();
        assert_eq!(freq[0], ("ssh".to_string(), 2));
        assert_eq!(freq[1], ("http".to_string(), 1));
    }

    #[test]
    fn probes_per_second_handles_zero_duration() {
        let stats = ScanStats {
            probes_sent: 100,
            duration_ms: 0,
            ..Default::default()
        };
        assert_eq!(stats.probes_per_second(), 0.0);

        let stats = ScanStats {
            probes_sent: 100,
            duration_ms: 1000,
            ..Default::default()
        };
        assert_eq!(stats.probes_per_second(), 100.0);
    }

    #[test]
    fn report_round_trips_through_json() {
        let mut report = ScanReport::empty();
        report.hosts.push(host_with_ports());
        report.recompute_stats();

        let text = serde_json::to_string(&report).unwrap();
        let parsed: ScanReport = serde_json::from_str(&text).unwrap();
        assert_eq!(report, parsed);
        assert!(text.contains("\"schema_version\":1"));
    }

    #[test]
    fn optional_fields_are_omitted_from_json() {
        let port = PortReport::new(80, Transport::Tcp, PortState::Open, PortReason::SynAck);
        let text = serde_json::to_string(&port).unwrap();
        assert!(
            !text.contains("service"),
            "empty optional fields should be omitted: {text}"
        );
        assert!(!text.contains("null"), "no nulls should appear: {text}");
    }

    #[test]
    fn scan_ids_are_unique_and_sortable() {
        let now = Utc::now();
        let a = new_scan_id(now);
        let b = new_scan_id(now);
        assert_ne!(a, b);
        assert!(a.starts_with(&now.format("%Y%m%d").to_string()));
    }

    #[test]
    fn sorting_is_stable_across_runs() {
        let mut report = ScanReport::empty();
        report.hosts.push(host_with_ports());
        report
            .hosts
            .push(HostReport::new("10.0.0.1".parse().unwrap()));
        report.sort();
        assert_eq!(report.hosts[0].address.to_string(), "10.0.0.1");
        assert_eq!(report.hosts[1].ports[0].port, 22);
        assert_eq!(report.hosts[1].ports[1].port, 23);
    }
}
