use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::scanner::port::{PortSelection, Transport};
use crate::scanner::target::{IpFamily, TargetSpec};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_targets: u64,
    pub max_ports_per_host: u64,
    pub max_total_probes: u64,
    pub max_concurrency: usize,
    pub max_response_bytes: usize,
    pub event_buffer: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_targets: 65_536,
            max_ports_per_host: 65_535 * 2,
            max_total_probes: 20_000_000,
            max_concurrency: 20_000,
            max_response_bytes: 64 * 1024,
            event_buffer: 4096,
        }
    }
}

impl Limits {
    pub fn permissive() -> Self {
        Self {
            max_targets: 1_048_576,
            max_total_probes: 200_000_000,
            max_concurrency: 65_536,
            ..Self::default()
        }
    }

    fn validate(&self) -> Result<()> {
        if self.max_concurrency == 0 {
            return Err(Error::Config(
                "limits.max_concurrency must be at least 1".into(),
            ));
        }
        if self.max_response_bytes < 64 {
            return Err(Error::Config(
                "limits.max_response_bytes must be at least 64".into(),
            ));
        }
        if self.event_buffer == 0 {
            return Err(Error::Config(
                "limits.event_buffer must be at least 1".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimingTemplate {
    Sneaky,
    Polite,
    #[default]
    Normal,
    Aggressive,
    Insane,
}

impl TimingTemplate {
    pub const ALL: &'static [TimingTemplate] = &[
        TimingTemplate::Sneaky,
        TimingTemplate::Polite,
        TimingTemplate::Normal,
        TimingTemplate::Aggressive,
        TimingTemplate::Insane,
    ];

    pub fn name(self) -> &'static str {
        match self {
            TimingTemplate::Sneaky => "sneaky",
            TimingTemplate::Polite => "polite",
            TimingTemplate::Normal => "normal",
            TimingTemplate::Aggressive => "aggressive",
            TimingTemplate::Insane => "insane",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            TimingTemplate::Sneaky => "serial probes with a long delay; slowest and quietest",
            TimingTemplate::Polite => "low concurrency and a small delay; gentle on shared links",
            TimingTemplate::Normal => "balanced defaults suitable for most networks",
            TimingTemplate::Aggressive => "high concurrency and short timeouts; for LANs you own",
            TimingTemplate::Insane => "maximum throughput; expect loss and false negatives",
        }
    }

    pub fn timing(self) -> TimingConfig {
        let (concurrency, connect_ms, retries, delay_ms) = match self {
            TimingTemplate::Sneaky => (1, 5_000, 2, 400),
            TimingTemplate::Polite => (16, 3_000, 2, 20),
            TimingTemplate::Normal => (512, 1_500, 1, 0),
            TimingTemplate::Aggressive => (2_048, 800, 1, 0),
            TimingTemplate::Insane => (5_000, 400, 0, 0),
        };
        TimingConfig {
            template: self,
            concurrency,
            connect_timeout: Duration::from_millis(connect_ms),
            read_timeout: Duration::from_millis(connect_ms.max(1_000)),
            retries,
            scan_delay: Duration::from_millis(delay_ms),
            host_timeout: None,
            max_rate: None,
            adaptive: !matches!(self, TimingTemplate::Sneaky),
        }
    }
}

impl std::fmt::Display for TimingTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl std::str::FromStr for TimingTemplate {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let normalised = s.trim().to_ascii_lowercase();
        TimingTemplate::ALL
            .iter()
            .copied()
            .find(|t| t.name() == normalised)
            .ok_or_else(|| {
                let names: Vec<_> = TimingTemplate::ALL.iter().map(|t| t.name()).collect();
                Error::Config(format!(
                    "unknown timing template `{s}`, expected one of: {}",
                    names.join(", ")
                ))
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TimingConfig {
    pub template: TimingTemplate,
    pub concurrency: usize,
    #[serde(with = "crate::config::duration_ms")]
    pub connect_timeout: Duration,
    #[serde(with = "crate::config::duration_ms")]
    pub read_timeout: Duration,
    pub retries: u8,
    #[serde(with = "crate::config::duration_ms")]
    pub scan_delay: Duration,
    #[serde(with = "crate::config::opt_duration_ms")]
    pub host_timeout: Option<Duration>,
    pub max_rate: Option<u32>,
    pub adaptive: bool,
}

impl Default for TimingConfig {
    fn default() -> Self {
        TimingTemplate::Normal.timing()
    }
}

impl TimingConfig {
    fn validate(&self, limits: &Limits) -> Result<()> {
        if self.concurrency == 0 {
            return Err(Error::Config(
                "timing.concurrency must be at least 1".into(),
            ));
        }
        if self.concurrency > limits.max_concurrency {
            return Err(Error::LimitExceeded {
                what: "concurrency",
                requested: self.concurrency as u64,
                maximum: limits.max_concurrency as u64,
                hint: "lower --concurrency or raise limits.max_concurrency",
            });
        }
        if self.connect_timeout.is_zero() {
            return Err(Error::Config(
                "timing.connect_timeout must be greater than zero".into(),
            ));
        }
        if self.read_timeout.is_zero() {
            return Err(Error::Config(
                "timing.read_timeout must be greater than zero".into(),
            ));
        }
        if self.retries > 10 {
            return Err(Error::Config("timing.retries must be 10 or fewer".into()));
        }
        if matches!(self.max_rate, Some(0)) {
            return Err(Error::Config(
                "timing.max_rate must be greater than zero".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TcpScanMode {
    #[default]
    Connect,
    Syn,
    Auto,
}

impl TcpScanMode {
    pub fn name(self) -> &'static str {
        match self {
            TcpScanMode::Connect => "connect",
            TcpScanMode::Syn => "syn",
            TcpScanMode::Auto => "auto",
        }
    }
}

impl std::fmt::Display for TcpScanMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanModes {
    pub tcp: bool,
    pub tcp_mode: TcpScanMode,
    pub udp: bool,
}

impl Default for ScanModes {
    fn default() -> Self {
        Self {
            tcp: true,
            tcp_mode: TcpScanMode::Connect,
            udp: false,
        }
    }
}

impl ScanModes {
    pub fn transports(&self) -> Vec<Transport> {
        let mut out = Vec::new();
        if self.tcp {
            out.push(Transport::Tcp);
        }
        if self.udp {
            out.push(Transport::Udp);
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DiscoveryConfig {
    pub enabled: bool,
    pub icmp_echo: bool,
    pub tcp_ping: bool,
    pub tcp_ping_ports: Vec<u16>,
    pub arp: bool,
    pub infer_from_ports: bool,
    pub discovery_only: bool,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            icmp_echo: true,
            tcp_ping: true,
            tcp_ping_ports: vec![443, 80, 22, 445, 3389],
            arp: true,
            infer_from_ports: true,
            discovery_only: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DetectionConfig {
    pub banner_grab: bool,
    pub service_detection: bool,
    pub version_detection: bool,
    pub tls_inspection: bool,
    pub os_fingerprint: bool,
    pub max_intrusiveness: u8,
    pub probe_files: Vec<std::path::PathBuf>,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            banner_grab: true,
            service_detection: false,
            version_detection: false,
            tls_inspection: false,
            os_fingerprint: false,
            max_intrusiveness: 7,
            probe_files: Vec::new(),
        }
    }
}

impl DetectionConfig {
    pub fn full() -> Self {
        Self {
            banner_grab: true,
            service_detection: true,
            version_detection: true,
            tls_inspection: true,
            os_fingerprint: true,
            ..Self::default()
        }
    }

    pub fn any_enabled(&self) -> bool {
        self.banner_grab || self.service_detection || self.version_detection || self.tls_inspection
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    pub resolve_targets: bool,
    pub reverse_lookup: bool,
    pub servers: Vec<IpAddr>,
    #[serde(with = "crate::config::duration_ms")]
    pub timeout: Duration,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            resolve_targets: true,
            reverse_lookup: true,
            servers: Vec::new(),
            timeout: Duration::from_secs(3),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    pub targets: Vec<TargetSpec>,
    pub exclusions: Vec<TargetSpec>,
    pub ports: PortSelection,
    pub modes: ScanModes,
    pub discovery: DiscoveryConfig,
    pub detection: DetectionConfig,
    pub timing: TimingConfig,
    pub limits: Limits,
    pub dns: DnsConfig,
    pub family: IpFamily,
    pub interface: Option<String>,
    pub include_network_addresses: bool,
    pub profile_name: Option<String>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            exclusions: Vec::new(),
            ports: PortSelection::tcp(crate::detection::service::top_tcp_ports(100)),
            modes: ScanModes::default(),
            discovery: DiscoveryConfig::default(),
            detection: DetectionConfig::default(),
            timing: TimingConfig::default(),
            limits: Limits::default(),
            dns: DnsConfig::default(),
            family: IpFamily::default(),
            interface: None,
            include_network_addresses: false,
            profile_name: None,
        }
    }
}

impl ScanConfig {
    pub fn builder() -> ScanConfigBuilder {
        ScanConfigBuilder {
            config: ScanConfig::default(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.targets.is_empty() {
            return Err(Error::Config("no targets specified".into()));
        }

        self.limits.validate()?;
        self.timing.validate(&self.limits)?;

        let scanning_ports = !self.discovery.discovery_only;
        if scanning_ports {
            if self.modes.transports().is_empty() {
                return Err(Error::Config(
                    "no transport enabled: enable --tcp, --udp, or use --ping for discovery only"
                        .into(),
                ));
            }
            if self.modes.tcp && self.ports.tcp.is_empty() && !self.modes.udp {
                return Err(Error::Config(
                    "TCP scanning is enabled but no TCP ports were selected".into(),
                ));
            }
            if self.modes.udp && self.ports.udp.is_empty() && !self.modes.tcp {
                return Err(Error::Config(
                    "UDP scanning is enabled but no UDP ports were selected".into(),
                ));
            }
            if self.ports.is_empty() {
                return Err(Error::Config("no ports selected".into()));
            }

            let ports_per_host = self.enabled_ports_per_host();
            if ports_per_host > self.limits.max_ports_per_host {
                return Err(Error::LimitExceeded {
                    what: "port",
                    requested: ports_per_host,
                    maximum: self.limits.max_ports_per_host,
                    hint: "select fewer ports or raise limits.max_ports_per_host",
                });
            }
        }

        if self.detection.max_intrusiveness > 9 {
            return Err(Error::Config(
                "detection.max_intrusiveness must be 0-9".into(),
            ));
        }

        if let Some(name) = &self.interface {
            if name.trim().is_empty() {
                return Err(Error::Config("interface name is empty".into()));
            }
        }

        Ok(())
    }

    pub fn enabled_ports_per_host(&self) -> u64 {
        let mut total = 0u64;
        if self.modes.tcp {
            total += self.ports.tcp.len() as u64;
        }
        if self.modes.udp {
            total += self.ports.udp.len() as u64;
        }
        total
    }

    pub fn check_probe_budget(&self, host_count: u64) -> Result<()> {
        let total = self.enabled_ports_per_host().saturating_mul(host_count);
        if total > self.limits.max_total_probes {
            return Err(Error::LimitExceeded {
                what: "probe",
                requested: total,
                maximum: self.limits.max_total_probes,
                hint: "narrow the targets or ports, or raise limits.max_total_probes",
            });
        }
        Ok(())
    }

    pub fn requires_privileges(&self) -> bool {
        matches!(self.modes.tcp_mode, TcpScanMode::Syn)
    }

    pub fn benefits_from_privileges(&self) -> bool {
        self.requires_privileges()
            || matches!(self.modes.tcp_mode, TcpScanMode::Auto)
            || (self.discovery.enabled && self.discovery.arp)
    }
}

#[derive(Debug, Clone)]
pub struct ScanConfigBuilder {
    config: ScanConfig,
}

impl ScanConfigBuilder {
    pub fn targets(mut self, targets: Vec<TargetSpec>) -> Self {
        self.config.targets = targets;
        self
    }

    pub fn target(mut self, target: TargetSpec) -> Self {
        self.config.targets.push(target);
        self
    }

    pub fn exclusions(mut self, exclusions: Vec<TargetSpec>) -> Self {
        self.config.exclusions = exclusions;
        self
    }

    pub fn ports(mut self, ports: PortSelection) -> Self {
        self.config.ports = ports;
        self
    }

    pub fn modes(mut self, modes: ScanModes) -> Self {
        self.config.modes = modes;
        self
    }

    pub fn timing(mut self, timing: TimingConfig) -> Self {
        self.config.timing = timing;
        self
    }

    pub fn timing_template(mut self, template: TimingTemplate) -> Self {
        self.config.timing = template.timing();
        self
    }

    pub fn concurrency(mut self, concurrency: usize) -> Self {
        self.config.timing.concurrency = concurrency;
        self
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.config.timing.connect_timeout = timeout;
        self
    }

    pub fn retries(mut self, retries: u8) -> Self {
        self.config.timing.retries = retries;
        self
    }

    pub fn discovery(mut self, discovery: DiscoveryConfig) -> Self {
        self.config.discovery = discovery;
        self
    }

    pub fn detection(mut self, detection: DetectionConfig) -> Self {
        self.config.detection = detection;
        self
    }

    pub fn limits(mut self, limits: Limits) -> Self {
        self.config.limits = limits;
        self
    }

    pub fn dns(mut self, dns: DnsConfig) -> Self {
        self.config.dns = dns;
        self
    }

    pub fn family(mut self, family: IpFamily) -> Self {
        self.config.family = family;
        self
    }

    pub fn interface(mut self, interface: impl Into<String>) -> Self {
        self.config.interface = Some(interface.into());
        self
    }

    pub fn build(self) -> Result<ScanConfig> {
        self.config.validate()?;
        Ok(self.config)
    }

    pub fn build_unvalidated(self) -> ScanConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::port::{PortSet, PortSpec};

    fn config_with_target() -> ScanConfigBuilder {
        ScanConfig::builder().target("127.0.0.1".parse().unwrap())
    }

    #[test]
    fn default_config_needs_targets() {
        let err = ScanConfig::default().validate().unwrap_err();
        assert!(err.to_string().contains("no targets"));
    }

    #[test]
    fn minimal_config_validates() {
        let config = config_with_target().build().unwrap();
        assert!(config.modes.tcp);
        assert_eq!(config.ports.tcp.len(), 100);
    }

    #[test]
    fn zero_concurrency_is_rejected() {
        let err = config_with_target().concurrency(0).build().unwrap_err();
        assert!(err.to_string().contains("concurrency"));
    }

    #[test]
    fn concurrency_above_the_hard_limit_is_rejected() {
        let err = config_with_target()
            .concurrency(1_000_000)
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::LimitExceeded {
                what: "concurrency",
                ..
            }
        ));
    }

    #[test]
    fn zero_timeout_is_rejected() {
        let err = config_with_target()
            .connect_timeout(Duration::ZERO)
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("connect_timeout"));
    }

    #[test]
    fn empty_port_selection_is_rejected() {
        let err = config_with_target()
            .ports(PortSelection::default())
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("no TCP ports") || err.to_string().contains("no ports"));
    }

    #[test]
    fn udp_only_scan_validates() {
        let config = config_with_target()
            .modes(ScanModes {
                tcp: false,
                udp: true,
                ..Default::default()
            })
            .ports(PortSelection::udp(PortSet::from_iter_ordered([53, 161])))
            .build()
            .unwrap();
        assert_eq!(config.enabled_ports_per_host(), 2);
    }

    #[test]
    fn discovery_only_needs_no_ports() {
        let config = ScanConfig::builder()
            .target("127.0.0.1".parse().unwrap())
            .ports(PortSelection::default())
            .discovery(DiscoveryConfig {
                discovery_only: true,
                ..Default::default()
            })
            .build()
            .unwrap();
        assert!(config.discovery.discovery_only);
    }

    #[test]
    fn probe_budget_is_enforced() {
        let config = config_with_target()
            .ports(
                PortSpec::parse("1-65535", Transport::Tcp)
                    .unwrap()
                    .resolve(),
            )
            .build()
            .unwrap();
        assert!(config.check_probe_budget(1).is_ok());
        let err = config.check_probe_budget(1_000).unwrap_err();
        assert!(matches!(err, Error::LimitExceeded { what: "probe", .. }));
    }

    #[test]
    fn timing_templates_are_ordered_by_speed() {
        let mut previous = 0usize;
        for template in TimingTemplate::ALL {
            let timing = template.timing();
            assert!(
                timing.concurrency >= previous,
                "{} is not faster than the previous template",
                template.name()
            );
            previous = timing.concurrency;
        }
        assert!(
            TimingTemplate::Insane.timing().connect_timeout
                < TimingTemplate::Sneaky.timing().connect_timeout
        );
    }

    #[test]
    fn timing_template_parsing() {
        assert_eq!(
            "aggressive".parse::<TimingTemplate>().unwrap(),
            TimingTemplate::Aggressive
        );
        assert!("turbo".parse::<TimingTemplate>().is_err());
        let err = "turbo".parse::<TimingTemplate>().unwrap_err();
        assert!(
            err.to_string().contains("sneaky"),
            "help text missing: {err}"
        );
    }

    #[test]
    fn sneaky_template_is_serial_and_not_adaptive() {
        let timing = TimingTemplate::Sneaky.timing();
        assert_eq!(timing.concurrency, 1);
        assert!(!timing.adaptive);
        assert!(timing.scan_delay > Duration::ZERO);
    }

    #[test]
    fn privilege_requirement_detection() {
        let connect = config_with_target().build().unwrap();
        assert!(!connect.requires_privileges());

        assert!(
            connect.benefits_from_privileges(),
            "ARP discovery would still help"
        );

        let syn = config_with_target()
            .modes(ScanModes {
                tcp_mode: TcpScanMode::Syn,
                ..Default::default()
            })
            .build()
            .unwrap();
        assert!(syn.requires_privileges());
        assert!(syn.benefits_from_privileges());
    }

    #[test]
    fn config_round_trips_through_toml() {
        let config = config_with_target()
            .timing_template(TimingTemplate::Aggressive)
            .detection(DetectionConfig::full())
            .build()
            .unwrap();
        let text = toml::to_string(&config).unwrap();
        let parsed: ScanConfig = toml::from_str(&text).unwrap();
        assert_eq!(config, parsed);
    }

    #[test]
    fn config_round_trips_through_json() {
        let config = config_with_target().build().unwrap();
        let text = serde_json::to_string(&config).unwrap();
        let parsed: ScanConfig = serde_json::from_str(&text).unwrap();
        assert_eq!(config, parsed);
    }

    #[test]
    fn unknown_config_keys_are_rejected() {
        let err =
            toml::from_str::<TimingConfig>("concurrency = 10\nnonsense = true\n").unwrap_err();
        assert!(err.to_string().contains("nonsense"), "error was: {err}");
    }

    #[test]
    fn detection_full_enables_everything() {
        let d = DetectionConfig::full();
        assert!(d.service_detection && d.version_detection && d.tls_inspection && d.os_fingerprint);
        assert!(d.any_enabled());
    }
}
