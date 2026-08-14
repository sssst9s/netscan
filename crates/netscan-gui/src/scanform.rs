use std::time::Duration;

use netscan_core::config::{DiscoveryConfig, Limits};
use netscan_core::profiles::PortSelector;
use netscan_core::scanner::target::parse_target_list;
use netscan_core::{
    IpFamily, PortPreset, PortSpec, ProfileRegistry, ScanConfig, TcpScanMode, TimingTemplate,
    Transport,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortMode {
    Top,
    Preset,
    Custom,
}

impl PortMode {
    pub const ALL: &'static [PortMode] = &[PortMode::Top, PortMode::Preset, PortMode::Custom];

    pub fn label(self) -> &'static str {
        match self {
            PortMode::Top => "Top ports",
            PortMode::Preset => "Preset",
            PortMode::Custom => "Custom",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanForm {
    pub targets: String,
    pub exclusions: String,
    pub profile: Option<String>,
    pub port_mode: PortMode,
    pub top_ports: usize,
    pub preset: PortPreset,
    pub custom_ports: String,
    pub tcp: bool,
    pub udp: bool,
    pub tcp_mode: TcpScanMode,
    pub discovery: bool,
    pub discovery_only: bool,
    pub icmp: bool,
    pub tcp_ping: bool,
    pub service_detection: bool,
    pub tls_inspection: bool,
    pub os_detection: bool,
    pub max_intrusiveness: u8,
    pub timing: TimingTemplate,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub retries: u8,
    pub adaptive: bool,
    pub max_rate: Option<u32>,
    pub family: IpFamily,
    pub interface: Option<String>,
    pub reverse_dns: bool,
}

impl Default for ScanForm {
    fn default() -> Self {
        let timing = TimingTemplate::Normal.timing();
        Self {
            targets: String::new(),
            exclusions: String::new(),
            profile: None,
            port_mode: PortMode::Top,
            top_ports: 100,
            preset: PortPreset::Common,
            custom_ports: "22,80,443".to_string(),
            tcp: true,
            udp: false,
            tcp_mode: TcpScanMode::Connect,
            discovery: true,
            discovery_only: false,
            icmp: true,
            tcp_ping: true,
            service_detection: false,
            tls_inspection: false,
            os_detection: false,
            max_intrusiveness: 7,
            timing: TimingTemplate::Normal,
            concurrency: timing.concurrency,
            timeout_ms: timing.connect_timeout.as_millis() as u64,
            retries: timing.retries,
            adaptive: timing.adaptive,
            max_rate: None,
            family: IpFamily::V4,
            interface: None,
            reverse_dns: true,
        }
    }
}

impl ScanForm {
    pub fn apply_timing_template(&mut self, template: TimingTemplate) {
        let timing = template.timing();
        self.timing = template;
        self.concurrency = timing.concurrency;
        self.timeout_ms = timing.connect_timeout.as_millis() as u64;
        self.retries = timing.retries;
        self.adaptive = timing.adaptive;
    }

    pub fn apply_profile(&mut self, registry: &ProfileRegistry, name: &str) -> Result<(), String> {
        let profile = registry.get(name).map_err(|e| e.to_string())?;

        let mut config = ScanConfig {
            targets: vec!["127.0.0.1".parse().unwrap()],
            ..Default::default()
        };
        profile.apply(&mut config).map_err(|e| e.to_string())?;

        self.profile = Some(name.to_string());
        self.tcp = config.modes.tcp;
        self.udp = config.modes.udp;
        self.tcp_mode = config.modes.tcp_mode;
        self.discovery = config.discovery.enabled;
        self.discovery_only = config.discovery.discovery_only;
        self.service_detection = config.detection.service_detection;
        self.tls_inspection = config.detection.tls_inspection;
        self.os_detection = config.detection.os_fingerprint;
        self.max_intrusiveness = config.detection.max_intrusiveness;
        self.timing = config.timing.template;
        self.concurrency = config.timing.concurrency;
        self.timeout_ms = config.timing.connect_timeout.as_millis() as u64;
        self.retries = config.timing.retries;
        self.adaptive = config.timing.adaptive;
        self.reverse_dns = config.dns.reverse_lookup;

        if let Some(selector) = &profile.ports {
            match selector {
                PortSelector::Top(n) => {
                    self.port_mode = PortMode::Top;
                    self.top_ports = *n;
                }
                PortSelector::Preset(preset) => {
                    self.port_mode = PortMode::Preset;
                    self.preset = *preset;
                }
                PortSelector::Explicit(text) => {
                    self.port_mode = PortMode::Custom;
                    self.custom_ports.clone_from(text);
                }
            }
        }
        Ok(())
    }

    pub fn target_problem(&self) -> Option<String> {
        if self.targets.trim().is_empty() {
            return Some("Enter a target".to_string());
        }
        parse_target_list(&self.targets)
            .err()
            .map(|e| e.to_string())
    }

    pub fn port_summary(&self) -> String {
        match self.port_mode {
            PortMode::Top => format!("top {}", self.top_ports),
            PortMode::Preset => self.preset.name().to_string(),
            PortMode::Custom => {
                let ports = self.custom_ports.trim();
                if ports.is_empty() {
                    "custom".to_string()
                } else {
                    crate::widgets::ellipsise(ports, 18)
                }
            }
        }
    }

    pub fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();

        if self.targets.trim().is_empty() {
            problems.push("Enter at least one target.".to_string());
        } else if let Err(err) = parse_target_list(&self.targets) {
            problems.push(err.to_string());
        }

        if !self.exclusions.trim().is_empty() {
            if let Err(err) = parse_target_list(&self.exclusions) {
                problems.push(format!("Exclusions: {err}"));
            }
        }

        if !self.tcp && !self.udp && !self.discovery_only {
            problems.push("Enable TCP, UDP, or discovery-only.".to_string());
        }

        if self.port_mode == PortMode::Custom && !self.discovery_only {
            let transport = if self.udp && !self.tcp {
                Transport::Udp
            } else {
                Transport::Tcp
            };
            if let Err(err) = PortSpec::parse(&self.custom_ports, transport) {
                problems.push(err.to_string());
            }
        }

        if self.port_mode == PortMode::Top && self.top_ports == 0 {
            problems.push("Scan at least one port.".to_string());
        }

        if self.concurrency == 0 {
            problems.push("Concurrency must be at least 1.".to_string());
        }
        if self.timeout_ms == 0 {
            problems.push("Timeout must be greater than zero.".to_string());
        }
        if self.discovery && !self.icmp && !self.tcp_ping {
            problems.push(
                "Host discovery needs at least one method, or turn discovery off.".to_string(),
            );
        }

        problems
    }

    pub fn is_valid(&self) -> bool {
        self.problems().is_empty()
    }

    pub fn to_config(&self) -> Result<ScanConfig, String> {
        let targets = parse_target_list(&self.targets).map_err(|e| e.to_string())?;
        if targets.is_empty() {
            return Err("no targets".to_string());
        }
        let exclusions = if self.exclusions.trim().is_empty() {
            Vec::new()
        } else {
            parse_target_list(&self.exclusions).map_err(|e| e.to_string())?
        };

        let default_transport = if self.udp && !self.tcp {
            Transport::Udp
        } else {
            Transport::Tcp
        };
        let selector = match self.port_mode {
            PortMode::Top => PortSelector::Top(self.top_ports),
            PortMode::Preset => PortSelector::Preset(self.preset),
            PortMode::Custom => PortSelector::Explicit(self.custom_ports.clone()),
        };
        let mut ports = selector
            .resolve(default_transport)
            .map_err(|e| e.to_string())?;

        if self.udp && ports.udp.is_empty() {
            ports.merge(&netscan_core::PortSelection::udp(
                netscan_core::detection::service::top_udp_ports(self.top_ports.clamp(1, 200)),
            ));
        }

        let mut config = ScanConfig {
            targets,
            exclusions,
            ports,
            limits: Limits::default(),
            family: self.family,
            interface: self.interface.clone(),
            profile_name: self.profile.clone(),
            ..ScanConfig::default()
        };

        config.modes.tcp = self.tcp;
        config.modes.udp = self.udp;
        config.modes.tcp_mode = self.tcp_mode;

        config.discovery = DiscoveryConfig {
            enabled: self.discovery,
            icmp_echo: self.icmp,
            tcp_ping: self.tcp_ping,
            discovery_only: self.discovery_only,
            ..DiscoveryConfig::default()
        };

        config.detection.service_detection = self.service_detection;
        config.detection.version_detection = self.service_detection;
        config.detection.tls_inspection = self.tls_inspection;
        config.detection.os_fingerprint = self.os_detection;
        config.detection.banner_grab = true;
        config.detection.max_intrusiveness = self.max_intrusiveness;

        config.timing = self.timing.timing();
        config.timing.concurrency = self.concurrency;
        config.timing.connect_timeout = Duration::from_millis(self.timeout_ms);
        config.timing.read_timeout = Duration::from_millis(self.timeout_ms.max(1_000));
        config.timing.retries = self.retries;
        config.timing.adaptive = self.adaptive;
        config.timing.max_rate = self.max_rate;

        config.dns.reverse_lookup = self.reverse_dns;

        config.validate().map_err(|e| e.to_string())?;
        Ok(config)
    }

    pub fn summary(&self) -> String {
        let targets = self.targets.split_whitespace().count();
        let ports = match self.port_mode {
            PortMode::Top => format!("top {}", self.top_ports),
            PortMode::Preset => self.preset.name().to_string(),
            PortMode::Custom => self.custom_ports.clone(),
        };
        let transports = match (self.tcp, self.udp) {
            (true, true) => "TCP+UDP",
            (true, false) => "TCP",
            (false, true) => "UDP",
            (false, false) => "discovery only",
        };
        if self.discovery_only {
            return format!("{targets} target(s), host discovery only");
        }
        format!(
            "{targets} target(s), {ports} ports, {transports}, {} timing",
            self.timing.name()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form() -> ScanForm {
        ScanForm {
            targets: "192.168.1.0/24".to_string(),
            ..ScanForm::default()
        }
    }

    #[test]
    fn a_default_form_needs_targets() {
        let problems = ScanForm::default().problems();
        assert!(!problems.is_empty());
        assert!(problems[0].contains("target"));
        assert!(!ScanForm::default().is_valid());
    }

    #[test]
    fn a_minimal_form_produces_a_valid_configuration() {
        let form = form();
        assert!(form.is_valid(), "problems: {:?}", form.problems());
        let config = form.to_config().unwrap();
        assert_eq!(config.targets.len(), 1);
        assert_eq!(config.ports.tcp.len(), 100);
        assert!(config.modes.tcp);
    }

    #[test]
    fn bad_targets_are_reported_before_scanning() {
        let form = ScanForm {
            targets: "not a target!".to_string(),
            ..ScanForm::default()
        };
        assert!(!form.is_valid());

        assert!(
            form.problems()[0].contains("invalid target"),
            "{:?}",
            form.problems()
        );
        assert!(form.to_config().is_err());
    }

    #[test]
    fn bad_port_specifications_are_reported() {
        let form = ScanForm {
            port_mode: PortMode::Custom,
            custom_ports: "22,abc".to_string(),
            ..form()
        };
        assert!(!form.is_valid());
        assert!(form.problems().iter().any(|p| p.contains("abc")));
    }

    #[test]
    fn every_port_mode_produces_ports() {
        for mode in PortMode::ALL {
            let form = ScanForm {
                port_mode: *mode,
                ..form()
            };
            let config = form
                .to_config()
                .unwrap_or_else(|e| panic!("{mode:?} failed: {e}"));
            assert!(!config.ports.is_empty(), "{mode:?} produced no ports");
            assert!(!mode.label().is_empty());
        }
    }

    #[test]
    fn a_udp_scan_always_gets_udp_ports() {
        let form = ScanForm {
            tcp: false,
            udp: true,
            ..form()
        };
        let config = form.to_config().unwrap();
        assert!(
            !config.ports.udp.is_empty(),
            "a UDP scan with no UDP ports would scan nothing"
        );
        assert!(config.modes.udp);
        assert!(!config.modes.tcp);
    }

    #[test]
    fn custom_ports_follow_the_selected_transport() {
        let form = ScanForm {
            tcp: false,
            udp: true,
            port_mode: PortMode::Custom,
            custom_ports: "53,161".to_string(),
            ..form()
        };
        let config = form.to_config().unwrap();
        assert_eq!(config.ports.udp.as_slice(), &[53, 161]);
    }

    #[test]
    fn a_transportless_scan_is_rejected_unless_it_is_discovery_only() {
        let transportless = ScanForm {
            tcp: false,
            udp: false,
            ..form()
        };
        assert!(!transportless.is_valid());

        let discovery = ScanForm {
            tcp: false,
            udp: false,
            discovery_only: true,
            ..form()
        };
        assert!(discovery.is_valid(), "problems: {:?}", discovery.problems());
    }

    #[test]
    fn discovery_with_no_methods_is_rejected() {
        let form = ScanForm {
            discovery: true,
            icmp: false,
            tcp_ping: false,
            ..form()
        };
        assert!(!form.is_valid());
        assert!(form.problems().iter().any(|p| p.contains("discovery")));
    }

    #[test]
    fn timing_templates_move_the_controls() {
        let mut form = form();
        form.apply_timing_template(TimingTemplate::Sneaky);
        assert_eq!(form.concurrency, 1);
        assert!(!form.adaptive);

        form.apply_timing_template(TimingTemplate::Aggressive);
        assert!(form.concurrency > 1);
        assert!(form.adaptive);
        assert_eq!(
            form.to_config().unwrap().timing.concurrency,
            form.concurrency
        );
    }

    #[test]
    fn detection_toggles_reach_the_configuration() {
        let form = ScanForm {
            service_detection: true,
            tls_inspection: true,
            os_detection: true,
            ..form()
        };
        let config = form.to_config().unwrap();
        assert!(config.detection.service_detection);
        assert!(config.detection.version_detection);
        assert!(config.detection.tls_inspection);
        assert!(config.detection.os_fingerprint);
    }

    #[test]
    fn every_builtin_profile_loads_into_the_form_and_scans() {
        let registry = ProfileRegistry::with_builtins();
        for name in registry.names() {
            let mut form = form();
            form.apply_profile(&registry, name)
                .unwrap_or_else(|e| panic!("profile `{name}` failed to load: {e}"));
            assert_eq!(form.profile.as_deref(), Some(name));
            let config = form
                .to_config()
                .unwrap_or_else(|e| panic!("profile `{name}` produced an invalid scan: {e}"));
            assert_eq!(config.profile_name.as_deref(), Some(name));
        }
    }

    #[test]
    fn loading_a_profile_shows_its_port_choice() {
        let registry = ProfileRegistry::with_builtins();
        let mut form = form();

        form.apply_profile(&registry, "full").unwrap();
        assert_eq!(form.port_mode, PortMode::Top);
        assert_eq!(form.top_ports, 1000);

        form.apply_profile(&registry, "web").unwrap();
        assert_eq!(form.port_mode, PortMode::Preset);
        assert_eq!(form.preset, PortPreset::Web);

        form.apply_profile(&registry, "thorough").unwrap();
        assert_eq!(form.port_mode, PortMode::Custom);
        assert_eq!(form.custom_ports, "1-65535");
    }

    #[test]
    fn an_unknown_profile_is_reported() {
        let registry = ProfileRegistry::with_builtins();
        let err = form().apply_profile(&registry, "nope").unwrap_err();
        assert!(
            err.contains("quick"),
            "the error should list what exists: {err}"
        );
    }

    #[test]
    fn exclusions_are_parsed_and_validated() {
        let excluding = ScanForm {
            exclusions: "192.168.1.1 192.168.1.0/28".to_string(),
            ..form()
        };
        assert!(excluding.is_valid());
        assert_eq!(excluding.to_config().unwrap().exclusions.len(), 2);

        let bad = ScanForm {
            exclusions: "!!!".to_string(),
            ..form()
        };
        assert!(bad.problems().iter().any(|p| p.starts_with("Exclusions:")));
    }

    #[test]
    fn the_summary_describes_the_scan() {
        let summary = form().summary();
        assert!(summary.contains("1 target(s)"));
        assert!(summary.contains("top 100"));
        assert!(summary.contains("TCP"));

        let discovery = ScanForm {
            discovery_only: true,
            ..form()
        };
        assert!(discovery.summary().contains("discovery only"));
    }
}
