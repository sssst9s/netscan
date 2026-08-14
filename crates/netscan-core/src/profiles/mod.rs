pub mod presets;

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::config::settings::{ScanConfig, TcpScanMode, TimingTemplate};
use crate::detection::service;
use crate::error::{Error, Result};
use crate::scanner::port::{PortPreset, PortSelection, PortSpec, Transport};

pub use presets::{builtin_profiles, ProfileRegistry};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortSelector {
    Top(usize),
    Preset(PortPreset),
    Explicit(String),
}

impl PortSelector {
    pub fn resolve(&self, default_transport: Transport) -> Result<PortSelection> {
        match self {
            PortSelector::Top(n) => {
                let available = service::max_top_ports(default_transport);
                if *n == 0 {
                    return Err(Error::invalid_ports(
                        "top:0",
                        "must request at least one port",
                    ));
                }
                if *n > available {
                    return Err(Error::invalid_ports(
                        format!("top:{n}"),
                        format!(
                            "netscan's ranked {default_transport} dataset has {available} ports; \
                             request at most that many or use an explicit port list"
                        ),
                    ));
                }
                let set = match default_transport {
                    Transport::Tcp => service::top_tcp_ports(*n),
                    Transport::Udp => service::top_udp_ports(*n),
                };
                Ok(match default_transport {
                    Transport::Tcp => PortSelection::tcp(set),
                    Transport::Udp => PortSelection::udp(set),
                })
            }
            PortSelector::Preset(preset) => Ok(preset.selection()),
            PortSelector::Explicit(text) => Ok(PortSpec::parse(text, default_transport)?.resolve()),
        }
    }
}

impl FromStr for PortSelector {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let text = s.trim();
        if let Some(rest) = text
            .strip_prefix("top:")
            .or_else(|| text.strip_prefix("top-"))
        {
            let n = rest.trim().parse::<usize>().map_err(|_| {
                Error::invalid_ports(s, "`top:` must be followed by a number, e.g. top:1000")
            })?;
            return Ok(PortSelector::Top(n));
        }
        if let Some(rest) = text.strip_prefix("preset:") {
            return Ok(PortSelector::Preset(rest.trim().parse()?));
        }

        if let Ok(preset) = text.parse::<PortPreset>() {
            return Ok(PortSelector::Preset(preset));
        }

        PortSpec::parse(text, Transport::Tcp)?;
        Ok(PortSelector::Explicit(text.to_string()))
    }
}

impl fmt::Display for PortSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortSelector::Top(n) => write!(f, "top:{n}"),
            PortSelector::Preset(p) => write!(f, "preset:{p}"),
            PortSelector::Explicit(text) => f.write_str(text),
        }
    }
}

impl Serialize for PortSelector {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PortSelector {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(de)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Profile {
    #[serde(skip)]
    pub name: String,
    pub description: String,
    pub ports: Option<PortSelector>,
    pub udp_ports: Option<PortSelector>,
    pub timing: Option<TimingTemplate>,
    pub tcp: Option<bool>,
    pub tcp_mode: Option<TcpScanMode>,
    pub udp: Option<bool>,
    pub discovery: Option<bool>,
    pub discovery_only: Option<bool>,
    pub service_detection: Option<bool>,
    pub os_detection: Option<bool>,
    pub tls_inspection: Option<bool>,
    pub max_intrusiveness: Option<u8>,
    pub concurrency: Option<usize>,
    pub connect_timeout_ms: Option<u64>,
    pub retries: Option<u8>,
    pub max_rate: Option<u32>,
    pub scan_delay_ms: Option<u64>,
    pub reverse_dns: Option<bool>,
    pub adaptive: Option<bool>,
}

impl Profile {
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            ..Self::default()
        }
    }

    pub fn apply(&self, config: &mut ScanConfig) -> Result<()> {
        if let Some(template) = self.timing {
            config.timing = template.timing();
        }
        if let Some(tcp) = self.tcp {
            config.modes.tcp = tcp;
        }
        if let Some(mode) = self.tcp_mode {
            config.modes.tcp_mode = mode;
        }
        if let Some(udp) = self.udp {
            config.modes.udp = udp;
        }
        if let Some(selector) = &self.ports {
            let selection = selector.resolve(Transport::Tcp)?;

            config.ports = selection;
        }
        if let Some(selector) = &self.udp_ports {
            let udp = selector.resolve(Transport::Udp)?;
            config.ports.merge(&udp);
        }
        if let Some(enabled) = self.discovery {
            config.discovery.enabled = enabled;
        }
        if let Some(only) = self.discovery_only {
            config.discovery.discovery_only = only;
        }
        if let Some(enabled) = self.service_detection {
            config.detection.service_detection = enabled;
            config.detection.version_detection = enabled;
            config.detection.banner_grab = config.detection.banner_grab || enabled;
        }
        if let Some(enabled) = self.os_detection {
            config.detection.os_fingerprint = enabled;
        }
        if let Some(enabled) = self.tls_inspection {
            config.detection.tls_inspection = enabled;
        }
        if let Some(level) = self.max_intrusiveness {
            config.detection.max_intrusiveness = level;
        }
        if let Some(concurrency) = self.concurrency {
            config.timing.concurrency = concurrency;
        }
        if let Some(ms) = self.connect_timeout_ms {
            config.timing.connect_timeout = std::time::Duration::from_millis(ms);
            config.timing.read_timeout = std::time::Duration::from_millis(ms.max(1_000));
        }
        if let Some(retries) = self.retries {
            config.timing.retries = retries;
        }
        if let Some(rate) = self.max_rate {
            config.timing.max_rate = Some(rate);
        }
        if let Some(ms) = self.scan_delay_ms {
            config.timing.scan_delay = std::time::Duration::from_millis(ms);
        }
        if let Some(enabled) = self.reverse_dns {
            config.dns.reverse_lookup = enabled;
        }
        if let Some(adaptive) = self.adaptive {
            config.timing.adaptive = adaptive;
        }

        config.profile_name = Some(self.name.clone());
        Ok(())
    }

    pub fn to_config(
        &self,
        targets: Vec<crate::scanner::target::TargetSpec>,
    ) -> Result<ScanConfig> {
        let mut config = ScanConfig {
            targets,
            ..ScanConfig::default()
        };
        self.apply(&mut config)?;
        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_parses_top_form() {
        assert_eq!(
            "top:1000".parse::<PortSelector>().unwrap(),
            PortSelector::Top(1000)
        );
        assert_eq!(
            "top-100".parse::<PortSelector>().unwrap(),
            PortSelector::Top(100)
        );
        assert!("top:abc".parse::<PortSelector>().is_err());
    }

    #[test]
    fn selector_parses_presets_prefixed_and_bare() {
        assert_eq!(
            "preset:web".parse::<PortSelector>().unwrap(),
            PortSelector::Preset(PortPreset::Web)
        );
        assert_eq!(
            "database".parse::<PortSelector>().unwrap(),
            PortSelector::Preset(PortPreset::Database)
        );
    }

    #[test]
    fn selector_parses_explicit_specs() {
        let selector: PortSelector = "22,80,443".parse().unwrap();
        let resolved = selector.resolve(Transport::Tcp).unwrap();
        assert_eq!(resolved.tcp.as_slice(), &[22, 80, 443]);
    }

    #[test]
    fn selector_top_is_bounded_by_the_dataset() {
        let err = PortSelector::Top(999_999)
            .resolve(Transport::Tcp)
            .unwrap_err();
        assert!(err.to_string().contains("ranked"), "message was: {err}");
        assert!(PortSelector::Top(0).resolve(Transport::Tcp).is_err());
    }

    #[test]
    fn selector_round_trips_through_toml() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Holder {
            ports: PortSelector,
        }
        for text in ["top:1000", "preset:web", "22,80,443"] {
            let holder = Holder {
                ports: text.parse().unwrap(),
            };
            let toml_text = toml::to_string(&holder).unwrap();
            assert_eq!(toml::from_str::<Holder>(&toml_text).unwrap(), holder);
        }
    }

    #[test]
    fn profile_applies_only_declared_fields() {
        let mut config = ScanConfig::default();
        config.timing.concurrency = 77;

        let profile = Profile {
            retries: Some(4),
            ..Profile::new("p", "test")
        };
        profile.apply(&mut config).unwrap();

        assert_eq!(config.timing.retries, 4);
        assert_eq!(
            config.timing.concurrency, 77,
            "untouched field was overwritten"
        );
        assert_eq!(config.profile_name.as_deref(), Some("p"));
    }

    #[test]
    fn explicit_overrides_win_over_the_template_they_accompany() {
        let mut config = ScanConfig::default();
        let profile = Profile {
            timing: Some(TimingTemplate::Insane),
            concurrency: Some(10),
            ..Profile::new("p", "test")
        };
        profile.apply(&mut config).unwrap();
        assert_eq!(config.timing.concurrency, 10);
        assert_eq!(config.timing.template, TimingTemplate::Insane);
    }

    #[test]
    fn udp_ports_merge_with_tcp_ports() {
        let mut config = ScanConfig::default();
        let profile = Profile {
            ports: Some("22,80".parse().unwrap()),
            udp_ports: Some("53,161".parse().unwrap()),
            udp: Some(true),
            ..Profile::new("p", "test")
        };
        profile.apply(&mut config).unwrap();
        assert_eq!(config.ports.tcp.as_slice(), &[22, 80]);
        assert_eq!(config.ports.udp.as_slice(), &[53, 161]);
    }

    #[test]
    fn profile_builds_a_valid_config() {
        let profile = Profile {
            ports: Some("top:50".parse().unwrap()),
            timing: Some(TimingTemplate::Polite),
            ..Profile::new("p", "test")
        };
        let config = profile
            .to_config(vec!["127.0.0.1".parse().unwrap()])
            .unwrap();
        assert_eq!(config.ports.tcp.len(), 50);
        assert_eq!(config.timing.template, TimingTemplate::Polite);
    }
}
