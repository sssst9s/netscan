use std::collections::BTreeMap;

use crate::config::settings::{TcpScanMode, TimingTemplate};
use crate::error::{Error, Result};

use super::Profile;

pub fn builtin_profiles() -> Vec<Profile> {
    vec![
        Profile {
            ports: Some("top:100".parse().expect("valid built-in selector")),
            timing: Some(TimingTemplate::Aggressive),
            tcp: Some(true),
            udp: Some(false),
            discovery: Some(true),
            service_detection: Some(false),
            os_detection: Some(false),
            ..Profile::new(
                "quick",
                "top 100 TCP ports, fast timing, no service detection",
            )
        },
        Profile {
            ports: Some("top:1000".parse().expect("valid built-in selector")),
            timing: Some(TimingTemplate::Normal),
            tcp: Some(true),
            udp: Some(false),
            discovery: Some(true),
            service_detection: Some(true),
            os_detection: Some(true),
            tls_inspection: Some(true),
            ..Profile::new(
                "full",
                "top 1000 TCP ports with service, version and OS detection",
            )
        },
        Profile {
            ports: Some("preset:web".parse().expect("valid built-in selector")),
            timing: Some(TimingTemplate::Normal),
            tcp: Some(true),
            udp: Some(false),
            discovery: Some(true),
            service_detection: Some(true),
            tls_inspection: Some(true),
            os_detection: Some(false),
            ..Profile::new(
                "web",
                "HTTP/HTTPS ports with service, version and TLS inspection",
            )
        },
        Profile {
            ports: Some("top:100".parse().expect("valid built-in selector")),
            timing: Some(TimingTemplate::Sneaky),
            tcp: Some(true),
            tcp_mode: Some(TcpScanMode::Auto),
            udp: Some(false),
            discovery: Some(false),
            service_detection: Some(false),
            os_detection: Some(false),
            max_intrusiveness: Some(0),
            reverse_dns: Some(false),
            ..Profile::new(
                "stealth",
                "SYN scan where available, no discovery, no probes, slow serial timing",
            )
        },
        Profile {
            timing: Some(TimingTemplate::Aggressive),
            discovery: Some(true),
            discovery_only: Some(true),
            tcp: Some(true),
            udp: Some(false),
            service_detection: Some(false),
            os_detection: Some(false),
            ..Profile::new(
                "discovery",
                "find which hosts are up, without scanning ports",
            )
        },
        Profile {
            ports: Some("preset:database".parse().expect("valid built-in selector")),
            timing: Some(TimingTemplate::Normal),
            tcp: Some(true),
            udp: Some(true),
            discovery: Some(true),
            service_detection: Some(true),
            os_detection: Some(false),
            ..Profile::new(
                "database",
                "common database ports with service and version detection",
            )
        },
        Profile {
            ports: Some("1-65535".parse().expect("valid built-in selector")),
            udp_ports: Some("top:100".parse().expect("valid built-in selector")),
            timing: Some(TimingTemplate::Normal),
            tcp: Some(true),
            udp: Some(true),
            discovery: Some(true),
            service_detection: Some(true),
            os_detection: Some(true),
            tls_inspection: Some(true),
            ..Profile::new(
                "thorough",
                "all TCP ports, top 100 UDP ports, all detection enabled",
            )
        },
    ]
}

#[derive(Debug, Clone)]
pub struct ProfileRegistry {
    profiles: BTreeMap<String, Profile>,
}

impl Default for ProfileRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}

impl ProfileRegistry {
    pub fn with_builtins() -> Self {
        let mut profiles = BTreeMap::new();
        for profile in builtin_profiles() {
            profiles.insert(profile.name.clone(), profile);
        }
        Self { profiles }
    }

    pub fn empty() -> Self {
        Self {
            profiles: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, mut profile: Profile, name: impl Into<String>) {
        let name = name.into();
        profile.name = name.clone();
        self.profiles.insert(name, profile);
    }

    pub fn get(&self, name: &str) -> Result<&Profile> {
        self.profiles.get(name).ok_or_else(|| {
            let available: Vec<_> = self.profiles.keys().map(String::as_str).collect();
            Error::Config(format!(
                "unknown profile `{name}`; available profiles: {}",
                available.join(", ")
            ))
        })
    }

    pub fn contains(&self, name: &str) -> bool {
        self.profiles.contains_key(name)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Profile> {
        self.profiles.values()
    }

    pub fn names(&self) -> Vec<&str> {
        self.profiles.keys().map(String::as_str).collect()
    }

    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::target::TargetSpec;

    fn target() -> Vec<TargetSpec> {
        vec!["127.0.0.1".parse().unwrap()]
    }

    #[test]
    fn every_builtin_profile_produces_a_valid_config() {
        for profile in builtin_profiles() {
            let config = profile
                .to_config(target())
                .unwrap_or_else(|e| panic!("profile `{}` is invalid: {e}", profile.name));
            assert!(
                !profile.description.is_empty(),
                "{} has no description",
                profile.name
            );
            assert_eq!(config.profile_name.as_deref(), Some(profile.name.as_str()));
        }
    }

    #[test]
    fn builtin_names_are_unique() {
        let profiles = builtin_profiles();
        let registry = ProfileRegistry::with_builtins();
        assert_eq!(
            registry.len(),
            profiles.len(),
            "duplicate built-in profile name"
        );
    }

    #[test]
    fn expected_profiles_exist() {
        let registry = ProfileRegistry::with_builtins();
        for name in [
            "quick",
            "full",
            "web",
            "stealth",
            "discovery",
            "database",
            "thorough",
        ] {
            assert!(registry.contains(name), "missing built-in profile `{name}`");
        }
    }

    #[test]
    fn quick_is_faster_than_thorough() {
        let registry = ProfileRegistry::with_builtins();
        let quick = registry.get("quick").unwrap().to_config(target()).unwrap();
        let thorough = registry
            .get("thorough")
            .unwrap()
            .to_config(target())
            .unwrap();
        assert!(quick.enabled_ports_per_host() < thorough.enabled_ports_per_host());
        assert!(!quick.detection.service_detection);
        assert!(thorough.detection.service_detection);
    }

    #[test]
    fn discovery_profile_skips_port_scanning() {
        let registry = ProfileRegistry::with_builtins();
        let config = registry
            .get("discovery")
            .unwrap()
            .to_config(target())
            .unwrap();
        assert!(config.discovery.discovery_only);
    }

    #[test]
    fn stealth_profile_is_quiet() {
        let registry = ProfileRegistry::with_builtins();
        let config = registry
            .get("stealth")
            .unwrap()
            .to_config(target())
            .unwrap();
        assert!(!config.discovery.enabled);
        assert!(!config.detection.service_detection);
        assert!(!config.dns.reverse_lookup);
        assert_eq!(config.timing.concurrency, 1);
    }

    #[test]
    fn unknown_profile_lists_the_available_ones() {
        let registry = ProfileRegistry::with_builtins();
        let err = registry.get("nope").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("quick") && msg.contains("thorough"),
            "message was: {msg}"
        );
    }

    #[test]
    fn user_profiles_override_builtins() {
        let mut registry = ProfileRegistry::with_builtins();
        let before = registry.len();
        registry.insert(
            Profile {
                retries: Some(9),
                ..Profile::new("quick", "mine")
            },
            "quick",
        );
        assert_eq!(registry.len(), before);
        assert_eq!(registry.get("quick").unwrap().retries, Some(9));
    }
}
