use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::profiles::{Profile, ProfileRegistry};

use super::settings::Limits;

pub type ProfileDefinition = Profile;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConfigFile {
    pub default_profile: Option<String>,
    pub defaults: Profile,
    pub limits: Option<Limits>,
    pub profiles: BTreeMap<String, ProfileDefinition>,
}

impl ConfigFile {
    pub fn parse(text: &str) -> Result<Self> {
        let mut file: ConfigFile = toml::from_str(text)
            .map_err(|e| Error::Config(format!("invalid configuration: {e}")))?;

        for (name, profile) in file.profiles.iter_mut() {
            profile.name = name.clone();
        }
        file.defaults.name = "defaults".to_string();

        if let Some(default) = &file.default_profile {
            let known = file.profiles.contains_key(default)
                || ProfileRegistry::with_builtins().contains(default);
            if !known {
                return Err(Error::Config(format!(
                    "default_profile = \"{default}\" does not name a built-in or configured profile"
                )));
            }
        }

        Ok(file)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("could not read {}: {e}", path.display())))?;
        Self::parse(&text).map_err(|e| match e {
            Error::Config(msg) => Error::Config(format!("{}: {msg}", path.display())),
            other => other,
        })
    }

    pub fn discover() -> Result<Option<(PathBuf, Self)>> {
        for path in config_search_paths() {
            if path.is_file() {
                let file = Self::load(&path)?;
                return Ok(Some((path, file)));
            }
        }
        Ok(None)
    }

    pub fn registry(&self) -> ProfileRegistry {
        let mut registry = ProfileRegistry::with_builtins();
        for (name, profile) in &self.profiles {
            registry.insert(profile.clone(), name.clone());
        }
        registry
    }
}

pub fn config_search_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(explicit) = std::env::var_os("NETSCAN_CONFIG") {
        paths.push(PathBuf::from(explicit));
    }

    paths.push(PathBuf::from("netscan.toml"));

    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        paths.push(PathBuf::from(xdg).join("netscan").join("netscan.toml"));
    }

    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        paths.push(home.join(".config").join("netscan").join("netscan.toml"));
        if cfg!(target_os = "macos") {
            paths.push(
                home.join("Library")
                    .join("Application Support")
                    .join("netscan")
                    .join("netscan.toml"),
            );
        }
    }

    if let Some(appdata) = std::env::var_os("APPDATA") {
        paths.push(PathBuf::from(appdata).join("netscan").join("netscan.toml"));
    }

    paths
}

pub fn state_dir() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("NETSCAN_STATE_DIR") {
        return Some(PathBuf::from(explicit));
    }
    if let Some(xdg) = std::env::var_os("XDG_STATE_HOME") {
        return Some(PathBuf::from(xdg).join("netscan"));
    }
    let home = PathBuf::from(std::env::var_os("HOME")?);
    if cfg!(target_os = "macos") {
        Some(
            home.join("Library")
                .join("Application Support")
                .join("netscan"),
        )
    } else {
        Some(home.join(".local").join("state").join("netscan"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
default_profile = "dmz"

[defaults]
timing = "polite"
reverse_dns = false

[limits]
max_targets = 4096

[profiles.dmz]
description = "the ports we actually expose"
ports = "T:80,443,U:53"
udp = true
service_detection = true
"#;

    #[test]
    fn parses_a_full_configuration() {
        let file = ConfigFile::parse(SAMPLE).unwrap();
        assert_eq!(file.default_profile.as_deref(), Some("dmz"));
        assert_eq!(file.defaults.reverse_dns, Some(false));
        assert_eq!(file.limits.as_ref().unwrap().max_targets, 4096);
        let dmz = &file.profiles["dmz"];
        assert_eq!(
            dmz.name, "dmz",
            "profile name should come from the table key"
        );
        assert_eq!(dmz.udp, Some(true));
    }

    #[test]
    fn empty_configuration_is_valid() {
        let file = ConfigFile::parse("").unwrap();
        assert!(file.profiles.is_empty());
        assert_eq!(
            file.registry().len(),
            ProfileRegistry::with_builtins().len()
        );
    }

    #[test]
    fn registry_merges_builtins_with_user_profiles() {
        let file = ConfigFile::parse(SAMPLE).unwrap();
        let registry = file.registry();
        assert!(registry.contains("quick"), "built-ins should survive");
        assert!(registry.contains("dmz"), "user profiles should be added");
    }

    #[test]
    fn unknown_keys_are_rejected_with_a_useful_message() {
        let err = ConfigFile::parse("[defaults]\nnot_a_setting = 1\n").unwrap_err();
        assert!(
            err.to_string().contains("not_a_setting"),
            "message was: {err}"
        );
    }

    #[test]
    fn unknown_default_profile_is_rejected() {
        let err = ConfigFile::parse("default_profile = \"ghost\"\n").unwrap_err();
        assert!(err.to_string().contains("ghost"));
    }

    #[test]
    fn default_profile_may_name_a_builtin() {
        let file = ConfigFile::parse("default_profile = \"quick\"\n").unwrap();
        assert_eq!(file.default_profile.as_deref(), Some("quick"));
    }

    #[test]
    fn loading_a_file_reports_the_path_on_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("netscan.toml");
        std::fs::write(&path, "[defaults]\nbogus = true\n").unwrap();
        let err = ConfigFile::load(&path).unwrap_err();
        assert!(
            err.to_string().contains("netscan.toml"),
            "message was: {err}"
        );
    }

    #[test]
    fn round_trips_through_toml() {
        let file = ConfigFile::parse(SAMPLE).unwrap();
        let text = toml::to_string(&file).unwrap();
        let reparsed = ConfigFile::parse(&text).unwrap();
        assert_eq!(file, reparsed);
    }

    #[test]
    fn search_paths_prefer_the_environment_override() {
        let paths = config_search_paths();
        assert!(paths.iter().any(|p| p.ends_with("netscan.toml")));
        assert_eq!(
            paths[if std::env::var_os("NETSCAN_CONFIG").is_some() {
                1
            } else {
                0
            }],
            PathBuf::from("netscan.toml")
        );
    }
}
