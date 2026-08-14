pub mod file;
pub mod settings;

pub use file::{config_search_paths, ConfigFile, ProfileDefinition};
pub use settings::{
    DetectionConfig, DiscoveryConfig, DnsConfig, Limits, ScanConfig, ScanConfigBuilder, ScanModes,
    TcpScanMode, TimingConfig, TimingTemplate,
};

pub(crate) mod duration_ms {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &Duration, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_u64(value.as_millis().min(u128::from(u64::MAX)) as u64)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Duration, D::Error> {
        let millis = u64::deserialize(de)?;
        Ok(Duration::from_millis(millis))
    }
}

pub(crate) mod opt_duration_ms {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &Option<Duration>, ser: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(d) => ser.serialize_some(&(d.as_millis().min(u128::from(u64::MAX)) as u64)),
            None => ser.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Option<Duration>, D::Error> {
        let millis = Option::<u64>::deserialize(de)?;
        Ok(millis.map(Duration::from_millis))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
    #[serde(default)]
    struct Holder {
        #[serde(with = "super::duration_ms")]
        plain: Duration,
        #[serde(with = "super::opt_duration_ms")]
        maybe: Option<Duration>,
    }

    #[test]
    fn durations_round_trip_as_milliseconds() {
        let holder = Holder {
            plain: Duration::from_millis(1500),
            maybe: Some(Duration::from_secs(2)),
        };
        let text = toml::to_string(&holder).unwrap();
        assert!(text.contains("plain = 1500"), "{text}");
        assert!(text.contains("maybe = 2000"), "{text}");
        assert_eq!(toml::from_str::<Holder>(&text).unwrap(), holder);
    }

    #[test]
    fn optional_duration_may_be_absent() {
        let parsed: Holder = toml::from_str("plain = 10\n").unwrap();
        assert_eq!(parsed.maybe, None);
    }
}
