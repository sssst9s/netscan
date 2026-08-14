#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod compare;
pub mod config;
pub mod detection;
pub mod discovery;
pub mod error;
pub mod interfaces;
pub mod inventory;
pub mod output;
pub mod profiles;
pub mod protocols;
pub mod scanner;

pub use config::settings::{
    DetectionConfig, DiscoveryConfig, DnsConfig, Limits, ScanConfig, ScanConfigBuilder, ScanModes,
    TcpScanMode, TimingConfig, TimingTemplate,
};
pub use error::{Error, ProbeError, Result, Warning};
pub use profiles::{Profile, ProfileRegistry};
pub use scanner::engine::{Engine, ScanHandle};
pub use scanner::event::{Progress, ScanEvent};
pub use scanner::port::{PortPreset, PortSelection, PortSet, PortSpec, Transport};
pub use scanner::result::{
    Confidence, DetectionSource, HostReport, HostStatus, MacAddress, OsGuess, PortReason,
    PortReport, PortState, ScanOutcome, ScanReport, ScanStats, ServiceInfo, TlsInfo,
    SCHEMA_VERSION,
};
pub use scanner::target::{IpFamily, TargetSpec};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
