pub mod csv;
pub mod json;
pub mod jsonl;
pub mod table;
pub mod text;
pub mod xml;

use std::fmt;
use std::str::FromStr;

use crate::error::{Error, Result};
use crate::scanner::result::ScanReport;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    #[default]
    Text,
    Json,
    Jsonl,
    Csv,
    Xml,
}

impl Format {
    pub const ALL: &'static [Format] = &[
        Format::Text,
        Format::Json,
        Format::Jsonl,
        Format::Csv,
        Format::Xml,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Format::Text => "text",
            Format::Json => "json",
            Format::Jsonl => "jsonl",
            Format::Csv => "csv",
            Format::Xml => "xml",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Format::Text => "txt",
            Format::Json => "json",
            Format::Jsonl => "jsonl",
            Format::Csv => "csv",
            Format::Xml => "xml",
        }
    }

    pub fn from_path(path: &std::path::Path) -> Option<Self> {
        let extension = path.extension()?.to_str()?.to_ascii_lowercase();
        Format::ALL
            .iter()
            .copied()
            .find(|f| f.extension() == extension)
    }

    pub fn is_machine_readable(self) -> bool {
        !matches!(self, Format::Text)
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Format {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let normalised = s.trim().to_ascii_lowercase();
        Format::ALL
            .iter()
            .copied()
            .find(|f| f.name() == normalised)
            .ok_or_else(|| {
                let names: Vec<_> = Format::ALL.iter().map(|f| f.name()).collect();
                Error::Config(format!(
                    "unknown output format `{s}`, expected one of: {}",
                    names.join(", ")
                ))
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RenderOptions {
    pub colour: bool,
    pub show_all_ports: bool,
    pub show_down_hosts: bool,
    pub show_banners: bool,
    pub show_reasons: bool,
    pub table_style: table::TableStyle,
    pub width: Option<usize>,
}

impl RenderOptions {
    pub fn concise() -> Self {
        Self::default()
    }

    pub fn verbose() -> Self {
        Self {
            show_all_ports: true,
            show_down_hosts: true,
            show_banners: true,
            show_reasons: true,
            ..Self::default()
        }
    }

    pub fn with_colour(mut self, colour: bool) -> Self {
        self.colour = colour;
        self
    }

    pub fn with_table_style(mut self, style: table::TableStyle) -> Self {
        self.table_style = style;
        self
    }

    pub fn with_width(mut self, width: Option<usize>) -> Self {
        self.width = width;
        self
    }
}

pub fn render(report: &ScanReport, format: Format, options: RenderOptions) -> Result<String> {
    match format {
        Format::Text => Ok(text::render(report, options)),
        Format::Json => json::render(report),
        Format::Jsonl => jsonl::render(report),
        Format::Csv => csv::render(report),
        Format::Xml => Ok(xml::render(report)),
    }
}

pub fn write_file(
    report: &ScanReport,
    path: &std::path::Path,
    format: Format,
    options: RenderOptions,
) -> Result<()> {
    let rendered = render(report, format, options)?;
    std::fs::write(path, rendered)
        .map_err(|e| Error::Config(format!("could not write {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::port::Transport;
    use crate::scanner::result::{
        Confidence, DetectionSource, HostReport, HostStatus, PortReason, PortReport, PortState,
        ServiceInfo,
    };

    pub(crate) fn sample_report() -> ScanReport {
        let mut report = ScanReport::empty();
        report.parameters.targets = vec!["192.168.1.0/30".to_string()];
        report.parameters.ports = "22,80,443".to_string();

        let mut host = HostReport::new("192.168.1.10".parse().unwrap());
        host.status = HostStatus::Up;
        host.status_reason = Some("icmp echo reply".to_string());
        host.rtt_ms = Some(1.25);
        host.mac = Some("00:1b:63:11:22:33".parse().unwrap());
        host.vendor = Some("Apple".to_string());
        host.add_hostname(
            "router.local",
            crate::scanner::result::HostnameSource::ReverseDns,
        );

        let mut ssh = PortReport::new(
            22,
            Transport::Tcp,
            PortState::Open,
            PortReason::ConnectionEstablished,
        );
        ssh.rtt_ms = Some(0.9);
        ssh.service = Some(ServiceInfo {
            name: "ssh".into(),
            product: Some("OpenSSH".into()),
            version: Some("9.6p1".into()),
            extra: Some("protocol 2.0".into()),
            tls: false,
            source: DetectionSource::Probe("ssh".into()),
            confidence: Confidence::High,
        });
        ssh.banner = Some("SSH-2.0-OpenSSH_9.6p1".to_string());
        host.ports.push(ssh);

        let mut https = PortReport::new(
            443,
            Transport::Tcp,
            PortState::Open,
            PortReason::ConnectionEstablished,
        );
        https.service = Some(ServiceInfo {
            name: "https".into(),
            product: Some("nginx".into()),
            version: Some("1.24.0".into()),
            tls: true,
            source: DetectionSource::Tls,
            confidence: Confidence::High,
            ..Default::default()
        });
        host.ports.push(https);

        host.other_ports.record(PortState::Closed);
        host.other_ports.record(PortState::Closed);
        report.hosts.push(host);

        let mut down = HostReport::new("192.168.1.11".parse().unwrap());
        down.status = HostStatus::Down;
        report.hosts.push(down);

        report.recompute_stats();
        report
    }

    #[test]
    fn format_names_round_trip() {
        for format in Format::ALL {
            assert_eq!(format.name().parse::<Format>().unwrap(), *format);
            assert_eq!(format.to_string(), format.name());
        }
    }

    #[test]
    fn unknown_formats_list_the_valid_ones() {
        let err = "yaml".parse::<Format>().unwrap_err();
        assert!(err.to_string().contains("json"), "message was: {err}");
    }

    #[test]
    fn formats_are_inferred_from_file_extensions() {
        assert_eq!(
            Format::from_path(std::path::Path::new("out.json")),
            Some(Format::Json)
        );
        assert_eq!(
            Format::from_path(std::path::Path::new("out.CSV")),
            Some(Format::Csv)
        );
        assert_eq!(
            Format::from_path(std::path::Path::new("out.jsonl")),
            Some(Format::Jsonl)
        );
        assert_eq!(Format::from_path(std::path::Path::new("out.dat")), None);
        assert_eq!(Format::from_path(std::path::Path::new("noextension")), None);
    }

    #[test]
    fn every_format_renders_without_error() {
        let report = sample_report();
        for format in Format::ALL {
            let rendered = render(&report, *format, RenderOptions::default())
                .unwrap_or_else(|e| panic!("{format} failed: {e}"));
            assert!(!rendered.is_empty(), "{format} produced nothing");
            assert!(
                rendered.contains("192.168.1.10"),
                "{format} lost the host address"
            );
        }
    }

    #[test]
    fn every_format_handles_an_empty_report() {
        let report = ScanReport::empty();
        for format in Format::ALL {
            let rendered = render(&report, *format, RenderOptions::default())
                .unwrap_or_else(|e| panic!("{format} failed on an empty report: {e}"));

            assert!(!rendered.is_empty() || *format == Format::Jsonl);
        }
    }

    #[test]
    fn writing_to_a_file_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scan.json");
        let report = sample_report();
        write_file(&report, &path, Format::Json, RenderOptions::default()).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let parsed: ScanReport = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed.hosts.len(), report.hosts.len());
    }
}
