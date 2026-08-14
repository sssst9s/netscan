use std::collections::BTreeMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::scanner::port::Transport;
use crate::scanner::result::{HostStatus, MacAddress, ScanReport};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InventoryService {
    pub port: u16,
    pub transport: Transport,
    pub service: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub tls: bool,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl InventoryService {
    pub fn label(&self) -> String {
        format!("{}/{}", self.port, self.transport)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InventoryHost {
    pub address: IpAddr,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<MacAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_type: Option<String>,
    pub services: Vec<InventoryService>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub times_seen: u32,
}

impl InventoryHost {
    pub fn display_name(&self) -> String {
        self.hostnames
            .first()
            .cloned()
            .unwrap_or_else(|| self.address.to_string())
    }

    pub fn service_count(&self) -> usize {
        self.services.len()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Inventory {
    pub schema_version: u32,
    pub generated_at: DateTime<Utc>,
    pub scans: Vec<String>,
    pub hosts: Vec<InventoryHost>,
}

impl Inventory {
    pub fn new() -> Self {
        Self {
            schema_version: crate::scanner::result::SCHEMA_VERSION,
            generated_at: Utc::now(),
            scans: Vec::new(),
            hosts: Vec::new(),
        }
    }

    pub fn from_report(report: &ScanReport) -> Self {
        let mut inventory = Self::new();
        inventory.merge(report);
        inventory
    }

    pub fn merge(&mut self, report: &ScanReport) {
        if !self.scans.contains(&report.scan_id) {
            self.scans.push(report.scan_id.clone());
        }
        self.generated_at = Utc::now();
        let observed_at = report.started_at;

        let mut index: BTreeMap<IpAddr, usize> = self
            .hosts
            .iter()
            .enumerate()
            .map(|(i, h)| (h.address, i))
            .collect();

        for host in report.hosts.iter().filter(|h| h.status == HostStatus::Up) {
            let position = match index.get(&host.address) {
                Some(position) => *position,
                None => {
                    self.hosts.push(InventoryHost {
                        address: host.address,
                        hostnames: Vec::new(),
                        mac: None,
                        vendor: None,
                        os: None,
                        device_type: None,
                        services: Vec::new(),
                        first_seen: observed_at,
                        last_seen: observed_at,
                        times_seen: 0,
                    });
                    index.insert(host.address, self.hosts.len() - 1);
                    self.hosts.len() - 1
                }
            };

            let entry = &mut self.hosts[position];
            entry.last_seen = entry.last_seen.max(observed_at);
            entry.first_seen = entry.first_seen.min(observed_at);
            entry.times_seen += 1;

            for hostname in &host.hostnames {
                if !entry.hostnames.contains(&hostname.name) {
                    entry.hostnames.push(hostname.name.clone());
                }
            }
            if host.mac.is_some() {
                entry.mac = host.mac;
            }
            if host.vendor.is_some() {
                entry.vendor.clone_from(&host.vendor);
            }
            if let Some(os) = &host.os {
                if !os.is_empty() {
                    entry.os = os.name.clone().or_else(|| os.family.clone());
                    if os.device_type.is_some() {
                        entry.device_type.clone_from(&os.device_type);
                    }
                }
            }

            for port in host.open_ports() {
                let service = port.service.as_ref();
                let name = service
                    .map(|s| s.name.clone())
                    .unwrap_or_else(|| port.service_name().to_string());

                match entry
                    .services
                    .iter_mut()
                    .find(|s| s.port == port.port && s.transport == port.transport)
                {
                    Some(existing) => {
                        existing.last_seen = existing.last_seen.max(observed_at);
                        existing.first_seen = existing.first_seen.min(observed_at);
                        existing.service = name;
                        if service.and_then(|s| s.product.as_ref()).is_some() {
                            existing.product = service.and_then(|s| s.product.clone());
                        }
                        if service.and_then(|s| s.version.as_ref()).is_some() {
                            existing.version = service.and_then(|s| s.version.clone());
                        }
                        existing.tls = service.map(|s| s.tls).unwrap_or(existing.tls);
                    }
                    None => entry.services.push(InventoryService {
                        port: port.port,
                        transport: port.transport,
                        service: name,
                        product: service.and_then(|s| s.product.clone()),
                        version: service.and_then(|s| s.version.clone()),
                        tls: service.map(|s| s.tls).unwrap_or(false),
                        first_seen: observed_at,
                        last_seen: observed_at,
                    }),
                }
            }

            entry.services.sort_by_key(|s| (s.transport, s.port));
        }

        self.hosts.sort_by_key(|h| h.address);
    }

    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    pub fn service_count(&self) -> usize {
        self.hosts.iter().map(InventoryHost::service_count).sum()
    }

    pub fn stale_since(&self, cutoff: DateTime<Utc>) -> Vec<&InventoryHost> {
        let mut stale: Vec<&InventoryHost> =
            self.hosts.iter().filter(|h| h.last_seen < cutoff).collect();
        stale.sort_by_key(|h| h.last_seen);
        stale
    }

    pub fn to_csv(&self) -> crate::error::Result<String> {
        const COLUMNS: &[&str] = &[
            "address",
            "hostname",
            "mac",
            "vendor",
            "os",
            "device_type",
            "port",
            "transport",
            "service",
            "product",
            "version",
            "tls",
            "first_seen",
            "last_seen",
            "times_seen",
        ];

        let mut writer = csv::WriterBuilder::new()
            .has_headers(false)
            .from_writer(Vec::new());
        writer
            .write_record(COLUMNS)
            .map_err(|e| crate::error::Error::Serialization(e.to_string()))?;

        for host in &self.hosts {
            let base = [
                host.address.to_string(),
                host.hostnames.first().cloned().unwrap_or_default(),
                host.mac.map(|m| m.to_string()).unwrap_or_default(),
                host.vendor.clone().unwrap_or_default(),
                host.os.clone().unwrap_or_default(),
                host.device_type.clone().unwrap_or_default(),
            ];

            if host.services.is_empty() {
                let record: Vec<String> = base
                    .iter()
                    .cloned()
                    .chain(std::iter::repeat_n(String::new(), 6))
                    .chain([
                        host.first_seen.to_rfc3339(),
                        host.last_seen.to_rfc3339(),
                        host.times_seen.to_string(),
                    ])
                    .collect();
                writer
                    .write_record(&record)
                    .map_err(|e| crate::error::Error::Serialization(e.to_string()))?;
                continue;
            }

            for service in &host.services {
                let record: Vec<String> = base
                    .iter()
                    .cloned()
                    .chain([
                        service.port.to_string(),
                        service.transport.to_string(),
                        service.service.clone(),
                        service.product.clone().unwrap_or_default(),
                        service.version.clone().unwrap_or_default(),
                        service.tls.to_string(),
                        service.first_seen.to_rfc3339(),
                        service.last_seen.to_rfc3339(),
                        host.times_seen.to_string(),
                    ])
                    .collect();
                debug_assert_eq!(record.len(), COLUMNS.len());
                writer
                    .write_record(&record)
                    .map_err(|e| crate::error::Error::Serialization(e.to_string()))?;
            }
        }

        let bytes = writer
            .into_inner()
            .map_err(|e| crate::error::Error::Serialization(e.to_string()))?;
        String::from_utf8(bytes).map_err(|e| crate::error::Error::Serialization(e.to_string()))
    }

    pub fn to_json(&self) -> crate::error::Result<String> {
        serde_json::to_string_pretty(self)
            .map(|mut t| {
                t.push('\n');
                t
            })
            .map_err(|e| crate::error::Error::Serialization(e.to_string()))
    }

    pub fn from_json(text: &str) -> crate::error::Result<Self> {
        serde_json::from_str(text)
            .map_err(|e| crate::error::Error::Serialization(format!("not an inventory: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::result::{
        Confidence, DetectionSource, HostReport, PortReason, PortReport, PortState, ServiceInfo,
    };

    fn report_with(address: &str, ports: &[(u16, &str, Option<&str>)]) -> ScanReport {
        let mut report = ScanReport::empty();
        let mut host = HostReport::new(address.parse().unwrap());
        host.status = HostStatus::Up;
        host.add_hostname(
            "web.example",
            crate::scanner::result::HostnameSource::ReverseDns,
        );
        host.mac = Some("00:1b:63:11:22:33".parse().unwrap());
        host.vendor = Some("Apple".to_string());

        for (port, service, version) in ports {
            let mut report_port = PortReport::new(
                *port,
                Transport::Tcp,
                PortState::Open,
                PortReason::ConnectionEstablished,
            );
            report_port.service = Some(ServiceInfo {
                name: (*service).to_string(),
                product: Some("TestProduct".to_string()),
                version: version.map(str::to_string),
                source: DetectionSource::Probe("test".into()),
                confidence: Confidence::High,
                ..Default::default()
            });
            host.ports.push(report_port);
        }
        report.hosts.push(host);
        report.recompute_stats();
        report
    }

    #[test]
    fn an_inventory_is_built_from_a_report() {
        let inventory =
            Inventory::from_report(&report_with("10.0.0.1", &[(22, "ssh", Some("9.6"))]));
        assert_eq!(inventory.len(), 1);
        let host = &inventory.hosts[0];
        assert_eq!(host.address.to_string(), "10.0.0.1");
        assert_eq!(host.hostnames, vec!["web.example".to_string()]);
        assert_eq!(host.vendor.as_deref(), Some("Apple"));
        assert_eq!(host.services.len(), 1);
        assert_eq!(host.services[0].version.as_deref(), Some("9.6"));
        assert_eq!(host.times_seen, 1);
        assert_eq!(host.display_name(), "web.example");
    }

    #[test]
    fn only_hosts_that_are_up_are_recorded() {
        let mut report = report_with("10.0.0.1", &[(22, "ssh", None)]);
        let mut down = HostReport::new("10.0.0.2".parse().unwrap());
        down.status = HostStatus::Down;
        report.hosts.push(down);

        let inventory = Inventory::from_report(&report);
        assert_eq!(inventory.len(), 1);
    }

    #[test]
    fn merging_the_same_scan_twice_does_not_duplicate_hosts() {
        let report = report_with("10.0.0.1", &[(22, "ssh", None)]);
        let mut inventory = Inventory::from_report(&report);
        inventory.merge(&report);
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory.hosts[0].services.len(), 1);
        assert_eq!(
            inventory.scans.len(),
            1,
            "the same scan id should be recorded once"
        );
        assert_eq!(inventory.hosts[0].times_seen, 2);
    }

    #[test]
    fn merging_preserves_first_seen_and_advances_last_seen() {
        let mut earlier = report_with("10.0.0.1", &[(22, "ssh", None)]);
        earlier.started_at = "2026-01-01T00:00:00Z".parse().unwrap();
        let mut later = report_with("10.0.0.1", &[(22, "ssh", None)]);
        later.started_at = "2026-06-01T00:00:00Z".parse().unwrap();

        let mut inventory = Inventory::from_report(&earlier);
        inventory.merge(&later);

        let host = &inventory.hosts[0];
        assert_eq!(host.first_seen, earlier.started_at);
        assert_eq!(host.last_seen, later.started_at);
        assert_eq!(host.services[0].first_seen, earlier.started_at);
        assert_eq!(host.services[0].last_seen, later.started_at);
    }

    #[test]
    fn a_new_service_is_added_on_merge_and_the_old_one_is_kept() {
        let first = report_with("10.0.0.1", &[(22, "ssh", None)]);
        let second = report_with("10.0.0.1", &[(22, "ssh", None), (443, "https", None)]);

        let mut inventory = Inventory::from_report(&first);
        inventory.merge(&second);
        assert_eq!(inventory.hosts[0].services.len(), 2);
        assert_eq!(inventory.service_count(), 2);
    }

    #[test]
    fn a_version_upgrade_is_recorded_on_the_existing_service() {
        let before = report_with("10.0.0.1", &[(22, "ssh", Some("8.9"))]);
        let after = report_with("10.0.0.1", &[(22, "ssh", Some("9.6"))]);

        let mut inventory = Inventory::from_report(&before);
        inventory.merge(&after);
        assert_eq!(inventory.hosts[0].services.len(), 1);
        assert_eq!(
            inventory.hosts[0].services[0].version.as_deref(),
            Some("9.6")
        );
    }

    #[test]
    fn a_scan_without_version_detection_does_not_erase_a_known_version() {
        let detailed = report_with("10.0.0.1", &[(22, "ssh", Some("9.6"))]);
        let mut plain = report_with("10.0.0.1", &[(22, "ssh", None)]);
        plain.hosts[0].ports[0].service = None;

        let mut inventory = Inventory::from_report(&detailed);
        inventory.merge(&plain);
        assert_eq!(
            inventory.hosts[0].services[0].version.as_deref(),
            Some("9.6"),
            "a scan that did not look must not erase what an earlier scan found"
        );
    }

    #[test]
    fn hosts_are_ordered_by_address() {
        let mut inventory = Inventory::from_report(&report_with("10.0.0.9", &[(22, "ssh", None)]));
        inventory.merge(&report_with("10.0.0.2", &[(22, "ssh", None)]));
        assert_eq!(inventory.hosts[0].address.to_string(), "10.0.0.2");
        assert_eq!(inventory.hosts[1].address.to_string(), "10.0.0.9");
    }

    #[test]
    fn stale_hosts_are_identified() {
        let mut old = report_with("10.0.0.1", &[(22, "ssh", None)]);
        old.started_at = "2026-01-01T00:00:00Z".parse().unwrap();
        let mut recent = report_with("10.0.0.2", &[(22, "ssh", None)]);
        recent.started_at = "2026-08-01T00:00:00Z".parse().unwrap();

        let mut inventory = Inventory::from_report(&old);
        inventory.merge(&recent);

        let cutoff: DateTime<Utc> = "2026-06-01T00:00:00Z".parse().unwrap();
        let stale = inventory.stale_since(cutoff);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].address.to_string(), "10.0.0.1");
    }

    #[test]
    fn csv_export_has_one_row_per_service() {
        let inventory = Inventory::from_report(&report_with(
            "10.0.0.1",
            &[(22, "ssh", None), (443, "https", None)],
        ));
        let text = inventory.to_csv().unwrap();
        let rows: Vec<&str> = text.lines().collect();
        assert_eq!(rows.len(), 3, "header plus two services");
        assert!(rows[0].starts_with("address,hostname,mac"));
        assert!(rows[1].contains("10.0.0.1"));
        assert!(rows[1].contains("22"));
    }

    #[test]
    fn csv_export_includes_hosts_with_no_services() {
        let mut report = ScanReport::empty();
        let mut host = HostReport::new("10.0.0.5".parse().unwrap());
        host.status = HostStatus::Up;
        report.hosts.push(host);

        let text = Inventory::from_report(&report).to_csv().unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.contains("10.0.0.5"));
    }

    #[test]
    fn json_round_trips() {
        let inventory =
            Inventory::from_report(&report_with("10.0.0.1", &[(22, "ssh", Some("9.6"))]));
        let text = inventory.to_json().unwrap();
        let parsed = Inventory::from_json(&text).unwrap();
        assert_eq!(parsed, inventory);
    }

    #[test]
    fn malformed_json_is_rejected() {
        assert!(Inventory::from_json("nonsense").is_err());
        assert!(Inventory::from_json("{}").is_err());
    }

    #[test]
    fn an_empty_inventory_is_valid() {
        let inventory = Inventory::new();
        assert!(inventory.is_empty());
        assert_eq!(inventory.service_count(), 0);
        assert!(inventory.to_csv().unwrap().lines().count() == 1);
    }
}
