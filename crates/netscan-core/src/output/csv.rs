use crate::error::{Error, Result};
use crate::scanner::result::{HostStatus, ScanReport};

pub const COLUMNS: &[&str] = &[
    "address",
    "hostname",
    "host_status",
    "host_rtt_ms",
    "mac",
    "vendor",
    "os_family",
    "os_confidence",
    "port",
    "transport",
    "state",
    "reason",
    "port_rtt_ms",
    "service",
    "product",
    "version",
    "tls",
    "tls_subject",
    "tls_expires",
    "detection_source",
    "confidence",
    "banner",
    "scan_id",
    "started_at",
];

pub fn render(report: &ScanReport) -> Result<String> {
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_writer(Vec::new());

    writer
        .write_record(COLUMNS)
        .map_err(|e| Error::Serialization(format!("csv header: {e}")))?;

    for host in &report.hosts {
        let host_fields = [
            host.address.to_string(),
            host.primary_hostname().unwrap_or_default().to_string(),
            host.status.to_string(),
            host.rtt_ms.map(format_ms).unwrap_or_default(),
            host.mac.map(|m| m.to_string()).unwrap_or_default(),
            host.vendor.clone().unwrap_or_default(),
            host.os
                .as_ref()
                .and_then(|o| o.family.clone())
                .unwrap_or_default(),
            host.os
                .as_ref()
                .map(|o| o.confidence.to_string())
                .unwrap_or_default(),
        ];

        if host.ports.is_empty() {
            let mut record: Vec<String> = host_fields.to_vec();
            record.extend(std::iter::repeat_n(
                String::new(),
                COLUMNS.len() - host_fields.len() - 2,
            ));
            record.push(report.scan_id.clone());
            record.push(report.started_at.to_rfc3339());
            writer
                .write_record(&record)
                .map_err(|e| Error::Serialization(format!("csv row: {e}")))?;
            continue;
        }

        for port in &host.ports {
            let service = port.service.as_ref();
            let tls = port.tls.as_ref();
            let record: Vec<String> = host_fields
                .iter()
                .cloned()
                .chain([
                    port.port.to_string(),
                    port.transport.to_string(),
                    port.state.to_string(),
                    port.reason.to_string(),
                    port.rtt_ms.map(format_ms).unwrap_or_default(),
                    service
                        .map(|s| s.name.clone())
                        .unwrap_or_else(|| port.service_name().to_string()),
                    service.and_then(|s| s.product.clone()).unwrap_or_default(),
                    service.and_then(|s| s.version.clone()).unwrap_or_default(),
                    service
                        .map(|s| s.tls.to_string())
                        .unwrap_or_else(|| "false".to_string()),
                    tls.and_then(|t| t.subject.clone()).unwrap_or_default(),
                    tls.and_then(|t| t.not_after)
                        .map(|d| d.to_rfc3339())
                        .unwrap_or_default(),
                    service.map(|s| s.source.to_string()).unwrap_or_default(),
                    service
                        .map(|s| s.confidence.to_string())
                        .unwrap_or_default(),
                    port.banner.clone().unwrap_or_default(),
                    report.scan_id.clone(),
                    report.started_at.to_rfc3339(),
                ])
                .collect();

            debug_assert_eq!(record.len(), COLUMNS.len());
            writer
                .write_record(&record)
                .map_err(|e| Error::Serialization(format!("csv row: {e}")))?;
        }
    }

    let bytes = writer
        .into_inner()
        .map_err(|e| Error::Serialization(format!("csv flush: {e}")))?;
    String::from_utf8(bytes).map_err(|e| Error::Serialization(e.to_string()))
}

pub fn render_hosts(report: &ScanReport) -> Result<String> {
    const HOST_COLUMNS: &[&str] = &[
        "address",
        "hostname",
        "status",
        "rtt_ms",
        "mac",
        "vendor",
        "os_family",
        "open_ports",
    ];

    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_writer(Vec::new());
    writer
        .write_record(HOST_COLUMNS)
        .map_err(|e| Error::Serialization(format!("csv header: {e}")))?;

    for host in report
        .hosts
        .iter()
        .filter(|h| h.status != HostStatus::Skipped)
    {
        let open: Vec<String> = host.open_ports().map(|p| p.label()).collect();
        writer
            .write_record([
                host.address.to_string(),
                host.primary_hostname().unwrap_or_default().to_string(),
                host.status.to_string(),
                host.rtt_ms.map(format_ms).unwrap_or_default(),
                host.mac.map(|m| m.to_string()).unwrap_or_default(),
                host.vendor.clone().unwrap_or_default(),
                host.os
                    .as_ref()
                    .and_then(|o| o.family.clone())
                    .unwrap_or_default(),
                open.join(" "),
            ])
            .map_err(|e| Error::Serialization(format!("csv row: {e}")))?;
    }

    let bytes = writer
        .into_inner()
        .map_err(|e| Error::Serialization(format!("csv flush: {e}")))?;
    String::from_utf8(bytes).map_err(|e| Error::Serialization(e.to_string()))
}

fn format_ms(value: f64) -> String {
    format!("{value:.2}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::tests::sample_report;

    fn parse(text: &str) -> Vec<Vec<String>> {
        csv::ReaderBuilder::new()
            .has_headers(false)
            .from_reader(text.as_bytes())
            .records()
            .map(|r| r.unwrap().iter().map(str::to_string).collect())
            .collect()
    }

    #[test]
    fn the_header_matches_the_declared_columns() {
        let rows = parse(&render(&sample_report()).unwrap());
        assert_eq!(
            rows[0],
            COLUMNS.iter().map(|s| s.to_string()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn every_row_has_the_same_number_of_fields() {
        let rows = parse(&render(&sample_report()).unwrap());
        for (n, row) in rows.iter().enumerate() {
            assert_eq!(row.len(), COLUMNS.len(), "row {n} has {} fields", row.len());
        }
    }

    #[test]
    fn there_is_one_row_per_port() {
        let report = sample_report();
        let rows = parse(&render(&report).unwrap());

        assert_eq!(rows.len(), 1 + 2 + 1);
    }

    #[test]
    fn host_details_are_repeated_on_each_port_row() {
        let rows = parse(&render(&sample_report()).unwrap());
        assert_eq!(rows[1][0], "192.168.1.10");
        assert_eq!(rows[2][0], "192.168.1.10");
        assert_eq!(rows[1][1], "router.local");
        assert_eq!(rows[1][4], "00:1b:63:11:22:33");
    }

    #[test]
    fn service_details_are_exported() {
        let rows = parse(&render(&sample_report()).unwrap());
        let ssh = rows.iter().find(|r| r[8] == "22").expect("port 22 row");
        assert_eq!(ssh[9], "tcp");
        assert_eq!(ssh[10], "open");
        assert_eq!(ssh[13], "ssh");
        assert_eq!(ssh[14], "OpenSSH");
        assert_eq!(ssh[15], "9.6p1");
        assert_eq!(ssh[19], "probe:ssh");
        assert_eq!(ssh[20], "high");
    }

    #[test]
    fn hosts_with_no_listed_ports_still_appear() {
        let rows = parse(&render(&sample_report()).unwrap());
        let down = rows
            .iter()
            .find(|r| r[0] == "192.168.1.11")
            .expect("down host row");
        assert_eq!(down[2], "down");
        assert_eq!(down[8], "", "there is no port on this row");
    }

    #[test]
    fn fields_containing_separators_are_quoted() {
        let mut report = sample_report();
        report.hosts[0].ports[0].banner = Some("has, a comma and \"quotes\"".to_string());
        let text = render(&report).unwrap();

        let rows = parse(&text);
        let ssh = rows.iter().find(|r| r[8] == "22").unwrap();
        assert_eq!(ssh[21], "has, a comma and \"quotes\"");
    }

    #[test]
    fn newlines_in_banners_do_not_break_the_row_structure() {
        let mut report = sample_report();
        report.hosts[0].ports[0].banner = Some("line one\nline two".to_string());
        let rows = parse(&render(&report).unwrap());
        for row in &rows {
            assert_eq!(row.len(), COLUMNS.len());
        }
    }

    #[test]
    fn the_host_only_export_has_one_row_per_host() {
        let rows = parse(&render_hosts(&sample_report()).unwrap());
        assert_eq!(rows.len(), 3, "header plus two hosts");
        assert_eq!(rows[1][7], "22/tcp 443/tcp");
    }

    #[test]
    fn an_empty_report_still_produces_a_header() {
        let text = render(&ScanReport::empty()).unwrap();
        let rows = parse(&text);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][0], "address");
    }
}
