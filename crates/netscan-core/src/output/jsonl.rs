use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::scanner::result::{HostReport, ScanReport, ScanStats};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Line {
    Scan {
        schema_version: u32,
        scan_id: String,
        started_at: chrono::DateTime<chrono::Utc>,
        parameters: crate::scanner::result::ScanParameters,
    },
    Host(Box<HostReport>),
    Summary {
        scan_id: String,
        finished_at: chrono::DateTime<chrono::Utc>,
        outcome: crate::scanner::result::ScanOutcome,
        stats: ScanStats,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        warnings: Vec<crate::error::Warning>,
    },
}

pub fn render(report: &ScanReport) -> Result<String> {
    let mut out = String::new();
    write_line(&mut out, &header(report))?;
    for host in &report.hosts {
        write_line(&mut out, &Line::Host(Box::new(host.clone())))?;
    }
    write_line(&mut out, &footer(report))?;
    Ok(out)
}

pub fn header(report: &ScanReport) -> Line {
    Line::Scan {
        schema_version: report.schema_version,
        scan_id: report.scan_id.clone(),
        started_at: report.started_at,
        parameters: report.parameters.clone(),
    }
}

pub fn footer(report: &ScanReport) -> Line {
    Line::Summary {
        scan_id: report.scan_id.clone(),
        finished_at: report.finished_at,
        outcome: report.outcome,
        stats: report.stats.clone(),
        warnings: report.warnings.clone(),
    }
}

pub fn render_line(line: &Line) -> Result<String> {
    let mut text = serde_json::to_string(line).map_err(|e| Error::Serialization(e.to_string()))?;
    text.push('\n');
    Ok(text)
}

fn write_line(out: &mut String, line: &Line) -> Result<()> {
    out.push_str(&render_line(line)?);
    Ok(())
}

pub fn parse(text: &str) -> Result<ScanReport> {
    let mut report = ScanReport::empty();
    let mut saw_header = false;

    for (n, raw) in text.lines().enumerate() {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let line: Line = serde_json::from_str(raw)
            .map_err(|e| Error::Serialization(format!("line {}: {e}", n + 1)))?;
        match line {
            Line::Scan {
                schema_version,
                scan_id,
                started_at,
                parameters,
            } => {
                report.schema_version = schema_version;
                report.scan_id = scan_id;
                report.started_at = started_at;
                report.finished_at = started_at;
                report.parameters = parameters;
                saw_header = true;
            }
            Line::Host(host) => report.hosts.push(*host),
            Line::Summary {
                finished_at,
                outcome,
                stats,
                warnings,
                ..
            } => {
                report.finished_at = finished_at;
                report.outcome = outcome;
                report.stats = stats;
                report.warnings = warnings;
            }
        }
    }

    if !saw_header && report.hosts.is_empty() {
        return Err(Error::Serialization(
            "no netscan JSON Lines records found".to_string(),
        ));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::tests::sample_report;

    #[test]
    fn every_line_is_independently_valid_json() {
        let text = render(&sample_report()).unwrap();
        for line in text.lines() {
            serde_json::from_str::<serde_json::Value>(line)
                .unwrap_or_else(|e| panic!("line is not valid JSON ({e}): {line}"));
        }
    }

    #[test]
    fn the_header_comes_first_and_the_summary_last() {
        let text = render(&sample_report()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert!(
            lines[0].contains("\"type\":\"scan\""),
            "first line was: {}",
            lines[0]
        );
        assert!(
            lines.last().unwrap().contains("\"type\":\"summary\""),
            "last line was: {}",
            lines.last().unwrap()
        );
        assert_eq!(lines.len(), 2 + sample_report().hosts.len());
    }

    #[test]
    fn round_trips_through_parse() {
        let report = sample_report();
        let parsed = parse(&render(&report).unwrap()).unwrap();
        assert_eq!(parsed.hosts, report.hosts);
        assert_eq!(parsed.scan_id, report.scan_id);
        assert_eq!(parsed.stats, report.stats);
    }

    #[test]
    fn a_truncated_stream_still_yields_the_hosts_it_contains() {
        let text = render(&sample_report()).unwrap();

        let truncated: String = text
            .lines()
            .take(text.lines().count() - 1)
            .collect::<Vec<_>>()
            .join("\n");
        let parsed = parse(&truncated).unwrap();
        assert_eq!(parsed.hosts.len(), 2);
    }

    #[test]
    fn blank_lines_are_ignored() {
        let text = format!("\n{}\n\n", render(&sample_report()).unwrap());
        assert_eq!(parse(&text).unwrap().hosts.len(), 2);
    }

    #[test]
    fn a_malformed_line_names_its_line_number() {
        let text = format!("{}not json\n", render(&sample_report()).unwrap());
        let err = parse(&text).unwrap_err();
        assert!(err.to_string().contains("line 5"), "message was: {err}");
    }

    #[test]
    fn empty_input_is_an_error_rather_than_an_empty_report() {
        assert!(parse("").is_err());
    }

    #[test]
    fn single_lines_can_be_streamed() {
        let report = sample_report();
        let line = render_line(&Line::Host(Box::new(report.hosts[0].clone()))).unwrap();
        assert!(line.ends_with('\n'));
        assert_eq!(line.lines().count(), 1);
        assert!(line.contains("192.168.1.10"));
    }
}
