use std::fmt::Write;

use crate::output::RenderOptions;
use crate::scanner::result::{HostReport, HostStatus, PortState, ScanReport};

mod colour {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const RED: &str = "\x1b[31m";
    pub const CYAN: &str = "\x1b[36m";
}

struct Painter {
    enabled: bool,
}

impl Painter {
    fn paint(&self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("{code}{text}{}", colour::RESET)
        } else {
            text.to_string()
        }
    }

    fn bold(&self, text: &str) -> String {
        self.paint(colour::BOLD, text)
    }

    fn dim(&self, text: &str) -> String {
        self.paint(colour::DIM, text)
    }

    fn state(&self, state: PortState) -> String {
        let code = match state {
            PortState::Open => colour::GREEN,
            PortState::OpenFiltered => colour::YELLOW,
            PortState::Closed => colour::DIM,
            PortState::Filtered => colour::YELLOW,
            PortState::Unknown => colour::RED,
        };
        self.paint(code, state.as_str())
    }
}

pub fn render(report: &ScanReport, options: RenderOptions) -> String {
    let painter = Painter {
        enabled: options.colour,
    };
    let mut out = String::with_capacity(2048);

    let shown: Vec<&HostReport> = report
        .hosts
        .iter()
        .filter(|host| options.show_down_hosts || host.status == HostStatus::Up)
        .collect();

    let up: Vec<&HostReport> = shown
        .iter()
        .copied()
        .filter(|h| h.status == HostStatus::Up)
        .collect();
    if up.len() > 1 {
        let _ = writeln!(out, "{}", painter.bold(&format!("Hosts ({})", up.len())));
        render_host_table(&mut out, &up, &options, &painter);
        out.push('\n');
    }

    for host in &shown {
        render_host(&mut out, host, &options, &painter);
        out.push('\n');
    }

    if shown.is_empty() && !report.hosts.is_empty() {
        let _ = writeln!(
            out,
            "No hosts were up. Re-run with --show-down to list the {} address(es) that were tested.",
            report.hosts.len()
        );
        out.push('\n');
    }

    render_summary(&mut out, report, &options, &painter);

    if !report.warnings.is_empty() {
        out.push('\n');
        let _ = writeln!(out, "{}", painter.bold("Warnings"));
        for warning in &report.warnings {
            let _ = writeln!(
                out,
                "  {}",
                painter.paint(colour::YELLOW, &warning.to_string())
            );
        }
    }

    out
}

fn render_host(out: &mut String, host: &HostReport, options: &RenderOptions, painter: &Painter) {
    let title = match host.primary_hostname() {
        Some(name) => format!("{} ({})", host.address, name),
        None => host.address.to_string(),
    };
    let _ = write!(out, "{}", painter.bold(&title));

    if host.status != HostStatus::Up {
        let _ = writeln!(out, "  {}", painter.dim(&format!("[{}]", host.status)));
        return;
    }

    if let Some(rtt) = host.rtt_ms {
        let _ = write!(out, "  {}", painter.dim(&format!("{rtt:.1} ms")));
    }
    out.push('\n');

    if let Some(mac) = &host.mac {
        let vendor = host.vendor.as_deref().unwrap_or("unknown vendor");
        let _ = writeln!(out, "  MAC     {mac}  ({vendor})");
    }
    if let Some(os) = &host.os {
        if !os.is_empty() {
            let _ = writeln!(
                out,
                "  OS      {} {}",
                os.summary(),
                painter.dim("(inferred)")
            );
            if options.show_reasons {
                for evidence in &os.evidence {
                    let _ = writeln!(
                        out,
                        "          {}",
                        painter.dim(&format!("{}: {}", evidence.kind, evidence.detail))
                    );
                }
            }
        }
    }

    let listed: Vec<_> = host
        .ports
        .iter()
        .filter(|port| options.show_all_ports || port.state.is_open_ish())
        .collect();

    if listed.is_empty() {
        let _ = writeln!(out, "  {}", painter.dim("no open ports found"));
    } else {
        render_port_table(out, &listed, options, painter);
    }

    if !host.other_ports.is_empty() && !options.show_all_ports {
        let summary: Vec<String> = host
            .other_ports
            .counts
            .iter()
            .map(|(state, count)| format!("{count} {state}"))
            .collect();
        let _ = writeln!(
            out,
            "  {}",
            painter.dim(&format!("Not shown: {}", summary.join(", ")))
        );
    }

    if host.not_scanned > 0 {
        let _ = writeln!(
            out,
            "  {}",
            painter.paint(
                colour::YELLOW,
                &format!("{} port(s) were not tested", host.not_scanned)
            )
        );
    }
}

fn render_port_table(
    out: &mut String,
    ports: &[&crate::scanner::result::PortReport],
    options: &RenderOptions,
    painter: &Painter,
) {
    use crate::output::table::{Column, Table};

    let mut columns = vec![
        Column::new("PORT"),
        Column::new("STATE"),
        Column::new("SERVICE"),
        Column::new("VERSION").flexible(),
    ];
    if options.show_reasons {
        columns.push(Column::new("REASON"));
    }
    columns.push(Column::new("DETAILS").flexible());

    let mut table = Table::new(columns)
        .style(options.table_style)
        .indent(2)
        .max_width(options.width.map(|w| w.saturating_sub(2)));

    for port in ports {
        let version = port
            .service
            .as_ref()
            .and_then(|service| service.product_version())
            .unwrap_or_default();

        let mut details = String::new();
        if let Some(service) = &port.service {
            if service.tls {
                details.push_str("TLS");
            }
            if let Some(extra) = &service.extra {
                if !details.is_empty() {
                    details.push_str(", ");
                }
                details.push_str(extra);
            }
        }
        if let Some(tls) = &port.tls {
            if let Some(subject) = &tls.subject {
                if !details.is_empty() {
                    details.push_str(", ");
                }
                let _ = write!(details, "cert {subject}");
                if tls.expired {
                    details.push_str(&painter.paint(colour::RED, " EXPIRED"));
                } else if tls.self_signed {
                    details.push_str(" (self-signed)");
                }
            }
        }
        if let Some(error) = &port.error {
            if !details.is_empty() {
                details.push_str(", ");
            }
            let _ = write!(details, "{error}");
        }
        if options.show_banners {
            if let Some(banner) = &port.banner {
                if !details.is_empty() {
                    details.push_str(" | ");
                }
                details.push_str(banner);
            }
        }

        let mut row = vec![
            painter.paint(colour::CYAN, &port.label()),
            painter.state(port.state),
            port.service_name().to_string(),
            version,
        ];
        if options.show_reasons {
            row.push(port.reason.to_string());
        }
        row.push(details);
        table.row(row);
    }

    out.push_str(&table.render());
}

fn render_host_table(
    out: &mut String,
    hosts: &[&HostReport],
    options: &RenderOptions,
    painter: &Painter,
) {
    use crate::output::table::{Align, Column, Table};

    let mut table = Table::new(vec![
        Column::new("ADDRESS"),
        Column::new("HOSTNAME").flexible(),
        Column::new("STATUS"),
        Column {
            header: "OPEN".to_string(),
            align: Align::Right,
            flexible: false,
        },
        Column {
            header: "LATENCY".to_string(),
            align: Align::Right,
            flexible: false,
        },
        Column::new("SERVICES").flexible(),
    ])
    .style(options.table_style)
    .max_width(options.width);

    for host in hosts {
        let mut services: Vec<&str> = host.open_ports().map(|p| p.service_name()).collect();
        services.sort_unstable();
        services.dedup();

        let open = host.open_port_count();
        table.row([
            painter.bold(&host.address.to_string()),
            host.primary_hostname().unwrap_or("").to_string(),
            painter.paint(status_colour(host.status), &host.status.to_string()),
            if open > 0 {
                painter.paint(colour::GREEN, &open.to_string())
            } else {
                "0".to_string()
            },
            host.rtt_ms
                .map(|rtt| format!("{rtt:.1} ms"))
                .unwrap_or_default(),
            services.join(", "),
        ]);
    }

    out.push_str(&table.render());
}

fn status_colour(status: HostStatus) -> &'static str {
    match status {
        HostStatus::Up => colour::GREEN,
        HostStatus::Down => colour::DIM,
        HostStatus::Skipped => colour::DIM,
    }
}

fn render_summary(
    out: &mut String,
    report: &ScanReport,
    options: &RenderOptions,
    painter: &Painter,
) {
    use crate::output::table::{Align, Column, Table};

    let stats = &report.stats;
    let seconds = stats.duration_ms as f64 / 1000.0;

    let mut table = Table::new(vec![
        Column::new("HOSTS UP").right(),
        Column::new("SCANNED").right(),
        Column::new("OPEN").right(),
        Column::new("TESTED").right(),
        Column {
            header: "TIME".to_string(),
            align: Align::Right,
            flexible: false,
        },
        Column {
            header: "RATE".to_string(),
            align: Align::Right,
            flexible: false,
        },
    ])
    .style(options.table_style)
    .max_width(options.width);

    table.row([
        painter.paint(colour::GREEN, &stats.hosts_up.to_string()),
        stats.hosts_total.to_string(),
        painter.paint(colour::GREEN, &stats.ports_open.to_string()),
        stats.ports_tested.to_string(),
        format!("{seconds:.2}s"),
        format!("{:.0}/s", stats.probes_per_second()),
    ]);
    out.push_str(&table.render());

    let mut notes: Vec<String> = Vec::new();
    if let Some(rtt) = stats.mean_rtt_ms {
        notes.push(format!("mean RTT {rtt:.1} ms"));
    }
    if stats.retries > 0 {
        notes.push(format!("{} retries", stats.retries));
    }
    if stats.errors > 0 {
        notes.push(format!("{} errors", stats.errors));
    }
    if !notes.is_empty() {
        let _ = writeln!(out, "{}", painter.dim(&notes.join(", ")));
    }

    if report.outcome != crate::scanner::result::ScanOutcome::Completed {
        let _ = writeln!(
            out,
            "{}",
            painter.paint(
                colour::YELLOW,
                &format!("Scan {:?}: results are partial.", report.outcome).to_lowercase()
            )
        );
    }
}

pub fn host_one_liner(host: &HostReport, colour: bool) -> String {
    let painter = Painter { enabled: colour };
    let name = match host.primary_hostname() {
        Some(name) => format!("{} ({name})", host.address),
        None => host.address.to_string(),
    };
    let open = host.open_port_count();
    let ports: Vec<String> = host
        .open_ports()
        .take(6)
        .map(|p| p.port.to_string())
        .collect();
    let mut summary = format!("{:<40} {open} open", painter.bold(&name));
    if !ports.is_empty() {
        let _ = write!(summary, "  {}", painter.dim(&ports.join(", ")));
        if open > ports.len() {
            let _ = write!(
                summary,
                "{}",
                painter.dim(&format!(", +{}", open - ports.len()))
            );
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::tests::sample_report;

    fn strip_ansi(text: &str) -> String {
        let mut out = String::new();
        let mut chars = text.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                for c in chars.by_ref() {
                    if c == 'm' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn open_ports_are_listed_with_their_services() {
        let text = render(&sample_report(), RenderOptions::concise());
        assert!(text.contains("192.168.1.10"));
        assert!(text.contains("router.local"));
        assert!(text.contains("22/tcp"));
        assert!(text.contains("open"));
        assert!(text.contains("OpenSSH 9.6p1"));
        assert!(text.contains("nginx 1.24.0"));
    }

    #[test]
    fn closed_ports_are_summarised_not_listed() {
        let text = render(&sample_report(), RenderOptions::concise());
        assert!(text.contains("Not shown: 2 closed"), "output was:\n{text}");

        assert_eq!(text.matches("closed").count(), 1);
    }

    #[test]
    fn down_hosts_are_hidden_by_default_and_shown_on_request() {
        let concise = render(&sample_report(), RenderOptions::concise());
        assert!(!concise.contains("192.168.1.11"));

        let verbose = render(&sample_report(), RenderOptions::verbose());
        assert!(verbose.contains("192.168.1.11"));
        assert!(verbose.contains("[down]"));
    }

    #[test]
    fn the_summary_reports_the_headline_numbers() {
        let text = render(&sample_report(), RenderOptions::concise());
        assert!(text.contains("HOSTS UP"), "output was:\n{text}");
        assert!(text.contains("OPEN"));
        assert!(text.contains("TESTED"));

        let row = text
            .lines()
            .skip_while(|line| !line.contains("HOSTS UP"))
            .nth(2)
            .expect("the summary table should have a row");
        let cells: Vec<&str> = row
            .split('│')
            .map(str::trim)
            .filter(|cell| !cell.is_empty())
            .collect();
        assert_eq!(cells[0], "1", "one host up");
        assert_eq!(cells[1], "2", "of two scanned");
        assert_eq!(cells[2], "2", "two open ports");
    }

    #[test]
    fn banners_appear_only_when_asked_for() {
        let concise = render(&sample_report(), RenderOptions::concise());
        assert!(!concise.contains("SSH-2.0-OpenSSH_9.6p1"));

        let verbose = render(&sample_report(), RenderOptions::verbose());
        assert!(verbose.contains("SSH-2.0-OpenSSH_9.6p1"));
    }

    #[test]
    fn reasons_appear_only_when_asked_for() {
        let concise = render(&sample_report(), RenderOptions::concise());
        assert!(!concise.contains("connection-established"));

        let verbose = render(&sample_report(), RenderOptions::verbose());
        assert!(verbose.contains("connection-established"));
    }

    #[test]
    fn colour_is_off_by_default_and_adds_no_information() {
        let plain = render(&sample_report(), RenderOptions::concise());
        assert!(!plain.contains('\x1b'), "colour should be opt-in");

        let coloured = render(&sample_report(), RenderOptions::concise().with_colour(true));
        assert!(coloured.contains('\x1b'));
        assert_eq!(
            strip_ansi(&coloured),
            plain,
            "colour must be redundant with the plain text"
        );
    }

    #[test]
    fn tables_stay_aligned_when_colour_is_enabled() {
        use crate::output::table::display_width;

        let coloured = render(&sample_report(), RenderOptions::concise().with_colour(true));

        let table_lines: Vec<&str> = coloured
            .lines()
            .filter(|line| line.contains('│') || line.contains('╭'))
            .collect();
        assert!(
            !table_lines.is_empty(),
            "no table was rendered:\n{coloured}"
        );

        let widths: Vec<usize> = table_lines.iter().map(|l| display_width(l)).collect();

        let mut sorted = widths.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert!(
            sorted.len() <= 2,
            "table lines have inconsistent widths {widths:?}:\n{}",
            strip_ansi(&coloured)
        );
    }

    #[test]
    fn a_multi_host_scan_leads_with_an_overview_table() {
        let mut report = sample_report();
        let mut second = crate::scanner::result::HostReport::new("192.168.1.12".parse().unwrap());
        second.status = HostStatus::Up;
        second.ports.push(crate::scanner::result::PortReport::new(
            80,
            crate::scanner::port::Transport::Tcp,
            PortState::Open,
            crate::scanner::result::PortReason::ConnectionEstablished,
        ));
        report.hosts.push(second);
        report.recompute_stats();

        let text = render(&report, RenderOptions::concise());
        let overview = text
            .find("ADDRESS")
            .expect("an overview table should be present");
        let detail = text
            .find("PORT")
            .expect("per-host detail should be present");
        assert!(overview < detail, "the overview belongs first:\n{text}");
        assert!(text.contains("Hosts (2)"));
    }

    #[test]
    fn a_single_host_scan_skips_the_overview() {
        let text = render(&sample_report(), RenderOptions::concise());
        assert!(
            !text.contains("Hosts (1)"),
            "one host needs no overview table:\n{text}"
        );
    }

    #[test]
    fn an_all_down_scan_says_so_helpfully() {
        let mut report = sample_report();
        for host in &mut report.hosts {
            host.status = HostStatus::Down;
            host.ports.clear();
        }
        report.recompute_stats();

        let text = render(&report, RenderOptions::concise());
        assert!(text.contains("No hosts were up"));
        assert!(
            text.contains("--show-down"),
            "the message should say what to do next"
        );
    }

    #[test]
    fn a_partial_scan_is_flagged() {
        let mut report = sample_report();
        report.outcome = crate::scanner::result::ScanOutcome::Cancelled;
        let text = render(&report, RenderOptions::concise());
        assert!(text.contains("results are partial"));
    }

    #[test]
    fn warnings_are_shown() {
        let mut report = sample_report();
        report
            .warnings
            .push(crate::error::Warning::global("test.code", "be careful"));
        let text = render(&report, RenderOptions::concise());
        assert!(text.contains("Warnings"));
        assert!(text.contains("be careful"));
    }

    #[test]
    fn os_inference_is_labelled_as_such() {
        let mut report = sample_report();
        report.hosts[0].os = Some(crate::scanner::result::OsGuess {
            family: Some("Linux".to_string()),
            confidence: crate::scanner::result::Confidence::Medium,
            ..Default::default()
        });
        let text = render(&report, RenderOptions::concise());
        assert!(text.contains("Linux (medium confidence)"));
        assert!(
            text.contains("(inferred)"),
            "an inference must be labelled: {text}"
        );
    }

    #[test]
    fn the_one_liner_is_compact() {
        let report = sample_report();
        let line = host_one_liner(&report.hosts[0], false);
        assert!(line.contains("192.168.1.10"));
        assert!(line.contains("2 open"));
        assert_eq!(line.lines().count(), 1);
    }

    #[test]
    fn an_empty_report_renders_a_summary() {
        let text = render(&ScanReport::empty(), RenderOptions::concise());
        assert!(text.contains("HOSTS UP"), "output was:\n{text}");
    }
}
