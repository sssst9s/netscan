use std::fmt::Write;

use crate::scanner::result::{HostStatus, ScanReport};

pub fn render(report: &ScanReport) -> String {
    let mut out = String::with_capacity(4096);
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let _ = writeln!(
        out,
        "<netscan version=\"{}\" schema=\"{}\" scan_id=\"{}\" started=\"{}\" finished=\"{}\" outcome=\"{}\">",
        escape(&report.tool.version),
        report.schema_version,
        escape(&report.scan_id),
        escape(&report.started_at.to_rfc3339()),
        escape(&report.finished_at.to_rfc3339()),
        escape(&format!("{:?}", report.outcome).to_lowercase()),
    );

    render_parameters(&mut out, report);

    out.push_str("  <hosts>\n");
    for host in &report.hosts {
        render_host(&mut out, host);
    }
    out.push_str("  </hosts>\n");

    render_stats(&mut out, report);

    if !report.warnings.is_empty() {
        out.push_str("  <warnings>\n");
        for warning in &report.warnings {
            let _ = writeln!(
                out,
                "    <warning code=\"{}\"{}>{}</warning>",
                escape(&warning.code),
                warning
                    .host
                    .map(|h| format!(" host=\"{}\"", escape(&h.to_string())))
                    .unwrap_or_default(),
                escape(&warning.message)
            );
        }
        out.push_str("  </warnings>\n");
    }

    out.push_str("</netscan>\n");
    out
}

fn render_parameters(out: &mut String, report: &ScanReport) {
    let p = &report.parameters;
    out.push_str("  <parameters>\n");
    for target in &p.targets {
        let _ = writeln!(out, "    <target>{}</target>", escape(target));
    }
    let _ = writeln!(out, "    <ports>{}</ports>", escape(&p.ports));
    for transport in &p.transports {
        let _ = writeln!(out, "    <transport>{}</transport>", escape(transport));
    }
    let _ = writeln!(out, "    <tcp_mode>{}</tcp_mode>", escape(&p.tcp_mode));
    let _ = writeln!(out, "    <timing>{}</timing>", escape(&p.timing));
    let _ = writeln!(out, "    <concurrency>{}</concurrency>", p.concurrency);
    if let Some(profile) = &p.profile {
        let _ = writeln!(out, "    <profile>{}</profile>", escape(profile));
    }
    let _ = writeln!(
        out,
        "    <detection service=\"{}\" os=\"{}\"/>",
        p.service_detection, p.os_detection
    );
    out.push_str("  </parameters>\n");
}

fn render_host(out: &mut String, host: &crate::scanner::result::HostReport) {
    let _ = write!(
        out,
        "    <host address=\"{}\" status=\"{}\"",
        escape(&host.address.to_string()),
        host.status
    );
    if let Some(rtt) = host.rtt_ms {
        let _ = write!(out, " rtt_ms=\"{rtt:.2}\"");
    }
    if let Some(mac) = &host.mac {
        let _ = write!(out, " mac=\"{}\"", escape(&mac.to_string()));
    }
    if let Some(vendor) = &host.vendor {
        let _ = write!(out, " vendor=\"{}\"", escape(vendor));
    }
    out.push_str(">\n");

    if let Some(reason) = &host.status_reason {
        let _ = writeln!(
            out,
            "      <status_reason>{}</status_reason>",
            escape(reason)
        );
    }

    for hostname in &host.hostnames {
        let _ = writeln!(
            out,
            "      <hostname source=\"{}\">{}</hostname>",
            escape(&format!("{:?}", hostname.source).to_lowercase()),
            escape(&hostname.name)
        );
    }

    if let Some(os) = &host.os {
        if !os.is_empty() {
            let _ = write!(out, "      <os confidence=\"{}\"", os.confidence);
            if let Some(family) = &os.family {
                let _ = write!(out, " family=\"{}\"", escape(family));
            }
            if let Some(name) = &os.name {
                let _ = write!(out, " name=\"{}\"", escape(name));
            }
            if let Some(device) = &os.device_type {
                let _ = write!(out, " device_type=\"{}\"", escape(device));
            }
            out.push_str(">\n");
            for evidence in &os.evidence {
                let _ = writeln!(
                    out,
                    "        <evidence kind=\"{}\" suggests=\"{}\">{}</evidence>",
                    escape(&evidence.kind),
                    escape(&evidence.suggests),
                    escape(&evidence.detail)
                );
            }
            out.push_str("      </os>\n");
        }
    }

    if !host.ports.is_empty() {
        out.push_str("      <ports>\n");
        for port in &host.ports {
            render_port(out, port);
        }
        out.push_str("      </ports>\n");
    }

    if !host.other_ports.is_empty() {
        out.push_str("      <other_ports>\n");
        for (state, count) in &host.other_ports.counts {
            let _ = writeln!(
                out,
                "        <state name=\"{}\" count=\"{count}\"/>",
                escape(state)
            );
        }
        out.push_str("      </other_ports>\n");
    }

    if host.not_scanned > 0 {
        let _ = writeln!(out, "      <not_scanned>{}</not_scanned>", host.not_scanned);
    }

    out.push_str("    </host>\n");
}

fn render_port(out: &mut String, port: &crate::scanner::result::PortReport) {
    let _ = write!(
        out,
        "        <port number=\"{}\" transport=\"{}\" state=\"{}\" reason=\"{}\"",
        port.port, port.transport, port.state, port.reason
    );
    if let Some(rtt) = port.rtt_ms {
        let _ = write!(out, " rtt_ms=\"{rtt:.2}\"");
    }

    let has_children = port.service.is_some() || port.tls.is_some() || port.banner.is_some();
    if !has_children {
        out.push_str("/>\n");
        return;
    }
    out.push_str(">\n");

    if let Some(service) = &port.service {
        let _ = write!(
            out,
            "          <service name=\"{}\" source=\"{}\" confidence=\"{}\" tls=\"{}\"",
            escape(&service.name),
            escape(&service.source.to_string()),
            service.confidence,
            service.tls
        );
        if let Some(product) = &service.product {
            let _ = write!(out, " product=\"{}\"", escape(product));
        }
        if let Some(version) = &service.version {
            let _ = write!(out, " version=\"{}\"", escape(version));
        }
        if let Some(extra) = &service.extra {
            let _ = write!(out, " extra=\"{}\"", escape(extra));
        }
        out.push_str("/>\n");
    }

    if let Some(tls) = &port.tls {
        let _ = write!(
            out,
            "          <tls expired=\"{}\" self_signed=\"{}\"",
            tls.expired, tls.self_signed
        );
        if let Some(version) = &tls.version {
            let _ = write!(out, " version=\"{}\"", escape(version));
        }
        if let Some(subject) = &tls.subject {
            let _ = write!(out, " subject=\"{}\"", escape(subject));
        }
        if let Some(issuer) = &tls.issuer {
            let _ = write!(out, " issuer=\"{}\"", escape(issuer));
        }
        if let Some(not_after) = tls.not_after {
            let _ = write!(out, " not_after=\"{}\"", escape(&not_after.to_rfc3339()));
        }
        if tls.subject_alt_names.is_empty() {
            out.push_str("/>\n");
        } else {
            out.push_str(">\n");
            for name in &tls.subject_alt_names {
                let _ = writeln!(out, "            <san>{}</san>", escape(name));
            }
            out.push_str("          </tls>\n");
        }
    }

    if let Some(banner) = &port.banner {
        let _ = writeln!(out, "          <banner>{}</banner>", escape(banner));
    }

    out.push_str("        </port>\n");
}

fn render_stats(out: &mut String, report: &ScanReport) {
    let s = &report.stats;
    let _ = writeln!(
        out,
        "  <stats hosts_total=\"{}\" hosts_up=\"{}\" hosts_down=\"{}\" ports_tested=\"{}\" \
         ports_open=\"{}\" ports_closed=\"{}\" ports_filtered=\"{}\" probes_sent=\"{}\" \
         retries=\"{}\" errors=\"{}\" duration_ms=\"{}\"/>",
        s.hosts_total,
        s.hosts_up,
        s.hosts_down,
        s.ports_tested,
        s.ports_open,
        s.ports_closed,
        s.ports_filtered,
        s.probes_sent,
        s.retries,
        s.errors,
        s.duration_ms
    );
    let _ = report;
    let _ = HostStatus::Up;
}

fn escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(c),
            c if (c as u32) < 0x20 => out.push('.'),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::tests::sample_report;

    #[test]
    fn output_has_a_declaration_and_a_single_root() {
        let text = render(&sample_report());
        assert!(text.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"));
        assert_eq!(text.matches("<netscan ").count(), 1);
        assert!(text.trim_end().ends_with("</netscan>"));
    }

    #[test]
    fn tags_are_balanced() {
        let text = render(&sample_report());
        for tag in [
            "netscan",
            "parameters",
            "hosts",
            "host",
            "ports",
            "port",
            "service",
        ] {
            let opens = text.matches(&format!("<{tag} ")).count()
                + text.matches(&format!("<{tag}>")).count();
            let self_closing = text
                .lines()
                .filter(|l| {
                    l.trim_start().starts_with(&format!("<{tag} ")) && l.trim_end().ends_with("/>")
                })
                .count();
            let closes = text.matches(&format!("</{tag}>")).count();
            assert_eq!(
                opens - self_closing,
                closes,
                "unbalanced <{tag}>: {opens} open, {self_closing} self-closing, {closes} closed"
            );
        }
    }

    #[test]
    fn host_and_port_details_appear() {
        let text = render(&sample_report());
        assert!(text.contains("address=\"192.168.1.10\""));
        assert!(text.contains("number=\"22\""));
        assert!(text.contains("product=\"OpenSSH\""));
        assert!(text.contains("version=\"9.6p1\""));
        assert!(text.contains("<hostname source=\"reversedns\">router.local</hostname>"));
        assert!(text.contains("mac=\"00:1b:63:11:22:33\""));
    }

    #[test]
    fn special_characters_are_escaped() {
        assert_eq!(escape("a & b"), "a &amp; b");
        assert_eq!(escape("<script>"), "&lt;script&gt;");
        assert_eq!(escape("say \"hi\""), "say &quot;hi&quot;");
        assert_eq!(escape("it's"), "it&apos;s");
    }

    #[test]
    fn hostile_banners_cannot_break_out_of_the_document() {
        let mut report = sample_report();
        report.hosts[0].ports[0].banner =
            Some("</banner></port></ports></host><evil/>".to_string());
        report.hosts[0].vendor = Some("\" onload=\"alert(1)".to_string());

        let text = render(&report);
        assert!(
            !text.contains("<evil/>"),
            "injected element survived:\n{text}"
        );
        assert_eq!(text.matches("</banner>").count(), 1);
        assert!(
            !text.contains("onload=\"alert"),
            "attribute injection survived"
        );
    }

    #[test]
    fn control_characters_are_replaced() {
        assert_eq!(escape("a\x00b\x1bc"), "a.b.c");
        assert_eq!(
            escape("keep\ttabs\nand\rnewlines"),
            "keep\ttabs\nand\rnewlines"
        );
    }

    #[test]
    fn stats_are_emitted_as_attributes() {
        let text = render(&sample_report());
        assert!(text.contains("hosts_total=\"2\""));
        assert!(text.contains("hosts_up=\"1\""));
        assert!(text.contains("ports_open=\"2\""));
    }

    #[test]
    fn an_empty_report_is_still_a_valid_document() {
        let text = render(&ScanReport::empty());
        assert!(text.contains("<hosts>"));
        assert!(text.contains("</netscan>"));
    }

    #[test]
    fn warnings_are_included() {
        let mut report = sample_report();
        report.warnings.push(crate::error::Warning::for_host(
            "test.code",
            "something & something",
            "10.0.0.1".parse().unwrap(),
        ));
        let text = render(&report);
        assert!(text.contains("code=\"test.code\""));
        assert!(text.contains("host=\"10.0.0.1\""));
        assert!(text.contains("something &amp; something"));
    }
}
