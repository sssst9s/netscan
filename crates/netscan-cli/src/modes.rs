use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use netscan_core::compare::{compare, ScanDiff};
use netscan_core::inventory::Inventory;
use netscan_core::{ScanConfig, ScanReport};

use crate::cli::{Args, Verbosity};

pub fn run_compare(paths: &[PathBuf], args: &Args) -> Result<i32> {
    let previous = load_report(&paths[0])?;
    let current = load_report(&paths[1])?;
    let diff = compare(&previous, &current);

    if args.json || matches!(args.format.as_deref(), Some("json")) {
        let text = serde_json::to_string_pretty(&diff)?;
        println!("{text}");
    } else {
        print!(
            "{}",
            render_diff(&diff, args.verbosity() != Verbosity::Quiet)
        );
    }

    if let Some(path) = &args.output {
        let text = serde_json::to_string_pretty(&diff)?;
        std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
    }

    Ok(if diff.is_empty() { 0 } else { 3 })
}

pub fn load_report(path: &Path) -> Result<ScanReport> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    let looks_like_jsonl = path.extension().is_some_and(|e| e == "jsonl")
        || text.lines().filter(|l| !l.trim().is_empty()).count() > 1
            && text.trim_start().starts_with('{')
            && text
                .lines()
                .next()
                .is_some_and(|l| l.trim_end().ends_with('}'));

    let parsed = if looks_like_jsonl {
        netscan_core::output::jsonl::parse(&text)
            .or_else(|_| netscan_core::output::json::parse(&text))
    } else {
        netscan_core::output::json::parse(&text)
            .or_else(|_| netscan_core::output::jsonl::parse(&text))
    };

    parsed
        .map_err(anyhow::Error::from)
        .with_context(|| format!("{} is not a netscan report", path.display()))
}

pub fn render_diff(diff: &ScanDiff, verbose: bool) -> String {
    use std::fmt::Write;
    let mut out = String::new();

    if !diff.comparable {
        out.push_str("These scans are not directly comparable:\n");
        for note in &diff.comparability_notes {
            let _ = writeln!(out, "  - {note}");
        }
        out.push_str("Only changes that both scans actually measured are reported below.\n\n");
    }

    if diff.is_empty() {
        out.push_str("No changes.\n");
        return out;
    }

    if !diff.new_hosts.is_empty() {
        let _ = writeln!(out, "New hosts ({})", diff.new_hosts.len());
        for host in &diff.new_hosts {
            let name = host.hostname.as_deref().unwrap_or("");
            let ports = if host.open_ports.is_empty() {
                "no open ports".to_string()
            } else {
                host.open_ports.join(", ")
            };
            let _ = writeln!(out, "  + {} {name}  {ports}", host.address);
        }
        out.push('\n');
    }

    if !diff.removed_hosts.is_empty() {
        let _ = writeln!(
            out,
            "Hosts no longer responding ({})",
            diff.removed_hosts.len()
        );
        for host in &diff.removed_hosts {
            let _ = writeln!(
                out,
                "  - {} {}",
                host.address,
                host.hostname.as_deref().unwrap_or("")
            );
        }
        out.push('\n');
    }

    if !diff.opened_ports.is_empty() {
        let _ = writeln!(out, "Newly open ports ({})", diff.opened_ports.len());
        for port in &diff.opened_ports {
            let service = port.service.as_deref().unwrap_or("");
            let _ = writeln!(out, "  + {}  {service}", port.label());
        }
        out.push('\n');
    }

    if !diff.closed_ports.is_empty() {
        let _ = writeln!(out, "Ports no longer open ({})", diff.closed_ports.len());
        for port in &diff.closed_ports {
            let _ = writeln!(out, "  - {}  (now {})", port.label(), port.current_state);
        }
        out.push('\n');
    }

    if !diff.changed_services.is_empty() {
        let _ = writeln!(out, "Service changes ({})", diff.changed_services.len());
        for change in &diff.changed_services {
            let marker = if change.version_only { "~" } else { "!" };
            let _ = writeln!(
                out,
                "  {marker} {} {}/{}  {} -> {}",
                change.address, change.port, change.transport, change.previous, change.current
            );
        }
        out.push('\n');
    }

    if !diff.changed_os.is_empty() {
        let _ = writeln!(out, "OS inference changes ({})", diff.changed_os.len());
        for change in &diff.changed_os {
            let _ = writeln!(
                out,
                "  ~ {}  {} -> {}",
                change.address, change.previous, change.current
            );
        }
        out.push('\n');
    }

    if verbose && !diff.changed_states.is_empty() {
        let _ = writeln!(
            out,
            "Other port state changes ({})",
            diff.changed_states.len()
        );
        for port in &diff.changed_states {
            let _ = writeln!(
                out,
                "  ~ {}  {} -> {}",
                port.label(),
                port.previous_state,
                port.current_state
            );
        }
        out.push('\n');
    }

    let _ = writeln!(out, "{}", diff.summary());
    out
}

pub fn parse_interval(text: &str) -> Result<Duration> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        bail!("--watch needs an interval, for example 30s, 5m or 1h");
    }

    let (number, unit) = trimmed.split_at(
        trimmed
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(trimmed.len()),
    );
    if number.is_empty() {
        bail!("`{text}` is not an interval; try 30s, 5m or 1h");
    }
    let value: u64 = number.parse().context("interval is not a number")?;

    let seconds = match unit.trim() {
        "" | "s" | "sec" | "secs" | "second" | "seconds" => value,
        "m" | "min" | "mins" | "minute" | "minutes" => value * 60,
        "h" | "hr" | "hrs" | "hour" | "hours" => value * 3600,
        "d" | "day" | "days" => value * 86_400,
        other => bail!("unknown interval unit `{other}`; use s, m, h or d"),
    };

    if seconds == 0 {
        bail!("--watch interval must be greater than zero");
    }
    Ok(Duration::from_secs(seconds))
}

pub async fn run_watch(config: ScanConfig, args: &Args) -> Result<i32> {
    let interval = parse_interval(args.watch.as_deref().unwrap_or("5m"))?;
    let quiet = args.verbosity() == Verbosity::Quiet;
    let mut previous: Option<ScanReport> = None;
    let mut round = 0u32;
    let mut changes_seen = false;

    if !quiet {
        eprintln!(
            "netscan: watching {} every {}. Press Ctrl+C to stop.",
            config
                .targets
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            crate::progress::HumanDuration(interval)
        );
    }

    loop {
        round += 1;
        let started = chrono::Utc::now();
        let report = crate::run::scan(config.clone(), args).await?;

        if let Some(path) = &args.output {
            crate::run::append_jsonl(&report, path)?;
        }
        if let Some(path) = &args.inventory {
            update_inventory(&report, path)?;
        }

        match &previous {
            None => {
                if !quiet {
                    eprintln!(
                        "netscan: round {round} at {} — baseline: {} host(s) up, {} open port(s)",
                        started.format("%H:%M:%S"),
                        report.stats.hosts_up,
                        report.stats.ports_open
                    );
                }
            }
            Some(previous) => {
                let diff = compare(previous, &report);
                if diff.is_empty() {
                    if !quiet {
                        eprintln!(
                            "netscan: round {round} at {} — no changes",
                            started.format("%H:%M:%S")
                        );
                    }
                } else {
                    changes_seen = true;
                    println!(
                        "--- {} round {round}: {} ---",
                        started.format("%Y-%m-%d %H:%M:%S"),
                        diff.summary()
                    );
                    print!("{}", render_diff(&diff, false));
                }
            }
        }

        previous = Some(report);

        if let Some(limit) = args.watch_rounds {
            if round >= limit {
                break;
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = tokio::signal::ctrl_c() => {
                if !quiet {
                    eprintln!("\nnetscan: stopping.");
                }
                break;
            }
        }
    }

    Ok(if changes_seen { 3 } else { 0 })
}

pub fn update_inventory(report: &ScanReport, path: &Path) -> Result<Inventory> {
    let mut inventory = if path.exists() {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Inventory::from_json(&text)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("{} is not a netscan inventory", path.display()))?
    } else {
        Inventory::new()
    };

    inventory.merge(report);

    let rendered = if path.extension().is_some_and(|e| e == "csv") {
        inventory.to_csv().map_err(anyhow::Error::from)?
    } else {
        inventory.to_json().map_err(anyhow::Error::from)?
    };
    std::fs::write(path, rendered).with_context(|| format!("writing {}", path.display()))?;

    Ok(inventory)
}

pub fn list_profiles(registry: &netscan_core::ProfileRegistry) {
    println!("Available scan profiles:\n");
    let width = registry.names().iter().map(|n| n.len()).max().unwrap_or(8);
    for profile in registry.iter() {
        println!("  {:<width$}  {}", profile.name, profile.description);
    }
    println!("\nUse one with --profile <NAME>. Define your own under [profiles.<name>]");
    println!("in netscan.toml; see CONFIGURATION.md.");
}

pub fn list_probes(config: &ScanConfig) -> Result<()> {
    let mut registry =
        netscan_core::scanner::probe::ProbeRegistry::builtin().map_err(anyhow::Error::from)?;
    for path in &config.detection.probe_files {
        registry.load_file(path).map_err(anyhow::Error::from)?;
    }

    println!("Loaded service probes ({}):\n", registry.len());
    println!(
        "  {:<18}  {:<9}  {:<5}  PORTS",
        "NAME", "TRANSPORT", "LEVEL"
    );
    let mut probes: Vec<_> = registry.iter().collect();
    probes.sort_by_key(|p| (p.transport(), p.name().to_string()));
    for probe in probes {
        let ports = if probe.ports().is_empty() {
            "any".to_string()
        } else {
            let shown: Vec<String> = probe.ports().iter().take(8).map(u16::to_string).collect();
            if probe.ports().len() > 8 {
                format!("{}, +{}", shown.join(", "), probe.ports().len() - 8)
            } else {
                shown.join(", ")
            }
        };
        println!(
            "  {:<18}  {:<9}  {:<5}  {ports}",
            probe.name(),
            probe.transport(),
            probe.intrusiveness()
        );
    }
    println!("\nLEVEL is intrusiveness: 0 reads a banner, higher levels send more.");
    println!("Cap it with --max-intrusiveness, and add your own with --probe-file.");
    Ok(())
}

pub fn list_interfaces() -> Result<()> {
    let interfaces = netscan_core::interfaces::list().map_err(anyhow::Error::from)?;
    println!("Local network interfaces:\n");
    for interface in &interfaces {
        let flags = if interface.is_loopback {
            " (loopback)"
        } else {
            ""
        };
        println!("  {}{flags}", interface.name);
        for address in &interface.addresses {
            match address.network {
                Some(network) => println!("      {}  in {network}", address.address),
                None => println!("      {}", address.address),
            }
        }
    }

    let local = netscan_core::interfaces::local_networks().map_err(anyhow::Error::from)?;
    if local.is_empty() {
        println!("\n--local would find no networks to scan on this machine.");
    } else {
        let names: Vec<String> = local.iter().map(ToString::to_string).collect();
        println!("\n--local would scan: {}", names.join(", "));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use netscan_core::scanner::result::{
        HostReport, HostStatus, PortReason, PortReport, PortState,
    };
    use netscan_core::Transport;

    fn report_with_open(address: &str, port: u16) -> ScanReport {
        let mut report = ScanReport::empty();
        report.parameters.targets = vec!["10.0.0.0/24".to_string()];
        report.parameters.ports = "22".to_string();
        let mut host = HostReport::new(address.parse().unwrap());
        host.status = HostStatus::Up;
        host.ports.push(PortReport::new(
            port,
            Transport::Tcp,
            PortState::Open,
            PortReason::ConnectionEstablished,
        ));
        report.hosts.push(host);
        report.recompute_stats();
        report
    }

    #[test]
    fn intervals_parse_in_every_unit() {
        assert_eq!(parse_interval("30").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_interval("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_interval("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_interval("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_interval("1d").unwrap(), Duration::from_secs(86_400));
        assert_eq!(
            parse_interval(" 10 minutes ").unwrap(),
            Duration::from_secs(600)
        );
    }

    #[test]
    fn bad_intervals_explain_the_format() {
        for bad in ["", "  ", "soon", "5x", "0s"] {
            let err = parse_interval(bad).unwrap_err().to_string();
            assert!(!err.is_empty(), "{bad:?} should be rejected");
        }
        assert!(parse_interval("abc")
            .unwrap_err()
            .to_string()
            .contains("30s"));
        assert!(parse_interval("5x")
            .unwrap_err()
            .to_string()
            .contains("use s, m, h or d"));
    }

    #[test]
    fn reports_round_trip_through_json_and_jsonl_files() {
        let dir = tempfile::tempdir().unwrap();
        let report = report_with_open("10.0.0.1", 22);

        let json_path = dir.path().join("scan.json");
        std::fs::write(
            &json_path,
            netscan_core::output::json::render(&report).unwrap(),
        )
        .unwrap();
        assert_eq!(load_report(&json_path).unwrap().hosts.len(), 1);

        let jsonl_path = dir.path().join("scan.jsonl");
        std::fs::write(
            &jsonl_path,
            netscan_core::output::jsonl::render(&report).unwrap(),
        )
        .unwrap();
        assert_eq!(load_report(&jsonl_path).unwrap().hosts.len(), 1);
    }

    #[test]
    fn loading_a_non_report_says_so_with_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notes.json");
        std::fs::write(&path, "{\"hello\": true}").unwrap();
        let err = format!("{:#}", load_report(&path).unwrap_err());
        assert!(err.contains("notes.json"), "message was: {err}");
    }

    #[test]
    fn an_unchanged_diff_renders_as_no_changes() {
        let a = report_with_open("10.0.0.1", 22);
        let b = report_with_open("10.0.0.1", 22);
        let text = render_diff(&compare(&a, &b), false);
        assert_eq!(text.trim(), "No changes.");
    }

    #[test]
    fn a_diff_names_what_changed() {
        let a = report_with_open("10.0.0.1", 22);
        let b = report_with_open("10.0.0.2", 22);
        let text = render_diff(&compare(&a, &b), false);
        assert!(text.contains("New hosts (1)"), "output was:\n{text}");
        assert!(text.contains("+ 10.0.0.2"), "output was:\n{text}");
        assert!(
            text.contains("Hosts no longer responding (1)"),
            "output was:\n{text}"
        );
        assert!(text.contains("- 10.0.0.1"), "output was:\n{text}");
    }

    #[test]
    fn incomparable_scans_are_flagged_before_the_changes() {
        let a = report_with_open("10.0.0.1", 22);
        let mut b = report_with_open("10.0.0.1", 22);
        b.parameters.ports = "1-1000".to_string();

        let text = render_diff(&compare(&a, &b), false);
        assert!(
            text.starts_with("These scans are not directly comparable"),
            "output was:\n{text}"
        );
        assert!(text.contains("port selections differ"));
    }

    #[test]
    fn an_inventory_is_created_then_merged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inventory.json");

        let inventory = update_inventory(&report_with_open("10.0.0.1", 22), &path).unwrap();
        assert_eq!(inventory.len(), 1);
        assert!(path.exists());

        let inventory = update_inventory(&report_with_open("10.0.0.2", 80), &path).unwrap();
        assert_eq!(
            inventory.len(),
            2,
            "the second scan should merge, not replace"
        );
    }

    #[test]
    fn an_inventory_can_be_written_as_csv() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inventory.csv");
        update_inventory(&report_with_open("10.0.0.1", 22), &path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("address,hostname"));
    }

    #[test]
    fn a_corrupt_inventory_is_reported_rather_than_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inventory.json");
        std::fs::write(&path, "not an inventory").unwrap();

        let err = format!(
            "{:#}",
            update_inventory(&report_with_open("10.0.0.1", 22), &path).unwrap_err()
        );
        assert!(err.contains("inventory.json"), "message was: {err}");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "not an inventory",
            "a file that could not be read must not be clobbered"
        );
    }
}
