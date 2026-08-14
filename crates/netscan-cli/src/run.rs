use std::io::{IsTerminal, Write};
use std::path::Path;

use anyhow::{Context, Result};
use netscan_core::output::{Format, RenderOptions};
use netscan_core::{Engine, ScanConfig, ScanEvent, ScanOutcome, ScanReport};

use crate::cli::{Args, Verbosity};
use crate::progress::ProgressLine;

pub async fn scan(config: ScanConfig, args: &Args) -> Result<ScanReport> {
    let verbosity = args.verbosity();
    let show_hosts_live = verbosity != Verbosity::Quiet && !writes_to_stdout(args);

    let engine = Engine::new(config).map_err(anyhow::Error::from)?;
    if verbosity == Verbosity::Debug {
        eprintln!("netscan: {}", crate::config::describe(engine.config()));
        eprintln!("netscan: {} probes loaded", engine.registry().len());
    }

    let mut handle = engine.start();
    let mut progress = if args.no_progress || verbosity == Verbosity::Quiet {
        ProgressLine::disabled()
    } else {
        ProgressLine::new(true)
    };
    let cancel = handle.cancellation_token();

    tokio::spawn(async move {
        let mut interrupts = 0u8;
        loop {
            if tokio::signal::ctrl_c().await.is_err() {
                return;
            }
            interrupts += 1;
            if interrupts == 1 {
                eprintln!("\nnetscan: cancelling, finishing probes already in flight…");
                eprintln!("netscan: press Ctrl+C again to exit immediately.");
                cancel.cancel();
            } else {
                eprintln!("\nnetscan: exiting.");
                std::process::exit(130);
            }
        }
    });

    let mut report = None;
    let colour = use_colour(args);
    let mut first_progress = true;

    let mut many_hosts = false;

    while let Some(event) = handle.next_event().await {
        match event {
            ScanEvent::Started {
                hosts_total,
                ports_per_host,
                ..
            } => {
                many_hosts = hosts_total > 1;

                if !progress.is_enabled() && verbosity != Verbosity::Quiet {
                    eprintln!(
                        "netscan: scanning {hosts_total} host(s), {ports_per_host} port(s) each"
                    );
                }
            }
            ScanEvent::Progress(update) => {
                if std::mem::take(&mut first_progress) {
                    progress.force_update(&update);
                } else {
                    progress.update(&update);
                }
            }
            ScanEvent::Warning(warning) => {
                if verbosity != Verbosity::Quiet {
                    progress.note(&format!("netscan: {warning}"));
                }
            }
            ScanEvent::HostCompleted { host } => {
                if show_hosts_live && many_hosts && host.status == netscan_core::HostStatus::Up {
                    progress.clear();
                    println!(
                        "{}",
                        netscan_core::output::text::host_one_liner(&host, colour)
                    );
                    let _ = std::io::stdout().flush();
                }
            }
            ScanEvent::Finished { report: finished } => report = Some(*finished),
            _ => {}
        }
    }

    progress.finish();
    let report = match report {
        Some(report) => report,
        None => handle.finish().await.map_err(anyhow::Error::from)?,
    };

    Ok(report)
}

pub fn emit(report: &ScanReport, args: &Args) -> Result<()> {
    let options = render_options(args);

    if let Some(path) = &args.output {
        let format = output_format(args, Some(path));
        netscan_core::output::write_file(report, path, format, options)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("writing {}", path.display()))?;

        if args.verbosity() != Verbosity::Quiet {
            eprintln!(
                "netscan: wrote {} ({format}) — {} host(s), {} open port(s)",
                path.display(),
                report.stats.hosts_up,
                report.stats.ports_open
            );
        }

        if args.verbosity() != Verbosity::Quiet && !writes_to_stdout(args) {
            print!("{}", netscan_core::output::text::render(report, options));
        }
        return Ok(());
    }

    let format = output_format(args, None);
    let rendered =
        netscan_core::output::render(report, format, options).map_err(anyhow::Error::from)?;
    print!("{rendered}");
    let _ = std::io::stdout().flush();
    Ok(())
}

pub fn append_jsonl(report: &ScanReport, path: &Path) -> Result<()> {
    use std::io::Write as _;
    let text = netscan_core::output::jsonl::render(report).map_err(anyhow::Error::from)?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    file.write_all(text.as_bytes())
        .with_context(|| format!("appending to {}", path.display()))?;
    Ok(())
}

pub fn output_format(args: &Args, path: Option<&Path>) -> Format {
    if let Some(name) = &args.format {
        if let Ok(format) = name.parse() {
            return format;
        }
    }
    if args.json {
        return Format::Json;
    }
    if args.jsonl {
        return Format::Jsonl;
    }
    if args.csv {
        return Format::Csv;
    }
    if args.xml {
        return Format::Xml;
    }
    path.and_then(Format::from_path).unwrap_or(Format::Text)
}

pub fn writes_to_stdout(args: &Args) -> bool {
    args.output.is_none() && output_format(args, None).is_machine_readable()
}

fn use_colour(args: &Args) -> bool {
    if args.no_colour {
        return false;
    }
    if args.colour {
        return true;
    }

    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    std::io::stdout().is_terminal()
}

pub fn render_options(args: &Args) -> RenderOptions {
    let verbosity = args.verbosity();
    let verbose = matches!(verbosity, Verbosity::Verbose | Verbosity::Debug);
    RenderOptions {
        colour: use_colour(args),
        show_all_ports: args.show_all_ports || args.verbose >= 2,
        show_down_hosts: args.show_down || args.verbose >= 2,
        show_banners: verbose,
        show_reasons: args.verbose >= 2 || verbosity == Verbosity::Debug,
        table_style: table_style(args),
        width: terminal_width(),
    }
}

fn table_style(args: &Args) -> netscan_core::output::table::TableStyle {
    use netscan_core::output::table::TableStyle;
    match args.table.as_deref() {
        Some("rounded") => TableStyle::Rounded,
        Some("square") => TableStyle::Square,
        Some("ascii") => TableStyle::Ascii,
        Some("plain") => TableStyle::Plain,
        _ => TableStyle::detect(),
    }
}

fn terminal_width() -> Option<usize> {
    if !std::io::stdout().is_terminal() {
        return None;
    }
    std::env::var("COLUMNS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|width| *width >= 40)
        .or(Some(100))
}

pub fn exit_code(report: &ScanReport) -> i32 {
    match report.outcome {
        ScanOutcome::Completed => 0,
        ScanOutcome::Failed => 1,
        ScanOutcome::Cancelled => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn args(list: &[&str]) -> Args {
        let mut full = vec!["netscan", "--no-config"];
        full.extend_from_slice(list);
        Args::try_parse_from(full).unwrap()
    }

    #[test]
    fn the_format_flag_wins_over_the_extension() {
        let args = args(["--format", "csv", "-o", "out.json", "t"].as_ref());
        assert_eq!(
            output_format(&args, Some(Path::new("out.json"))),
            Format::Csv
        );
    }

    #[test]
    fn the_extension_is_used_when_no_format_is_given() {
        let args = args(["-o", "out.json", "t"].as_ref());
        assert_eq!(
            output_format(&args, Some(Path::new("out.json"))),
            Format::Json
        );
        assert_eq!(
            output_format(&args, Some(Path::new("out.csv"))),
            Format::Csv
        );
        assert_eq!(
            output_format(&args, Some(Path::new("out.xml"))),
            Format::Xml
        );
    }

    #[test]
    fn text_is_the_default() {
        assert_eq!(output_format(&args(&["t"]), None), Format::Text);
        assert_eq!(
            output_format(&args(&["-o", "out.log", "t"]), Some(Path::new("out.log"))),
            Format::Text
        );
    }

    #[test]
    fn shorthand_flags_select_their_format() {
        assert_eq!(output_format(&args(&["--json", "t"]), None), Format::Json);
        assert_eq!(output_format(&args(&["--jsonl", "t"]), None), Format::Jsonl);
        assert_eq!(output_format(&args(&["--csv", "t"]), None), Format::Csv);
        assert_eq!(output_format(&args(&["--xml", "t"]), None), Format::Xml);
    }

    #[test]
    fn machine_output_to_stdout_suppresses_everything_else() {
        assert!(writes_to_stdout(&args(&["--json", "t"])));
        assert!(
            !writes_to_stdout(&args(&["t"])),
            "text output is not machine readable"
        );
        assert!(
            !writes_to_stdout(&args(&["--json", "-o", "out.json", "t"])),
            "with a file, stdout is free for the summary"
        );
    }

    #[test]
    fn verbosity_controls_what_is_rendered() {
        let plain = render_options(&args(&["t"]));
        assert!(!plain.show_banners);
        assert!(!plain.show_down_hosts);

        let verbose = render_options(&args(&["-v", "t"]));
        assert!(verbose.show_banners);

        let very_verbose = render_options(&args(&["-vv", "t"]));
        assert!(very_verbose.show_all_ports);
        assert!(very_verbose.show_down_hosts);
        assert!(very_verbose.show_reasons);
    }

    #[test]
    fn explicit_display_flags_work_without_verbosity() {
        let options = render_options(&args(&["--show-down", "--show-all-ports", "t"]));
        assert!(options.show_down_hosts);
        assert!(options.show_all_ports);
    }

    #[test]
    fn colour_can_be_forced_off() {
        assert!(!render_options(&args(&["--no-colour", "t"])).colour);
    }

    #[test]
    fn exit_codes_distinguish_cancellation_from_failure() {
        let mut report = ScanReport::empty();
        assert_eq!(exit_code(&report), 0);

        report.outcome = ScanOutcome::Cancelled;
        assert_eq!(exit_code(&report), 2);

        report.outcome = ScanOutcome::Failed;
        assert_eq!(exit_code(&report), 1);
    }

    #[test]
    fn appending_jsonl_creates_and_grows_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("watch.jsonl");
        let report = ScanReport::empty();

        append_jsonl(&report, &path).unwrap();
        let first = std::fs::read_to_string(&path).unwrap();
        append_jsonl(&report, &path).unwrap();
        let second = std::fs::read_to_string(&path).unwrap();

        assert!(
            second.len() > first.len(),
            "the second append should add lines"
        );
        assert_eq!(second.lines().count(), first.lines().count() * 2);
    }
}
