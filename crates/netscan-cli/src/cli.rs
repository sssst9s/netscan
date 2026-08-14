use std::path::PathBuf;

use clap::{ArgAction, Parser, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "netscan",
    version,
    about = "A fast, modern network scanner and analyser",
    long_about = None,
    after_help = EXAMPLES,
    max_term_width = 100,
)]
pub struct Args {
    #[arg(value_name = "TARGET")]
    pub targets: Vec<String>,
    #[arg(short = 'f', long = "targets-file", value_name = "FILE")]
    pub targets_file: Option<PathBuf>,
    #[arg(long)]
    pub local: bool,
    #[arg(long, value_name = "SPEC", action = ArgAction::Append)]
    pub exclude: Vec<String>,
    #[arg(long, value_name = "FILE")]
    pub exclude_file: Option<PathBuf>,
    #[arg(short = 'p', long = "ports", value_name = "SPEC")]
    pub ports: Option<String>,
    #[arg(long, value_name = "N", conflicts_with = "ports")]
    pub top_ports: Option<usize>,
    #[arg(long, value_name = "NAME", conflicts_with_all = ["ports", "top_ports"])]
    pub preset: Option<String>,
    #[arg(long, conflicts_with_all = ["ports", "top_ports", "preset"])]
    pub common: bool,
    #[arg(long, conflicts_with_all = ["ports", "top_ports", "preset", "common"])]
    pub web: bool,
    #[arg(long, conflicts_with_all = ["ports", "top_ports", "preset", "common", "web"])]
    pub database: bool,
    #[arg(
        long = "remote-access",
        conflicts_with_all = ["ports", "top_ports", "preset", "common", "web", "database"]
    )]
    pub remote_access: bool,
    #[arg(long)]
    pub tcp: bool,
    #[arg(long)]
    pub udp: bool,
    #[arg(long, conflicts_with = "connect")]
    pub syn: bool,
    #[arg(long)]
    pub connect: bool,
    #[arg(long)]
    pub ping: bool,
    #[arg(
        short = 's',
        long = "service-detection",
        visible_alias = "sV",
        alias = "sv"
    )]
    pub service_detection: bool,
    #[arg(long = "os-detection", visible_alias = "os")]
    pub os_detection: bool,
    #[arg(long)]
    pub tls: bool,
    #[arg(long)]
    pub no_banner: bool,
    #[arg(long, value_name = "LEVEL", value_parser = clap::value_parser!(u8).range(0..=9))]
    pub max_intrusiveness: Option<u8>,
    #[arg(long, value_name = "FILE", action = ArgAction::Append)]
    pub probe_file: Vec<PathBuf>,
    #[arg(short = 'P', long = "no-discovery", visible_alias = "Pn")]
    pub no_discovery: bool,
    #[arg(long)]
    pub no_icmp: bool,
    #[arg(long)]
    pub no_tcp_ping: bool,
    #[arg(long, value_name = "PORTS")]
    pub ping_ports: Option<String>,
    #[arg(short = 'T', long, value_name = "TEMPLATE")]
    pub timing: Option<String>,
    #[arg(short = 'c', long, value_name = "N")]
    pub concurrency: Option<usize>,
    #[arg(long, value_name = "MS")]
    pub timeout: Option<u64>,
    #[arg(short = 'r', long, value_name = "N")]
    pub retries: Option<u8>,
    #[arg(long, value_name = "N")]
    pub max_rate: Option<u32>,
    #[arg(long, value_name = "MS")]
    pub scan_delay: Option<u64>,
    #[arg(long, value_name = "MS")]
    pub host_timeout: Option<u64>,
    #[arg(long)]
    pub no_adaptive: bool,
    #[arg(short = '4', long = "ipv4", conflicts_with_all = ["ipv6", "both_families"])]
    pub ipv4: bool,
    #[arg(short = '6', long = "ipv6", conflicts_with = "both_families")]
    pub ipv6: bool,
    #[arg(long = "both")]
    pub both_families: bool,
    #[arg(short = 'e', long, value_name = "NAME")]
    pub interface: Option<String>,
    #[arg(long)]
    pub include_network_addresses: bool,
    #[arg(short = 'n', long = "no-dns")]
    pub no_dns: bool,
    #[arg(long, value_name = "ADDRESS", action = ArgAction::Append)]
    pub dns_server: Vec<String>,
    #[arg(long, value_name = "FORMAT", conflicts_with_all = ["json", "jsonl", "csv", "xml"])]
    pub format: Option<String>,
    #[arg(long)]
    pub json: bool,
    #[arg(long)]
    pub jsonl: bool,
    #[arg(long)]
    pub csv: bool,
    #[arg(long)]
    pub xml: bool,
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: Option<PathBuf>,
    #[arg(long)]
    pub show_down: bool,
    #[arg(long)]
    pub show_all_ports: bool,
    #[arg(short = 'v', long, action = ArgAction::Count)]
    pub verbose: u8,
    #[arg(short = 'q', long, conflicts_with = "verbose")]
    pub quiet: bool,
    #[arg(long)]
    pub debug: bool,
    #[arg(long, value_name = "STYLE", value_parser = ["auto", "rounded", "square", "ascii", "plain"])]
    pub table: Option<String>,
    #[arg(long, visible_alias = "no-color")]
    pub no_colour: bool,
    #[arg(long, visible_alias = "color", conflicts_with = "no_colour")]
    pub colour: bool,
    #[arg(long)]
    pub no_progress: bool,
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,
    #[arg(long, value_name = "FILE", env = "NETSCAN_CONFIG")]
    pub config: Option<PathBuf>,
    #[arg(long, conflicts_with = "config")]
    pub no_config: bool,
    #[arg(long, value_names = ["PREVIOUS", "CURRENT"], num_args = 2)]
    pub compare: Option<Vec<PathBuf>>,
    #[arg(long, value_name = "INTERVAL")]
    pub watch: Option<String>,
    #[arg(long, value_name = "N", requires = "watch")]
    pub watch_rounds: Option<u32>,
    #[arg(long, value_name = "FILE")]
    pub inventory: Option<PathBuf>,
    #[arg(long)]
    pub list_profiles: bool,
    #[arg(long)]
    pub list_probes: bool,
    #[arg(long)]
    pub list_interfaces: bool,
    #[arg(long, value_name = "N")]
    pub max_targets: Option<u64>,
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Verbosity {
    Quiet,
    Normal,
    Verbose,
    Debug,
}

impl Args {
    pub fn verbosity(&self) -> Verbosity {
        if self.debug {
            Verbosity::Debug
        } else if self.quiet {
            Verbosity::Quiet
        } else if self.verbose > 0 {
            Verbosity::Verbose
        } else {
            Verbosity::Normal
        }
    }

    pub fn is_informational(&self) -> bool {
        self.list_profiles || self.list_probes || self.list_interfaces || self.compare.is_some()
    }

    pub fn needs_targets(&self) -> bool {
        !self.is_informational() && !self.local && self.targets_file.is_none()
    }
}

const EXAMPLES: &str = "\
EXAMPLES:
  netscan 192.168.1.1                     scan one host's top 100 ports
  netscan 192.168.1.0/24                  scan a whole network
  netscan example.com -p 22,80,443        scan named ports on a host
  netscan -p 1-1024 10.0.0.1              scan a port range
  netscan --top-ports 1000 -sV target     top 1000 ports, with service detection
  netscan --profile full 192.168.1.0/24   use a named profile
  netscan --udp -p 53,161 target          scan UDP ports
  netscan --local --os-detection          inventory the network you are on
  netscan --json -o scan.json target      save machine-readable results
  netscan --compare before.json after.json  report what changed
  netscan --watch 5m 192.168.1.0/24       re-scan every five minutes

AUTHORISED USE:
  Scanning systems you do not own or have permission to test may be unlawful.
  See SECURITY.md.
";

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Args {
        let mut full = vec!["netscan"];
        full.extend_from_slice(args);
        Args::try_parse_from(full).unwrap_or_else(|e| panic!("failed to parse {args:?}: {e}"))
    }

    fn parse_err(args: &[&str]) -> String {
        let mut full = vec!["netscan"];
        full.extend_from_slice(args);
        Args::try_parse_from(full)
            .expect_err("expected a parse error")
            .to_string()
    }

    #[test]
    fn the_definition_is_internally_consistent() {
        Args::command().debug_assert();
    }

    #[test]
    fn a_bare_target_parses() {
        let args = parse(&["192.168.1.1"]);
        assert_eq!(args.targets, vec!["192.168.1.1".to_string()]);
        assert!(args.needs_targets());
    }

    #[test]
    fn multiple_targets_parse() {
        let args = parse(&["10.0.0.1", "10.0.0.2", "example.com"]);
        assert_eq!(args.targets.len(), 3);
    }

    #[test]
    fn port_flags_parse() {
        assert_eq!(parse(&["-p", "22,80", "t"]).ports.as_deref(), Some("22,80"));
        assert_eq!(
            parse(&["--ports", "1-1024", "t"]).ports.as_deref(),
            Some("1-1024")
        );
        assert_eq!(parse(&["--top-ports", "1000", "t"]).top_ports, Some(1000));
    }

    #[test]
    fn port_selection_flags_are_mutually_exclusive() {
        let err = parse_err(&["-p", "80", "--top-ports", "100", "t"]);
        assert!(err.contains("cannot be used with"), "error was: {err}");
    }

    #[test]
    fn preset_shorthands_parse() {
        assert!(parse(&["--web", "t"]).web);
        assert!(parse(&["--database", "t"]).database);
        assert!(parse(&["--remote-access", "t"]).remote_access);
        assert_eq!(
            parse(&["--preset", "mail", "t"]).preset.as_deref(),
            Some("mail")
        );
    }

    #[test]
    fn nmap_style_spellings_are_accepted() {
        assert!(parse(&["--sV", "t"]).service_detection);
        assert!(parse(&["--sv", "t"]).service_detection);
        assert!(parse(&["-s", "t"]).service_detection);
        assert!(parse(&["-Pn", "t"]).no_discovery);
        assert!(parse(&["--Pn", "t"]).no_discovery);
        assert!(parse(&["-6", "t"]).ipv6);
        assert!(parse(&["-n", "t"]).no_dns);
        assert_eq!(
            parse(&["-T", "aggressive", "t"]).timing.as_deref(),
            Some("aggressive")
        );
    }

    #[test]
    fn timing_takes_a_name_not_a_number() {
        let args = parse(&["--timing", "sneaky", "t"]);
        assert_eq!(args.timing.as_deref(), Some("sneaky"));
    }

    #[test]
    fn scan_mode_flags_parse() {
        assert!(parse(&["--udp", "t"]).udp);
        assert!(parse(&["--syn", "t"]).syn);
        assert!(parse(&["--ping", "t"]).ping);
        let err = parse_err(&["--syn", "--connect", "t"]);
        assert!(err.contains("cannot be used with"));
    }

    #[test]
    fn output_format_shorthands_conflict_with_the_long_form() {
        assert!(parse(&["--json", "t"]).json);
        assert_eq!(
            parse(&["--format", "csv", "t"]).format.as_deref(),
            Some("csv")
        );
        let err = parse_err(&["--json", "--format", "csv", "t"]);
        assert!(err.contains("cannot be used with"));
    }

    #[test]
    fn verbosity_is_derived_from_the_flags() {
        assert_eq!(parse(&["t"]).verbosity(), Verbosity::Normal);
        assert_eq!(parse(&["-v", "t"]).verbosity(), Verbosity::Verbose);
        assert_eq!(parse(&["-q", "t"]).verbosity(), Verbosity::Quiet);
        assert_eq!(parse(&["--debug", "t"]).verbosity(), Verbosity::Debug);
    }

    #[test]
    fn quiet_and_verbose_conflict() {
        let err = parse_err(&["-q", "-v", "t"]);
        assert!(err.contains("cannot be used with"));
    }

    #[test]
    fn compare_takes_exactly_two_files() {
        let args = parse(&["--compare", "a.json", "b.json"]);
        assert_eq!(args.compare.as_ref().unwrap().len(), 2);
        assert!(args.is_informational());
        assert!(!args.needs_targets());

        assert!(!parse_err(&["--compare", "only-one.json"]).is_empty());
    }

    #[test]
    fn watch_rounds_requires_watch() {
        assert!(parse(&["--watch", "5m", "--watch-rounds", "3", "t"]).watch_rounds == Some(3));
        let err = parse_err(&["--watch-rounds", "3", "t"]);
        assert!(err.contains("--watch"), "error was: {err}");
    }

    #[test]
    fn listing_modes_do_not_need_targets() {
        for flag in ["--list-profiles", "--list-probes", "--list-interfaces"] {
            let args = parse(&[flag]);
            assert!(args.is_informational(), "{flag} should be informational");
            assert!(!args.needs_targets());
        }
    }

    #[test]
    fn local_does_not_need_targets() {
        assert!(!parse(&["--local"]).needs_targets());
    }

    #[test]
    fn intrusiveness_is_range_checked() {
        assert_eq!(
            parse(&["--max-intrusiveness", "0", "t"]).max_intrusiveness,
            Some(0)
        );
        assert_eq!(
            parse(&["--max-intrusiveness", "9", "t"]).max_intrusiveness,
            Some(9)
        );
        let err = parse_err(&["--max-intrusiveness", "10", "t"]);
        assert!(err.contains("10"), "error was: {err}");
    }

    #[test]
    fn repeatable_flags_accumulate() {
        let args = parse(&["--exclude", "10.0.0.1", "--exclude", "10.0.0.2", "t"]);
        assert_eq!(args.exclude.len(), 2);

        let args = parse(&["--probe-file", "a.toml", "--probe-file", "b.toml", "t"]);
        assert_eq!(args.probe_file.len(), 2);
    }

    #[test]
    fn address_family_flags_conflict() {
        assert!(!parse_err(&["-4", "-6", "t"]).is_empty());
        assert!(!parse_err(&["-6", "--both", "t"]).is_empty());
        assert!(parse(&["--both", "t"]).both_families);
    }

    #[test]
    fn the_table_style_is_validated() {
        assert_eq!(
            parse(&["--table", "ascii", "t"]).table.as_deref(),
            Some("ascii")
        );
        assert_eq!(
            parse(&["--table", "plain", "t"]).table.as_deref(),
            Some("plain")
        );
        assert_eq!(parse(&["t"]).table, None, "auto by default");
        assert!(!parse_err(&["--table", "fancy", "t"]).is_empty());
    }

    #[test]
    fn colour_flags_conflict() {
        assert!(!parse_err(&["--colour", "--no-colour", "t"]).is_empty());

        assert!(parse(&["--color", "t"]).colour);
        assert!(parse(&["--no-color", "t"]).no_colour);
    }

    #[test]
    fn help_mentions_authorised_use() {
        let help = Args::command().render_long_help().to_string();
        assert!(
            help.contains("AUTHORISED USE"),
            "the help must carry the notice"
        );
        assert!(help.contains("EXAMPLES"));
    }
}
