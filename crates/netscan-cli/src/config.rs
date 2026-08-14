use std::time::Duration;

use anyhow::{bail, Context, Result};
use netscan_core::config::{ConfigFile, DetectionConfig, DiscoveryConfig, DnsConfig, Limits};
use netscan_core::profiles::{PortSelector, ProfileRegistry};
use netscan_core::scanner::target::{parse_targets_file, TargetSpec};
use netscan_core::{
    IpFamily, PortSelection, PortSpec, ScanConfig, TcpScanMode, TimingTemplate, Transport,
};

use crate::cli::Args;

#[derive(Debug)]
pub struct Resolved {
    pub config: ScanConfig,
    pub registry: ProfileRegistry,
    pub config_path: Option<std::path::PathBuf>,
}

pub fn resolve_for_listing(args: &Args) -> Result<Resolved> {
    match resolve(args) {
        Ok(resolved) => Ok(resolved),
        Err(_) => {
            let (config_file, config_path) = load_config_file(args)?;
            let registry = config_file.registry();
            let mut config = ScanConfig::default();
            if let Some(limits) = &config_file.limits {
                config.limits = limits.clone();
            }
            config_file.defaults.apply(&mut config).ok();
            config.profile_name = None;
            apply_detection(args, &mut config);
            Ok(Resolved {
                config,
                registry,
                config_path,
            })
        }
    }
}

pub fn resolve(args: &Args) -> Result<Resolved> {
    let (config_file, config_path) = load_config_file(args)?;
    let registry = config_file.registry();

    let mut config = ScanConfig::default();
    if let Some(limits) = &config_file.limits {
        config.limits = limits.clone();
    }
    config_file
        .defaults
        .apply(&mut config)
        .context("applying [defaults] from the configuration file")?;

    config.profile_name = None;

    let profile_name = args
        .profile
        .clone()
        .or_else(|| config_file.default_profile.clone());
    if let Some(name) = &profile_name {
        registry
            .get(name)
            .map_err(anyhow::Error::from)?
            .apply(&mut config)
            .with_context(|| format!("applying profile `{name}`"))?;
    }

    apply_targets(args, &mut config)?;
    apply_ports(args, &mut config)?;
    apply_modes(args, &mut config);
    apply_detection(args, &mut config);
    apply_discovery(args, &mut config)?;
    apply_timing(args, &mut config)?;
    apply_addressing(args, &mut config)?;
    apply_dns(args, &mut config)?;
    apply_limits(args, &mut config);

    config.validate().map_err(anyhow::Error::from)?;
    check_scale(&config)?;
    Ok(Resolved {
        config,
        registry,
        config_path,
    })
}

fn check_scale(config: &ScanConfig) -> Result<()> {
    let resolver = netscan_core::scanner::target::TargetResolver {
        max_targets: config.limits.max_targets,
        family: config.family,
        include_network_addresses: config.include_network_addresses,
        exclusions: Vec::new(),
    };
    resolver
        .check_limit(&config.targets)
        .map_err(anyhow::Error::from)?;

    let estimate = resolver.estimate(&config.targets);
    config
        .check_probe_budget(estimate)
        .map_err(anyhow::Error::from)?;
    Ok(())
}

fn load_config_file(args: &Args) -> Result<(ConfigFile, Option<std::path::PathBuf>)> {
    if args.no_config {
        return Ok((ConfigFile::default(), None));
    }
    if let Some(path) = &args.config {
        let file = ConfigFile::load(path)
            .with_context(|| format!("reading configuration from {}", path.display()))?;
        return Ok((file, Some(path.clone())));
    }
    match ConfigFile::discover().map_err(anyhow::Error::from)? {
        Some((path, file)) => Ok((file, Some(path))),
        None => Ok((ConfigFile::default(), None)),
    }
}

fn apply_targets(args: &Args, config: &mut ScanConfig) -> Result<()> {
    let mut targets: Vec<TargetSpec> = Vec::new();

    for text in &args.targets {
        targets.push(text.parse().map_err(anyhow::Error::from)?);
    }

    if let Some(path) = &args.targets_file {
        let contents =
            read_input(path).with_context(|| format!("reading targets from {}", path.display()))?;
        targets.extend(parse_targets_file(&contents).map_err(anyhow::Error::from)?);
    }

    if args.local {
        let networks = netscan_core::interfaces::local_networks().map_err(anyhow::Error::from)?;
        if networks.is_empty() {
            bail!(
                "--local found no directly attached networks to scan. \
                 List interfaces with --list-interfaces."
            );
        }
        for network in networks {
            targets.push(TargetSpec::Cidr { net: network });
        }
    }

    if !targets.is_empty() {
        config.targets = targets;
    }

    let mut exclusions: Vec<TargetSpec> = Vec::new();
    for text in &args.exclude {
        exclusions.push(text.parse().map_err(anyhow::Error::from)?);
    }
    if let Some(path) = &args.exclude_file {
        let contents = read_input(path)
            .with_context(|| format!("reading exclusions from {}", path.display()))?;
        exclusions.extend(parse_targets_file(&contents).map_err(anyhow::Error::from)?);
    }
    if !exclusions.is_empty() {
        config.exclusions = exclusions;
    }

    Ok(())
}

fn read_input(path: &std::path::Path) -> Result<String> {
    if path.as_os_str() == "-" {
        use std::io::Read;
        let mut buffer = String::new();
        std::io::stdin().read_to_string(&mut buffer)?;
        Ok(buffer)
    } else {
        Ok(std::fs::read_to_string(path)?)
    }
}

fn apply_ports(args: &Args, config: &mut ScanConfig) -> Result<()> {
    let default_transport = if args.udp && !args.tcp {
        Transport::Udp
    } else {
        Transport::Tcp
    };

    let selector: Option<PortSelector> = if let Some(spec) = &args.ports {
        Some(PortSelector::Explicit(spec.clone()))
    } else if let Some(n) = args.top_ports {
        Some(PortSelector::Top(n))
    } else if let Some(name) = &args.preset {
        Some(PortSelector::Preset(
            name.parse().map_err(anyhow::Error::from)?,
        ))
    } else if args.common {
        Some(PortSelector::Preset(netscan_core::PortPreset::Common))
    } else if args.web {
        Some(PortSelector::Preset(netscan_core::PortPreset::Web))
    } else if args.database {
        Some(PortSelector::Preset(netscan_core::PortPreset::Database))
    } else if args.remote_access {
        Some(PortSelector::Preset(netscan_core::PortPreset::RemoteAccess))
    } else {
        None
    };

    if let Some(selector) = selector {
        if let PortSelector::Explicit(text) = &selector {
            PortSpec::parse(text, default_transport)
                .map_err(anyhow::Error::from)
                .context("parsing --ports")?;
        }
        config.ports = selector
            .resolve(default_transport)
            .map_err(anyhow::Error::from)?;
    } else if args.udp && config.ports.udp.is_empty() {
        config.ports.merge(&PortSelection::udp(
            netscan_core::detection::service::top_udp_ports(50),
        ));
    }

    Ok(())
}

fn apply_modes(args: &Args, config: &mut ScanConfig) {
    if args.tcp || args.udp {
        config.modes.tcp = args.tcp;
        config.modes.udp = args.udp;
    }
    if args.syn {
        config.modes.tcp_mode = TcpScanMode::Syn;
        config.modes.tcp = true;
    }
    if args.connect {
        config.modes.tcp_mode = TcpScanMode::Connect;
        config.modes.tcp = true;
    }
    if args.ping {
        config.discovery.discovery_only = true;
        config.discovery.enabled = true;
    }
}

fn apply_detection(args: &Args, config: &mut ScanConfig) {
    if args.service_detection {
        config.detection.service_detection = true;
        config.detection.version_detection = true;
        config.detection.banner_grab = true;
        config.detection.tls_inspection = true;
    }
    if args.os_detection {
        config.detection.os_fingerprint = true;

        config.detection.banner_grab = true;
    }
    if args.tls {
        config.detection.tls_inspection = true;
    }
    if args.no_banner {
        config.detection.banner_grab = false;
    }
    if let Some(level) = args.max_intrusiveness {
        config.detection.max_intrusiveness = level;
    }
    if !args.probe_file.is_empty() {
        config.detection.probe_files.clone_from(&args.probe_file);
    }
}

fn apply_discovery(args: &Args, config: &mut ScanConfig) -> Result<()> {
    if args.no_discovery {
        config.discovery.enabled = false;
    }
    if args.no_icmp {
        config.discovery.icmp_echo = false;
    }
    if args.no_tcp_ping {
        config.discovery.tcp_ping = false;
    }
    if let Some(spec) = &args.ping_ports {
        let ports = PortSpec::parse(spec, Transport::Tcp)
            .map_err(anyhow::Error::from)
            .context("parsing --ping-ports")?
            .resolve();
        if ports.tcp.is_empty() {
            bail!("--ping-ports selected no TCP ports");
        }
        config.discovery.tcp_ping_ports = ports.tcp.as_slice().to_vec();
    }
    if config.discovery.enabled && !config.discovery.icmp_echo && !config.discovery.tcp_ping {
        bail!(
            "host discovery is enabled but every discovery method is disabled; \
             use --no-discovery to scan every target regardless"
        );
    }
    Ok(())
}

fn apply_timing(args: &Args, config: &mut ScanConfig) -> Result<()> {
    if let Some(name) = &args.timing {
        let template: TimingTemplate = name.parse().map_err(anyhow::Error::from)?;
        config.timing = template.timing();
    }
    if let Some(concurrency) = args.concurrency {
        config.timing.concurrency = concurrency;
    }
    if let Some(ms) = args.timeout {
        config.timing.connect_timeout = Duration::from_millis(ms);
        config.timing.read_timeout = Duration::from_millis(ms.max(1_000));
    }
    if let Some(retries) = args.retries {
        config.timing.retries = retries;
    }
    if let Some(rate) = args.max_rate {
        config.timing.max_rate = Some(rate);
    }
    if let Some(ms) = args.scan_delay {
        config.timing.scan_delay = Duration::from_millis(ms);
    }
    if let Some(ms) = args.host_timeout {
        config.timing.host_timeout = Some(Duration::from_millis(ms));
    }
    if args.no_adaptive {
        config.timing.adaptive = false;
    }
    Ok(())
}

fn apply_addressing(args: &Args, config: &mut ScanConfig) -> Result<()> {
    if args.ipv6 {
        config.family = IpFamily::V6;
    } else if args.both_families {
        config.family = IpFamily::Both;
    } else if args.ipv4 {
        config.family = IpFamily::V4;
    }

    if let Some(name) = &args.interface {
        netscan_core::interfaces::find(name).map_err(anyhow::Error::from)?;
        config.interface = Some(name.clone());
    }

    config.include_network_addresses = args.include_network_addresses;
    Ok(())
}

fn apply_dns(args: &Args, config: &mut ScanConfig) -> Result<()> {
    if args.no_dns {
        config.dns.reverse_lookup = false;
    }
    if !args.dns_server.is_empty() {
        let mut servers = Vec::new();
        for text in &args.dns_server {
            servers.push(
                text.parse()
                    .with_context(|| format!("--dns-server {text} is not an IP address"))?,
            );
        }
        config.dns = DnsConfig {
            servers,
            ..config.dns.clone()
        };
    }
    Ok(())
}

fn apply_limits(args: &Args, config: &mut ScanConfig) {
    if let Some(max) = args.max_targets {
        config.limits.max_targets = max;
    }

    if args.yes {
        let permissive = Limits::permissive();
        config.limits.max_targets = config.limits.max_targets.max(permissive.max_targets);
        config.limits.max_total_probes = config
            .limits
            .max_total_probes
            .max(permissive.max_total_probes);
    }
}

pub fn describe(config: &ScanConfig) -> String {
    let detection = &config.detection;
    let discovery: &DiscoveryConfig = &config.discovery;
    let detection_summary: DetectionConfig = detection.clone();

    format!(
        "targets={:?} ports={} transports={:?} tcp_mode={} timing={} concurrency={} \
         timeout={:?} retries={} adaptive={} discovery={} service_detection={} os={} family={}",
        config
            .targets
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        config.ports,
        config.modes.transports(),
        config.modes.tcp_mode,
        config.timing.template,
        config.timing.concurrency,
        config.timing.connect_timeout,
        config.timing.retries,
        config.timing.adaptive,
        discovery.enabled,
        detection_summary.service_detection,
        detection_summary.os_fingerprint,
        config.family,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn args(list: &[&str]) -> Args {
        let mut full = vec!["netscan", "--no-config"];
        full.extend_from_slice(list);
        Args::try_parse_from(full).expect("arguments should parse")
    }

    fn config(list: &[&str]) -> ScanConfig {
        resolve(&args(list))
            .expect("configuration should resolve")
            .config
    }

    #[test]
    fn a_bare_target_gets_the_default_port_set() {
        let config = config(&["192.168.1.1"]);
        assert_eq!(config.targets.len(), 1);
        assert_eq!(config.ports.tcp.len(), 100);
        assert!(config.modes.tcp);
        assert!(!config.modes.udp);
    }

    #[test]
    fn explicit_ports_win() {
        let config = config(&["-p", "22,80,443", "t.example"]);
        assert_eq!(config.ports.tcp.as_slice(), &[22, 80, 443]);
    }

    #[test]
    fn top_ports_selects_from_the_ranked_dataset() {
        let config = config(&["--top-ports", "20", "t.example"]);
        assert_eq!(config.ports.tcp.len(), 20);
        assert!(config.ports.tcp.contains(80));
    }

    #[test]
    fn presets_select_their_ports() {
        let config = config(&["--web", "t.example"]);
        assert!(config.ports.tcp.contains(80));
        assert!(config.ports.tcp.contains(8443));
        assert!(
            !config.ports.tcp.contains(22),
            "the web preset should not include SSH"
        );
    }

    #[test]
    fn udp_only_scans_get_udp_ports_by_default() {
        let config = config(&["--udp", "t.example"]);
        assert!(config.modes.udp);
        assert!(!config.modes.tcp);
        assert!(
            !config.ports.udp.is_empty(),
            "a UDP scan must have UDP ports to scan"
        );
    }

    #[test]
    fn unprefixed_ports_follow_the_transport() {
        let config = config(&["--udp", "-p", "53,161", "t.example"]);
        assert_eq!(config.ports.udp.as_slice(), &[53, 161]);
        assert!(config.ports.tcp.is_empty());
    }

    #[test]
    fn transport_prefixes_still_work() {
        let config = config(&["--tcp", "--udp", "-p", "T:80,U:53", "t.example"]);
        assert_eq!(config.ports.tcp.as_slice(), &[80]);
        assert_eq!(config.ports.udp.as_slice(), &[53]);
    }

    #[test]
    fn service_detection_enables_the_stages_it_needs() {
        let config = config(&["--sV", "t.example"]);
        assert!(config.detection.service_detection);
        assert!(config.detection.version_detection);
        assert!(config.detection.banner_grab);
    }

    #[test]
    fn os_detection_implies_banner_grabbing() {
        let config = config(&["--os-detection", "t.example"]);
        assert!(config.detection.os_fingerprint);
        assert!(config.detection.banner_grab, "OS inference reads banners");
    }

    #[test]
    fn timing_templates_apply() {
        let config = config(&["--timing", "sneaky", "t.example"]);
        assert_eq!(config.timing.template, TimingTemplate::Sneaky);
        assert_eq!(config.timing.concurrency, 1);
    }

    #[test]
    fn explicit_timing_values_override_the_template() {
        let config = config(&["--timing", "insane", "--concurrency", "7", "t.example"]);
        assert_eq!(config.timing.template, TimingTemplate::Insane);
        assert_eq!(config.timing.concurrency, 7);
    }

    #[test]
    fn flags_override_the_profile_they_accompany() {
        let config = config(&["--profile", "quick", "--concurrency", "3", "t.example"]);
        assert_eq!(config.profile_name.as_deref(), Some("quick"));
        assert_eq!(config.timing.concurrency, 3);
    }

    #[test]
    fn a_profile_supplies_what_the_flags_do_not() {
        let config = config(&["--profile", "full", "t.example"]);
        assert!(config.detection.service_detection);
        assert_eq!(config.ports.tcp.len(), 1000);
    }

    #[test]
    fn an_unknown_profile_lists_the_available_ones() {
        let err = resolve(&args(&["--profile", "nope", "t.example"])).unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("quick"), "message was: {message}");
    }

    #[test]
    fn ping_mode_skips_port_scanning() {
        let config = config(&["--ping", "10.0.0.0/24"]);
        assert!(config.discovery.discovery_only);
        assert!(config.discovery.enabled);
    }

    #[test]
    fn no_discovery_scans_everything() {
        let config = config(&["-Pn", "10.0.0.0/30"]);
        assert!(!config.discovery.enabled);
    }

    #[test]
    fn disabling_every_discovery_method_is_an_error_with_a_suggestion() {
        let err = resolve(&args(&["--no-icmp", "--no-tcp-ping", "t.example"])).unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("--no-discovery"), "message was: {message}");
    }

    #[test]
    fn exclusions_are_parsed() {
        let config = config(&[
            "--exclude",
            "10.0.0.1",
            "--exclude",
            "10.0.0.0/28",
            "10.0.0.0/24",
        ]);
        assert_eq!(config.exclusions.len(), 2);
    }

    #[test]
    fn address_family_flags_apply() {
        assert_eq!(config(&["-6", "t.example"]).family, IpFamily::V6);
        assert_eq!(config(&["--both", "t.example"]).family, IpFamily::Both);
        assert_eq!(config(&["t.example"]).family, IpFamily::V4);
    }

    #[test]
    fn dns_flags_apply() {
        assert!(!config(&["-n", "t.example"]).dns.reverse_lookup);
        let config = config(&["--dns-server", "9.9.9.9", "t.example"]);
        assert_eq!(config.dns.servers.len(), 1);
    }

    #[test]
    fn a_bad_dns_server_is_reported_against_the_flag() {
        let err = resolve(&args(&["--dns-server", "not-an-ip", "t.example"])).unwrap_err();
        assert!(format!("{err:#}").contains("--dns-server"));
    }

    #[test]
    fn an_unknown_interface_fails_before_the_scan_starts() {
        let err = resolve(&args(&["-e", "definitely-not-real", "t.example"])).unwrap_err();
        assert!(format!("{err:#}").contains("definitely-not-real"));
    }

    #[test]
    fn a_targetless_invocation_is_rejected() {
        let err = resolve(&args(&[])).unwrap_err();
        assert!(format!("{err:#}").contains("no targets"));
    }

    #[test]
    fn oversized_scans_are_refused_until_confirmed() {
        let err = resolve(&args(&["--top-ports", "1000", "10.0.0.0/8"])).unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("limit exceeded"), "message was: {message}");

        let config = config(&["--yes", "--top-ports", "20", "10.0.0.0/15"]);
        assert!(config.limits.max_targets > Limits::default().max_targets);

        let err = resolve(&args(&["--yes", "--top-ports", "1000", "10.0.0.0/12"])).unwrap_err();
        assert!(format!("{err:#}").contains("probe limit exceeded"));
    }

    #[test]
    fn max_targets_can_be_set_explicitly() {
        let config = config(&["--max-targets", "10", "10.0.0.0/29"]);
        assert_eq!(config.limits.max_targets, 10);
    }

    #[test]
    fn a_configuration_file_supplies_defaults_that_flags_override() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("netscan.toml");
        std::fs::write(
            &path,
            "[defaults]\nretries = 5\nconcurrency = 11\n\n[profiles.mine]\ndescription = \"x\"\nports = \"22\"\n",
        )
        .unwrap();

        let parsed = Args::try_parse_from([
            "netscan",
            "--config",
            path.to_str().unwrap(),
            "--concurrency",
            "3",
            "t.example",
        ])
        .unwrap();
        let resolved = resolve(&parsed).unwrap();

        assert_eq!(
            resolved.config.timing.retries, 5,
            "the file supplies what flags do not"
        );
        assert_eq!(
            resolved.config.timing.concurrency, 3,
            "flags win over the file"
        );
        assert!(
            resolved.registry.contains("mine"),
            "file profiles are registered"
        );
        assert!(resolved.registry.contains("quick"), "built-ins survive");
        assert_eq!(resolved.config_path.as_ref(), Some(&path));
    }

    #[test]
    fn defaults_do_not_claim_to_be_a_profile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("netscan.toml");
        std::fs::write(&path, "[defaults]\nretries = 2\n").unwrap();
        let parsed =
            Args::try_parse_from(["netscan", "--config", path.to_str().unwrap(), "t.example"])
                .unwrap();
        let resolved = resolve(&parsed).unwrap();
        assert_eq!(resolved.config.profile_name, None);
    }

    #[test]
    fn no_config_ignores_the_file_entirely() {
        let resolved = resolve(&args(&["t.example"])).unwrap();
        assert_eq!(resolved.config_path, None);
    }

    #[test]
    fn the_debug_description_names_the_important_settings() {
        let text = describe(&config(&["--sV", "-p", "22", "t.example"]));
        assert!(text.contains("ports=22"));
        assert!(text.contains("service_detection=true"));
        assert!(text.contains("tcp_mode=connect"));
    }
}
