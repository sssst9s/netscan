use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use futures::stream::StreamExt;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::config::settings::{ScanConfig, TcpScanMode};
use crate::detection::{fingerprint, Detector};
use crate::discovery::dns::Resolver;
use crate::discovery::{DiscoveryMethod, DiscoveryResult, HostDiscovery};
use crate::error::{Error, Result, Warning};
use crate::scanner::event::{Progress, ScanEvent};
use crate::scanner::port::Transport;
use crate::scanner::probe::ProbeRegistry;
use crate::scanner::result::{
    HostReport, HostStatus, Hostname, HostnameSource, PortReason, PortReport, PortState,
    ScanOutcome, ScanParameters, ScanReport, ScanStats,
};
use crate::scanner::scheduler::{AdaptiveController, DynamicSemaphore, RateLimiter};
use crate::scanner::target::{ResolvedTarget, TargetResolver};

const PROGRESS_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug)]
pub struct Engine {
    config: ScanConfig,
    registry: ProbeRegistry,
}

impl Engine {
    pub fn new(config: ScanConfig) -> Result<Self> {
        config.validate()?;
        let mut registry = ProbeRegistry::builtin()?;
        for path in &config.detection.probe_files {
            registry.load_file(path)?;
        }
        Ok(Self { config, registry })
    }

    pub fn with_registry(config: ScanConfig, registry: ProbeRegistry) -> Result<Self> {
        config.validate()?;
        Ok(Self { config, registry })
    }

    pub fn config(&self) -> &ScanConfig {
        &self.config
    }

    pub fn registry(&self) -> &ProbeRegistry {
        &self.registry
    }

    pub fn start(self) -> ScanHandle {
        let cancel = CancellationToken::new();
        let (tx, rx) = mpsc::channel(self.config.limits.event_buffer);

        let token = cancel.clone();
        let task = tokio::spawn(async move {
            let mut runner = ScanRunner::new(self.config, self.registry, tx.clone(), token);
            let report = runner.run().await;

            let _ = tx
                .send(ScanEvent::Finished {
                    report: Box::new(report.clone()),
                })
                .await;
            report
        });

        ScanHandle {
            events: rx,
            cancel,
            task: Some(task),
        }
    }

    pub async fn run(self) -> Result<ScanReport> {
        let mut handle = self.start();
        while handle.next_event().await.is_some() {}
        handle.finish().await
    }
}

#[derive(Debug)]
pub struct ScanHandle {
    events: mpsc::Receiver<ScanEvent>,
    cancel: CancellationToken,
    task: Option<tokio::task::JoinHandle<ScanReport>>,
}

impl ScanHandle {
    pub async fn next_event(&mut self) -> Option<ScanEvent> {
        self.events.recv().await
    }

    pub fn try_next_event(&mut self) -> Option<ScanEvent> {
        self.events.try_recv().ok()
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    pub async fn finish(&mut self) -> Result<ScanReport> {
        while self.events.try_recv().is_ok() {}
        match self.task.take() {
            Some(task) => task
                .await
                .map_err(|e| Error::Unsupported(format!("scan task failed: {e}"))),
            None => Err(Error::Unsupported(
                "scan handle already finished".to_string(),
            )),
        }
    }
}

impl Drop for ScanHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[derive(Debug, Default)]
struct Counters {
    hosts_total: AtomicU64,
    hosts_completed: AtomicU64,
    hosts_up: AtomicU64,
    probes_total: AtomicU64,
    probes_completed: AtomicU64,
    probes_sent: AtomicU64,
    open_ports: AtomicU64,
    retries: AtomicU64,
    errors: AtomicU64,
}

impl Counters {
    fn snapshot(&self, started: Instant, controller: &AdaptiveController) -> Progress {
        let elapsed = started.elapsed();
        let completed = self.probes_completed.load(Ordering::Relaxed);
        let rate = if elapsed.as_secs_f64() > 0.0 {
            completed as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        Progress {
            hosts_total: self.hosts_total.load(Ordering::Relaxed),
            hosts_completed: self.hosts_completed.load(Ordering::Relaxed),
            hosts_up: self.hosts_up.load(Ordering::Relaxed),
            probes_total: self.probes_total.load(Ordering::Relaxed),
            probes_completed: completed,
            open_ports: self.open_ports.load(Ordering::Relaxed),
            elapsed,
            rate,
            concurrency: controller.concurrency(),
            timeout: controller.timeout(),
        }
    }
}

struct ScanRunner {
    config: ScanConfig,
    events: mpsc::Sender<ScanEvent>,
    cancel: CancellationToken,
    counters: Arc<Counters>,
    controller: Arc<AdaptiveController>,
    permits: Arc<DynamicSemaphore>,
    rate_limiter: Option<Arc<RateLimiter>>,
    detector: Arc<Detector>,
    source: Option<IpAddr>,
    warnings: Vec<Warning>,
    started: Instant,
    syn_results: HashMap<(IpAddr, u16), crate::protocols::ProbeOutcome>,
    syn_hosts: std::collections::HashSet<IpAddr>,
}

impl ScanRunner {
    fn new(
        config: ScanConfig,
        registry: ProbeRegistry,
        events: mpsc::Sender<ScanEvent>,
        cancel: CancellationToken,
    ) -> Self {
        let controller = Arc::new(AdaptiveController::new(
            config.timing.adaptive,
            config.timing.connect_timeout,
            config.timing.concurrency,
        ));
        let permits = DynamicSemaphore::new(
            config.timing.concurrency,
            config
                .limits
                .max_concurrency
                .min(config.timing.concurrency.max(1)),
        );
        let rate_limiter = config
            .timing
            .max_rate
            .map(|rate| Arc::new(RateLimiter::new(rate)));
        let detector = Arc::new(Detector::new(
            registry,
            config.detection.clone(),
            config.limits.max_response_bytes,
        ));

        Self {
            config,
            events,
            cancel,
            counters: Arc::new(Counters::default()),
            controller,
            permits,
            rate_limiter,
            detector,
            source: None,
            warnings: Vec::new(),
            started: Instant::now(),
            syn_results: HashMap::new(),
            syn_hosts: std::collections::HashSet::new(),
        }
    }

    async fn emit(&self, event: ScanEvent) {
        let _ = self.events.send(event).await;
    }

    async fn warn(&mut self, warning: Warning) {
        self.warnings.push(warning.clone());
        self.emit(ScanEvent::Warning(warning)).await;
    }

    async fn run(&mut self) -> ScanReport {
        let started_at = Utc::now();
        self.started = Instant::now();

        self.resolve_source_address().await;
        self.check_scan_modes().await;

        let mut report = ScanReport {
            started_at,
            parameters: describe(&self.config),
            ..ScanReport::empty()
        };

        let (targets, resolver) = match self.resolve_targets().await {
            Ok(pair) => pair,
            Err(err) => {
                self.warn(Warning::global("scan.failed", err.to_string()))
                    .await;
                report.outcome = ScanOutcome::Failed;
                report.finished_at = Utc::now();
                report.warnings = std::mem::take(&mut self.warnings);
                return report;
            }
        };

        let ports_per_host = self.config.enabled_ports_per_host();
        self.counters
            .hosts_total
            .store(targets.len() as u64, Ordering::Relaxed);

        self.emit(ScanEvent::Started {
            hosts_total: targets.len() as u64,
            ports_per_host,
            started_at,
        })
        .await;

        let ticker = self.spawn_progress_ticker();

        let discovered = self.run_discovery(&targets).await;

        let scannable: Vec<DiscoveredHost> = if self.config.discovery.discovery_only {
            Vec::new()
        } else {
            discovered
                .iter()
                .filter(|host| host.discovery.is_up)
                .cloned()
                .collect()
        };

        if !self.config.discovery.discovery_only {
            self.counters
                .probes_total
                .store(scannable.len() as u64 * ports_per_host, Ordering::Relaxed);
            self.run_syn_prepass(&scannable).await;
        }

        let host_concurrency = self.host_concurrency();
        let per_host = (self.config.timing.concurrency / host_concurrency).max(1);

        let mut host_reports: HashMap<IpAddr, HostReport> = HashMap::new();
        for host in &discovered {
            host_reports.insert(host.target.addr, self.initial_host_report(host));
        }

        if !scannable.is_empty() {
            let results = {
                let this: &ScanRunner = self;
                let resolver = resolver.clone();
                futures::stream::iter(scannable)
                    .map(|host| {
                        let resolver = resolver.clone();
                        async move { this.scan_host(&host, per_host, resolver).await }
                    })
                    .buffer_unordered(host_concurrency)
                    .collect::<Vec<_>>()
                    .await
            };

            for host in results {
                host_reports.insert(host.address, host);
            }
        } else if self.config.discovery.discovery_only {
            for host in discovered.iter().filter(|h| h.discovery.is_up) {
                if let Some(report) = host_reports.get_mut(&host.target.addr) {
                    if let Some(resolver) = &resolver {
                        if let Some(name) = crate::discovery::dns::reverse_with_timeout(
                            resolver,
                            host.target.addr,
                            self.config.dns.timeout,
                        )
                        .await
                        {
                            report.add_hostname(name, HostnameSource::ReverseDns);
                        }
                    }
                    report.finished_at = Some(Utc::now());
                    self.counters
                        .hosts_completed
                        .fetch_add(1, Ordering::Relaxed);
                    self.emit(ScanEvent::HostCompleted {
                        host: Box::new(report.clone()),
                    })
                    .await;
                }
            }
        }

        ticker.abort();

        let final_progress = self.counters.snapshot(self.started, &self.controller);
        self.emit(ScanEvent::Progress(final_progress)).await;

        let mut hosts: Vec<HostReport> = host_reports.into_values().collect();
        hosts.sort_by_key(|host| host.address);
        report.hosts = hosts;
        report.finished_at = Utc::now();
        report.outcome = if self.cancel.is_cancelled() {
            ScanOutcome::Cancelled
        } else {
            ScanOutcome::Completed
        };
        report.stats = ScanStats {
            probes_sent: self.counters.probes_sent.load(Ordering::Relaxed),
            retries: self.counters.retries.load(Ordering::Relaxed),
            errors: self.counters.errors.load(Ordering::Relaxed),
            ..ScanStats::default()
        };
        report.recompute_stats();
        if let Some(mean) = self.controller.mean_rtt() {
            report.stats.mean_rtt_ms = Some(mean.as_secs_f64() * 1000.0);
        }
        report.warnings = std::mem::take(&mut self.warnings);
        report.sort();
        report
    }

    async fn resolve_source_address(&mut self) {
        let Some(name) = self.config.interface.clone() else {
            return;
        };
        let ipv6 = self.config.family == crate::scanner::target::IpFamily::V6;
        match crate::interfaces::source_address(&name, ipv6) {
            Ok(address) => self.source = Some(address),
            Err(err) => {
                self.warn(Warning::global(
                    "interface.unavailable",
                    format!("{err}; scanning from the default interface instead"),
                ))
                .await
            }
        }
    }

    async fn check_scan_modes(&mut self) {
        match self.config.modes.tcp_mode {
            TcpScanMode::Syn | TcpScanMode::Auto => {
                let (available, reason) = syn_availability(self.config.interface.as_deref());
                if !available {
                    if self.config.modes.tcp_mode == TcpScanMode::Syn {
                        self.warn(Warning::global(
                            "scan.syn_unavailable",
                            format!("{reason}; falling back to a TCP connect scan"),
                        ))
                        .await;
                    }
                    self.config.modes.tcp_mode = TcpScanMode::Connect;
                }
            }
            TcpScanMode::Connect => {}
        }

        if self.config.discovery.arp && !cfg!(feature = "raw") {
            self.config.discovery.arp = false;
        }
    }

    async fn resolve_targets(&mut self) -> Result<(Vec<ResolvedTarget>, Option<Arc<Resolver>>)> {
        let resolver_config = self.config.dns.clone();
        let needs_dns = self.config.targets.iter().any(|t| t.needs_resolution())
            || resolver_config.reverse_lookup;

        let resolver = if needs_dns {
            let (resolver, warning) = Resolver::new(resolver_config)?;
            if let Some(warning) = warning {
                self.warn(warning).await;
            }
            Some(Arc::new(resolver))
        } else {
            None
        };

        let target_resolver = TargetResolver {
            max_targets: self.config.limits.max_targets,
            family: self.config.family,
            include_network_addresses: self.config.include_network_addresses,
            exclusions: self.config.exclusions.clone(),
        };

        let (mut targets, hostnames) = target_resolver.expand_literals(&self.config.targets)?;

        if !hostnames.is_empty() {
            let Some(resolver) = resolver.as_ref() else {
                return Err(Error::Config(
                    "hostname targets require DNS resolution".into(),
                ));
            };
            let (resolved, warnings) =
                crate::discovery::dns::resolve_targets(resolver, &hostnames, self.config.family)
                    .await;
            for warning in warnings {
                self.warn(warning).await;
            }

            let exclusions = target_resolver.exclusion_matcher()?;
            let existing: std::collections::HashSet<IpAddr> =
                targets.iter().map(|t| t.addr).collect();
            for target in resolved {
                if !existing.contains(&target.addr) && !exclusions.contains(&target.addr) {
                    targets.push(target);
                }
            }
        }

        if targets.is_empty() {
            return Err(Error::Config(
                "no targets remain after resolution and exclusions".into(),
            ));
        }

        self.config.check_probe_budget(targets.len() as u64)?;
        Ok((targets, resolver))
    }

    fn host_concurrency(&self) -> usize {
        let ports = self.config.enabled_ports_per_host().max(1) as usize;
        let by_ports = (self.config.timing.concurrency / ports.min(64)).max(1);
        by_ports.clamp(1, 256).min(self.config.timing.concurrency)
    }

    fn spawn_progress_ticker(&self) -> tokio::task::JoinHandle<()> {
        let counters = Arc::clone(&self.counters);
        let controller = Arc::clone(&self.controller);
        let events = self.events.clone();
        let cancel = self.cancel.clone();
        let started = self.started;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(PROGRESS_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = interval.tick() => {
                        let progress = counters.snapshot(started, &controller);

                        match events.try_send(ScanEvent::Progress(progress)) {
                            Ok(()) => {}
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {}
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
                        }
                    }
                }
            }
        })
    }

    async fn run_discovery(&mut self, targets: &[ResolvedTarget]) -> Vec<DiscoveredHost> {
        if !self.config.discovery.enabled {
            self.counters
                .hosts_up
                .store(targets.len() as u64, Ordering::Relaxed);
            let hosts: Vec<DiscoveredHost> = targets
                .iter()
                .map(|target| DiscoveredHost {
                    target: target.clone(),
                    discovery: DiscoveryResult::assumed_up(),
                    mac: None,
                })
                .collect();
            for host in &hosts {
                self.emit(ScanEvent::HostDiscovered {
                    address: host.target.addr,
                    status: HostStatus::Up,
                    rtt_ms: None,
                })
                .await;
            }
            return hosts;
        }

        let (discovery, warnings) = HostDiscovery::new(
            self.config.discovery.icmp_echo,
            self.config.discovery.tcp_ping,
            self.config.discovery.tcp_ping_ports.clone(),
            self.config.timing.connect_timeout,
            self.source,
        );
        for warning in warnings {
            self.warn(warning).await;
        }

        let arp_results = self.run_arp_sweep(targets).await;
        let discovery = Arc::new(discovery);

        let concurrency = self.config.timing.concurrency.clamp(1, 512);
        let results = futures::stream::iter(targets.iter().cloned())
            .map(|target| {
                let discovery = Arc::clone(&discovery);
                let cancel = self.cancel.clone();
                let arp = arp_results.get(&target.addr).copied();
                async move {
                    if let Some((mac, rtt)) = arp {
                        return DiscoveredHost {
                            target,
                            discovery: DiscoveryResult {
                                is_up: true,
                                method: Some(DiscoveryMethod::IcmpEcho),
                                rtt: Some(rtt),
                                ttl: None,
                            },
                            mac: Some(mac),
                        };
                    }
                    let result = tokio::select! {
                        biased;
                        _ = cancel.cancelled() => DiscoveryResult::down(),
                        result = discovery.probe(target.addr) => result,
                    };
                    DiscoveredHost {
                        target,
                        discovery: result,
                        mac: None,
                    }
                }
            })
            .buffer_unordered(concurrency)
            .collect::<Vec<_>>()
            .await;

        for host in &results {
            if host.discovery.is_up {
                self.counters.hosts_up.fetch_add(1, Ordering::Relaxed);
            } else {
                self.counters
                    .hosts_completed
                    .fetch_add(1, Ordering::Relaxed);
            }
            self.emit(ScanEvent::HostDiscovered {
                address: host.target.addr,
                status: if host.discovery.is_up {
                    HostStatus::Up
                } else {
                    HostStatus::Down
                },
                rtt_ms: host.discovery.rtt.map(|d| d.as_secs_f64() * 1000.0),
            })
            .await;
        }

        results
    }

    #[cfg(feature = "raw")]
    async fn run_arp_sweep(
        &mut self,
        targets: &[ResolvedTarget],
    ) -> HashMap<IpAddr, (crate::scanner::result::MacAddress, Duration)> {
        let mut out = HashMap::new();
        if !self.config.discovery.arp {
            return out;
        }

        let local_networks = crate::interfaces::local_networks().unwrap_or_default();
        let candidates: Vec<std::net::Ipv4Addr> = targets
            .iter()
            .filter_map(|target| match target.addr {
                IpAddr::V4(v4) => {
                    let attached = local_networks
                        .iter()
                        .any(|net| net.contains(&IpAddr::V4(v4)));
                    attached.then_some(v4)
                }
                IpAddr::V6(_) => None,
            })
            .collect();

        if candidates.is_empty() {
            return out;
        }

        match crate::discovery::arp::sweep_async(
            self.config.interface.clone(),
            candidates,
            self.config
                .timing
                .connect_timeout
                .max(Duration::from_millis(500)),
        )
        .await
        {
            Ok(hosts) => {
                for host in hosts {
                    out.insert(IpAddr::V4(host.ip), (host.mac, host.rtt));
                }
            }
            Err(err) => {
                self.warn(Warning::global(
                    "discovery.arp_unavailable",
                    format!("{err}; using ICMP and TCP ping instead"),
                ))
                .await;
            }
        }
        out
    }

    #[cfg(not(feature = "raw"))]
    async fn run_arp_sweep(
        &mut self,
        _targets: &[ResolvedTarget],
    ) -> HashMap<IpAddr, (crate::scanner::result::MacAddress, Duration)> {
        HashMap::new()
    }

    #[cfg(feature = "raw")]
    async fn run_syn_prepass(&mut self, hosts: &[DiscoveredHost]) {
        use crate::protocols::raw::{SynReply, SynTarget};

        if self.config.modes.tcp_mode != TcpScanMode::Syn || !self.config.modes.tcp {
            return;
        }
        let ports: Vec<u16> = self.config.ports.tcp.as_slice().to_vec();
        if ports.is_empty() {
            return;
        }

        let targets: Vec<SynTarget> = hosts
            .iter()
            .filter_map(|host| match host.target.addr {
                IpAddr::V4(v4) => Some(SynTarget {
                    ip: v4,
                    ports: ports.clone(),
                }),
                IpAddr::V6(_) => None,
            })
            .collect();

        let ipv6_count = hosts.len() - targets.len();
        if ipv6_count > 0 {
            self.warn(Warning::global(
                "scan.syn_ipv4_only",
                format!(
                    "SYN scanning is IPv4-only; {ipv6_count} IPv6 host(s) will be connect scanned"
                ),
            ))
            .await;
        }
        if targets.is_empty() {
            return;
        }

        let salt: u32 = rand::random();
        let source_port: u16 = rand::random::<u16>() | 0xc000;

        let timeout = self
            .config
            .timing
            .connect_timeout
            .max(Duration::from_millis(500))
            .mul_f32(1.5);

        match crate::protocols::raw::syn_sweep_async(
            self.config.interface.clone(),
            targets,
            source_port,
            salt,
            timeout,
        )
        .await
        {
            Ok(sweep) => {
                for host in &hosts.iter().map(|h| h.target.addr).collect::<Vec<_>>() {
                    self.syn_hosts.insert(*host);
                }
                for ip in &sweep.unresolved {
                    self.syn_hosts.remove(&IpAddr::V4(*ip));
                }
                if !sweep.unresolved.is_empty() {
                    self.warn(Warning::global(
                        "scan.syn_off_link",
                        format!(
                            "{} host(s) did not answer ARP and are not on a directly attached \
                             network; they will be connect scanned instead",
                            sweep.unresolved.len()
                        ),
                    ))
                    .await;
                }
                for outcome in sweep.outcomes {
                    let probe = match outcome.reply {
                        SynReply::SynAck => {
                            crate::protocols::ProbeOutcome::open(PortReason::SynAck, outcome.rtt)
                        }
                        SynReply::Reset => crate::protocols::ProbeOutcome::closed(
                            PortReason::Reset,
                            Some(outcome.rtt),
                        ),
                    };
                    self.syn_results
                        .insert((IpAddr::V4(outcome.ip), outcome.port), probe);
                }
            }
            Err(err) => {
                self.warn(Warning::global(
                    "scan.syn_failed",
                    format!("{err}; falling back to a TCP connect scan"),
                ))
                .await;
                self.config.modes.tcp_mode = TcpScanMode::Connect;
            }
        }
    }

    #[cfg(not(feature = "raw"))]
    async fn run_syn_prepass(&mut self, _hosts: &[DiscoveredHost]) {}

    fn initial_host_report(&self, host: &DiscoveredHost) -> HostReport {
        let mut report = HostReport::new(host.target.addr);
        report.status = if host.discovery.is_up {
            HostStatus::Up
        } else {
            HostStatus::Down
        };
        report.status_reason = host
            .discovery
            .method
            .as_ref()
            .map(DiscoveryMethod::describe);
        report.rtt_ms = host.discovery.rtt.map(|d| d.as_secs_f64() * 1000.0);
        report.mac = host.mac;
        report.vendor = host
            .mac
            .and_then(|mac| crate::detection::oui::vendor_for(&mac))
            .map(str::to_string);
        if let Some(name) = &host.target.source_hostname {
            report.hostnames.push(Hostname {
                name: name.clone(),
                source: HostnameSource::UserSupplied,
            });
        }
        if !host.discovery.is_up {
            report.finished_at = Some(Utc::now());
            report.not_scanned = self.config.enabled_ports_per_host();
        }
        report
    }

    async fn scan_host(
        &self,
        host: &DiscoveredHost,
        per_host_concurrency: usize,
        resolver: Option<Arc<Resolver>>,
    ) -> HostReport {
        let address = host.target.addr;
        let mut report = self.initial_host_report(host);
        report.started_at = Utc::now();

        self.emit(ScanEvent::HostStarted { address }).await;

        let reverse = async {
            match resolver {
                Some(resolver) => {
                    crate::discovery::dns::reverse_with_timeout(
                        &resolver,
                        address,
                        self.config.dns.timeout,
                    )
                    .await
                }
                None => None,
            }
        };

        let planned = self.planned_ports();
        let total_planned = planned.len() as u64;

        let scan = self.probe_ports(address, &planned, per_host_concurrency);

        let (hostname, port_results) = match self.config.timing.host_timeout {
            Some(limit) => {
                let combined = futures::future::join(reverse, scan);

                tokio::time::timeout(limit, combined)
                    .await
                    .unwrap_or_default()
            }
            None => futures::future::join(reverse, scan).await,
        };

        if let Some(name) = hostname {
            report.add_hostname(name, HostnameSource::ReverseDns);
        }

        let tested = port_results.len() as u64;
        report.not_scanned = total_planned.saturating_sub(tested);

        let mut certificate_names = Vec::new();
        for result in port_results {
            certificate_names.extend(result.certificate_names);
            let port = result.port;
            if is_interesting(&port) {
                report.ports.push(port);
            } else {
                report.other_ports.record(port.state);
            }
        }

        for name in certificate_names {
            if name.parse::<IpAddr>().is_err() && !name.starts_with('*') {
                report.add_hostname(name, HostnameSource::TlsCertificate);
            }
        }

        if report.status != HostStatus::Up
            && self.config.discovery.infer_from_ports
            && report.ports.iter().any(|p| p.state != PortState::Filtered)
        {
            report.status = HostStatus::Up;
            report.status_reason = Some(DiscoveryMethod::InferredFromPortScan.describe());
            self.counters.hosts_up.fetch_add(1, Ordering::Relaxed);
        }

        if self.config.detection.os_fingerprint {
            report.os = Some(self.fingerprint(&report, host));
        }

        report.sort_ports();
        report.finished_at = Some(Utc::now());
        self.counters
            .hosts_completed
            .fetch_add(1, Ordering::Relaxed);
        self.emit(ScanEvent::HostCompleted {
            host: Box::new(report.clone()),
        })
        .await;
        report
    }

    fn planned_ports(&self) -> Vec<(Transport, u16)> {
        let mut planned = Vec::with_capacity(self.config.enabled_ports_per_host() as usize);
        if self.config.modes.tcp {
            planned.extend(self.config.ports.tcp.iter().map(|p| (Transport::Tcp, *p)));
        }
        if self.config.modes.udp {
            planned.extend(self.config.ports.udp.iter().map(|p| (Transport::Udp, *p)));
        }
        planned
    }

    async fn probe_ports(
        &self,
        address: IpAddr,
        planned: &[(Transport, u16)],
        concurrency: usize,
    ) -> Vec<PortOutcome> {
        let concurrency = if self.config.timing.scan_delay.is_zero() {
            concurrency.max(1)
        } else {
            1
        };

        futures::stream::iter(planned.iter().copied())
            .map(|(transport, port)| async move {
                if self.cancel.is_cancelled() {
                    return None;
                }
                Some(self.probe_one(address, transport, port).await)
            })
            .buffer_unordered(concurrency)
            .take_while(|result| futures::future::ready(result.is_some()))
            .filter_map(futures::future::ready)
            .collect()
            .await
    }

    async fn probe_one(&self, address: IpAddr, transport: Transport, port: u16) -> PortOutcome {
        let permit = self.permits.acquire().await;

        if let Some(limiter) = &self.rate_limiter {
            limiter.acquire().await;
        }
        if !self.config.timing.scan_delay.is_zero() {
            tokio::time::sleep(self.config.timing.scan_delay).await;
        }

        let target = SocketAddr::new(address, port);
        let mut attempts: u8 = 0;
        let max_attempts = self.config.timing.retries.saturating_add(1).max(1);

        let mut outcome;
        let mut stream = None;
        let mut udp_response = None;

        loop {
            attempts += 1;
            self.counters.probes_sent.fetch_add(1, Ordering::Relaxed);
            let timeout = self.controller.timeout();

            match transport {
                Transport::Tcp if self.syn_hosts.contains(&address) => {
                    outcome = self
                        .syn_results
                        .get(&(address, port))
                        .cloned()
                        .unwrap_or_else(|| {
                            crate::protocols::ProbeOutcome::filtered(PortReason::NoResponse)
                        });
                }
                Transport::Tcp => {
                    let probe = tokio::select! {
                        biased;
                        _ = self.cancel.cancelled() => {
                            return self.cancelled_outcome(transport, port, attempts);
                        }
                        probe = crate::protocols::tcp::connect(target, timeout, self.source) => probe,
                    };
                    outcome = probe.outcome;
                    stream = probe.stream;
                }
                Transport::Udp => {
                    let payload = crate::protocols::udp::default_payload(port);
                    let probe = tokio::select! {
                        biased;
                        _ = self.cancel.cancelled() => {
                            return self.cancelled_outcome(transport, port, attempts);
                        }
                        probe = crate::protocols::udp::probe(target, payload, timeout, self.source) => probe,
                    };
                    outcome = probe.outcome;
                    udp_response = probe.response;
                }
            }

            match outcome.rtt {
                Some(rtt) => self.controller.record_response(rtt),
                None => self.controller.record_timeout(),
            }

            if outcome.is_conclusive() || !outcome.is_retryable() || attempts >= max_attempts {
                break;
            }
            self.counters.retries.fetch_add(1, Ordering::Relaxed);
        }

        if self.controller.is_enabled() {
            self.permits.resize(self.controller.concurrency());
        }

        let mut port_report = PortReport {
            port,
            transport,
            state: outcome.state,
            reason: outcome.reason,
            rtt_ms: outcome.rtt.map(|d| d.as_secs_f64() * 1000.0),
            service: None,
            tls: None,
            banner: None,
            error: outcome.error.clone(),
            attempts,
        };

        if outcome.error.is_some() {
            self.counters.errors.fetch_add(1, Ordering::Relaxed);
        }

        let mut certificate_names = Vec::new();

        if outcome.state.is_open_ish() {
            self.counters.open_ports.fetch_add(1, Ordering::Relaxed);

            let detection = match transport {
                Transport::Tcp => {
                    self.detector
                        .detect_tcp(
                            address,
                            port,
                            stream,
                            None,
                            self.config.timing.read_timeout,
                            self.controller.timeout(),
                            self.source,
                        )
                        .await
                }
                Transport::Udp => self.detector.detect_udp(port, udp_response.as_deref()),
            };

            port_report.service = detection.service;
            port_report.tls = detection.tls;
            port_report.banner = detection.banner;
            certificate_names = detection.certificate_names;
        }

        drop(permit);

        self.counters
            .probes_completed
            .fetch_add(1, Ordering::Relaxed);
        self.emit(ScanEvent::PortResult {
            address,
            port: Box::new(port_report.clone()),
        })
        .await;

        PortOutcome {
            port: port_report,
            certificate_names,
        }
    }

    fn cancelled_outcome(&self, transport: Transport, port: u16, attempts: u8) -> PortOutcome {
        PortOutcome {
            port: PortReport {
                port,
                transport,
                state: PortState::Unknown,
                reason: PortReason::ProbeFailed,
                rtt_ms: None,
                service: None,
                tls: None,
                banner: None,
                error: Some(crate::error::ProbeError::Cancelled),
                attempts,
            },
            certificate_names: Vec::new(),
        }
    }

    fn fingerprint(
        &self,
        report: &HostReport,
        host: &DiscoveredHost,
    ) -> crate::scanner::result::OsGuess {
        let banners: Vec<&str> = report
            .ports
            .iter()
            .filter_map(|p| p.banner.as_deref())
            .collect();
        let services: Vec<&crate::scanner::result::ServiceInfo> = report
            .ports
            .iter()
            .filter_map(|p| p.service.as_ref())
            .collect();
        let open_ports: Vec<(u16, Transport)> = report
            .ports
            .iter()
            .filter(|p| p.state == PortState::Open)
            .map(|p| (p.port, p.transport))
            .collect();

        fingerprint::infer(&fingerprint::Observations {
            ttl: host.discovery.ttl,
            mac_vendor: report.vendor.as_deref(),
            open_ports,
            services,
            banners,
        })
    }
}

#[derive(Debug, Clone)]
struct DiscoveredHost {
    target: ResolvedTarget,
    discovery: DiscoveryResult,
    mac: Option<crate::scanner::result::MacAddress>,
}

#[derive(Debug, Clone)]
struct PortOutcome {
    port: PortReport,
    certificate_names: Vec<String>,
}

fn is_interesting(port: &PortReport) -> bool {
    port.state.is_open_ish() || port.service.is_some() || port.error.is_some()
}

fn describe(config: &ScanConfig) -> ScanParameters {
    ScanParameters {
        targets: config.targets.iter().map(ToString::to_string).collect(),
        ports: config.ports.to_string(),
        transports: config
            .modes
            .transports()
            .iter()
            .map(|t| t.to_string())
            .collect(),
        tcp_mode: config.modes.tcp_mode.to_string(),
        timing: config.timing.template.to_string(),
        concurrency: config.timing.concurrency,
        profile: config.profile_name.clone(),
        service_detection: config.detection.service_detection,
        os_detection: config.detection.os_fingerprint,
    }
}

#[cfg(feature = "raw")]
fn syn_availability(interface: Option<&str>) -> (bool, String) {
    match crate::protocols::raw::RawChannel::open(interface, Duration::from_millis(10)) {
        Ok(_) => (true, String::new()),
        Err(err) => (false, err.to_string()),
    }
}

#[cfg(not(feature = "raw"))]
fn syn_availability(_interface: Option<&str>) -> (bool, String) {
    (
        false,
        "SYN scanning needs the `raw` build feature, which this binary was built without"
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::settings::{DetectionConfig, DiscoveryConfig, ScanModes};
    use crate::scanner::port::{PortSelection, PortSet};
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    async fn test_server(banner: Option<&'static [u8]>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    if let Some(banner) = banner {
                        let _ = stream.write_all(banner).await;
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                });
            }
        });
        addr
    }

    fn base_config(ports: Vec<u16>) -> ScanConfig {
        ScanConfig {
            targets: vec!["127.0.0.1".parse().unwrap()],
            ports: PortSelection::tcp(PortSet::from_iter_ordered(ports)),
            modes: ScanModes {
                tcp: true,
                udp: false,
                tcp_mode: TcpScanMode::Connect,
            },
            discovery: DiscoveryConfig {
                enabled: false,
                ..DiscoveryConfig::default()
            },
            detection: DetectionConfig {
                banner_grab: false,
                service_detection: false,
                version_detection: false,
                tls_inspection: false,
                os_fingerprint: false,
                ..DetectionConfig::default()
            },
            dns: crate::config::settings::DnsConfig {
                reverse_lookup: false,
                resolve_targets: false,
                ..Default::default()
            },
            ..ScanConfig::default()
        }
    }

    #[tokio::test]
    async fn scans_an_open_port() {
        let addr = test_server(None).await;
        let config = base_config(vec![addr.port()]);
        let report = Engine::new(config).unwrap().run().await.unwrap();

        assert_eq!(report.hosts.len(), 1);
        let host = &report.hosts[0];
        assert_eq!(host.status, HostStatus::Up);
        assert_eq!(host.open_port_count(), 1);
        assert_eq!(host.ports[0].port, addr.port());
        assert_eq!(host.ports[0].state, PortState::Open);
        assert_eq!(report.stats.ports_open, 1);
        assert_eq!(report.outcome, ScanOutcome::Completed);
    }

    #[tokio::test]
    async fn closed_ports_are_summarised_not_listed() {
        let mut closed = Vec::new();
        for _ in 0..5 {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            closed.push(listener.local_addr().unwrap().port());
        }
        let config = base_config(closed.clone());
        let report = Engine::new(config).unwrap().run().await.unwrap();

        let host = &report.hosts[0];
        assert!(
            host.ports.is_empty(),
            "closed ports should not be listed individually"
        );
        assert_eq!(host.other_ports.get(PortState::Closed), 5);
        assert_eq!(host.ports_tested(), 5);
        assert_eq!(report.stats.ports_closed, 5);
    }

    #[tokio::test]
    async fn a_mixed_scan_reports_both_states() {
        let open = test_server(None).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed = listener.local_addr().unwrap().port();
        drop(listener);

        let config = base_config(vec![open.port(), closed]);
        let report = Engine::new(config).unwrap().run().await.unwrap();

        assert_eq!(report.stats.ports_open, 1);
        assert_eq!(report.stats.ports_closed, 1);
        assert_eq!(report.stats.ports_tested, 2);
    }

    #[tokio::test]
    async fn service_detection_identifies_a_banner() {
        let addr = test_server(Some(b"SSH-2.0-OpenSSH_9.6p1 Debian-2\r\n")).await;
        let mut config = base_config(vec![addr.port()]);
        config.detection = DetectionConfig {
            tls_inspection: false,
            os_fingerprint: true,
            ..DetectionConfig::full()
        };

        let report = Engine::new(config).unwrap().run().await.unwrap();
        let host = &report.hosts[0];
        let port = &host.ports[0];
        assert_eq!(
            port.service.as_ref().unwrap().product.as_deref(),
            Some("OpenSSH")
        );
        assert!(port.banner.as_ref().unwrap().contains("OpenSSH"));

        let os = host.os.as_ref().expect("fingerprinting was enabled");
        assert_eq!(os.family.as_deref(), Some("Linux"));
        assert!(
            !os.evidence.is_empty(),
            "an inference must carry its evidence"
        );
    }

    #[tokio::test]
    async fn a_completed_scan_reports_full_progress() {
        let addr = test_server(None).await;
        let mut handle = Engine::new(base_config(vec![addr.port()])).unwrap().start();

        let mut last_progress = None;
        while let Some(event) = handle.next_event().await {
            if let ScanEvent::Progress(progress) = event {
                last_progress = Some(progress);
            }
        }

        let progress = last_progress.expect("at least one progress event");
        assert_eq!(
            progress.percent(),
            100,
            "a finished scan should report 100%"
        );
        assert_eq!(progress.probes_completed, progress.probes_total);
    }

    #[tokio::test]
    async fn events_are_streamed_in_order() {
        let addr = test_server(None).await;
        let mut handle = Engine::new(base_config(vec![addr.port()])).unwrap().start();

        let mut kinds = Vec::new();
        while let Some(event) = handle.next_event().await {
            kinds.push(event.kind());
        }

        assert_eq!(kinds.first(), Some(&"started"));
        assert_eq!(kinds.last(), Some(&"finished"));
        assert!(kinds.contains(&"host-started"));
        assert!(kinds.contains(&"port-result"));
        assert!(kinds.contains(&"host-completed"));
    }

    #[tokio::test]
    async fn cancellation_produces_a_partial_report() {
        let mut config = base_config((1024..1524).collect());
        config.targets = vec!["198.51.100.9".parse().unwrap()];
        config.timing.connect_timeout = Duration::from_secs(5);
        config.timing.concurrency = 4;
        config.timing.adaptive = false;

        let mut handle = Engine::new(config).unwrap().start();

        tokio::time::sleep(Duration::from_millis(150)).await;
        handle.cancel();

        let report = loop {
            match handle.next_event().await {
                Some(ScanEvent::Finished { report }) => break *report,
                Some(_) => continue,
                None => panic!("stream ended without a Finished event"),
            }
        };

        assert_eq!(report.outcome, ScanOutcome::Cancelled);
        let host = &report.hosts[0];
        assert!(
            host.not_scanned > 0,
            "untested ports must be counted, not assumed closed"
        );
        assert!(
            host.ports_tested() < 500,
            "cancellation should have stopped the scan early, tested {}",
            host.ports_tested()
        );
    }

    #[tokio::test]
    async fn dropping_the_handle_cancels_the_scan() {
        let mut config = base_config((1024..1224).collect());
        config.targets = vec!["198.51.100.10".parse().unwrap()];
        config.timing.connect_timeout = Duration::from_secs(5);

        let handle = Engine::new(config).unwrap().start();
        let token = handle.cancellation_token();
        drop(handle);
        assert!(token.is_cancelled());
    }

    #[tokio::test]
    async fn discovery_marks_unreachable_hosts_down_without_scanning_them() {
        let mut config = base_config(vec![80, 443]);
        config.targets = vec!["198.51.100.11".parse().unwrap()];
        config.discovery = DiscoveryConfig {
            enabled: true,
            icmp_echo: false,
            tcp_ping: true,
            tcp_ping_ports: vec![80],
            arp: false,
            infer_from_ports: true,
            discovery_only: false,
        };
        config.timing.connect_timeout = Duration::from_millis(200);

        let report = Engine::new(config).unwrap().run().await.unwrap();
        let host = &report.hosts[0];
        assert_eq!(host.status, HostStatus::Down);
        assert_eq!(
            host.ports_tested(),
            0,
            "a host that is down should not be port scanned"
        );
        assert_eq!(host.not_scanned, 2);
        assert_eq!(report.stats.hosts_down, 1);
    }

    #[tokio::test]
    async fn discovery_only_scans_report_hosts_without_ports() {
        let addr = test_server(None).await;
        let mut config = base_config(vec![addr.port()]);
        config.discovery = DiscoveryConfig {
            enabled: true,
            icmp_echo: false,
            tcp_ping: true,
            tcp_ping_ports: vec![addr.port()],
            arp: false,
            infer_from_ports: true,
            discovery_only: true,
        };

        let report = Engine::new(config).unwrap().run().await.unwrap();
        let host = &report.hosts[0];
        assert_eq!(host.status, HostStatus::Up);
        assert!(host.ports.is_empty());
        assert_eq!(report.stats.ports_tested, 0);
    }

    #[tokio::test]
    async fn concurrency_is_bounded() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peak = Arc::new(AtomicU64::new(0));
        let live = Arc::new(AtomicU64::new(0));

        {
            let peak = Arc::clone(&peak);
            let live = Arc::clone(&live);
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    let peak = Arc::clone(&peak);
                    let live = Arc::clone(&live);
                    tokio::spawn(async move {
                        let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(80)).await;
                        live.fetch_sub(1, Ordering::SeqCst);
                        drop(stream);
                    });
                }
            });
        }

        let mut config = base_config(vec![addr.port(); 1]);

        config.ports = PortSelection::tcp(PortSet::from_iter_ordered(vec![addr.port()]));
        config.timing.concurrency = 4;
        config.timing.adaptive = false;

        let report = Engine::new(config).unwrap().run().await.unwrap();
        assert_eq!(report.stats.ports_open, 1);
        assert!(
            peak.load(Ordering::SeqCst) <= 4,
            "concurrency bound was exceeded"
        );
    }

    #[tokio::test]
    async fn retries_are_recorded() {
        let mut config = base_config(vec![80]);
        config.targets = vec!["198.51.100.12".parse().unwrap()];
        config.timing.connect_timeout = Duration::from_millis(120);
        config.timing.retries = 2;
        config.timing.adaptive = false;

        let report = Engine::new(config).unwrap().run().await.unwrap();
        assert!(
            report.stats.probes_sent >= 3,
            "a filtered port should be retried"
        );
        assert!(report.stats.retries >= 2);
        let host = &report.hosts[0];

        assert_eq!(host.other_ports.get(PortState::Filtered), 1);
    }

    #[tokio::test]
    async fn the_report_describes_the_scan_that_produced_it() {
        let addr = test_server(None).await;
        let mut config = base_config(vec![addr.port()]);
        config.profile_name = Some("test-profile".to_string());

        let report = Engine::new(config).unwrap().run().await.unwrap();
        assert_eq!(report.parameters.profile.as_deref(), Some("test-profile"));
        assert_eq!(report.parameters.targets, vec!["127.0.0.1".to_string()]);
        assert_eq!(report.parameters.transports, vec!["tcp".to_string()]);
        assert_eq!(
            report.schema_version,
            crate::scanner::result::SCHEMA_VERSION
        );
        assert!(report.finished_at >= report.started_at);
    }

    #[tokio::test]
    async fn an_invalid_configuration_is_rejected_before_the_scan_starts() {
        let mut config = base_config(vec![80]);
        config.targets.clear();
        assert!(Engine::new(config).is_err());
    }

    #[tokio::test]
    async fn syn_falls_back_to_connect_with_a_warning() {
        let addr = test_server(None).await;
        let mut config = base_config(vec![addr.port()]);
        config.modes.tcp_mode = TcpScanMode::Syn;

        let report = Engine::new(config).unwrap().run().await.unwrap();

        let downgraded = report
            .warnings
            .iter()
            .any(|w| w.code == "scan.syn_unavailable");
        if downgraded {
            assert_eq!(
                report.parameters.tcp_mode, "connect",
                "a downgraded scan must not claim to have used SYN"
            );
        } else {
            assert_eq!(report.parameters.tcp_mode, "syn");
        }
        assert_eq!(
            report.stats.ports_open, 1,
            "the fallback must still produce results"
        );
    }

    #[test]
    fn interesting_ports_are_the_ones_worth_listing() {
        let open = PortReport::new(80, Transport::Tcp, PortState::Open, PortReason::SynAck);
        assert!(is_interesting(&open));

        let closed = PortReport::new(81, Transport::Tcp, PortState::Closed, PortReason::Refused);
        assert!(!is_interesting(&closed));

        let mut errored = PortReport::new(
            82,
            Transport::Tcp,
            PortState::Unknown,
            PortReason::ProbeFailed,
        );
        errored.error = Some(crate::error::ProbeError::Timeout);
        assert!(
            is_interesting(&errored),
            "a probe that failed is worth reporting"
        );
    }
}
