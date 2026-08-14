use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::protocols::icmp::IcmpPinger;
use crate::scanner::result::PortState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryMethod {
    IcmpEcho,
    TcpOpen(u16),
    TcpClosed(u16),
    Assumed,
    InferredFromPortScan,
}

impl DiscoveryMethod {
    pub fn describe(&self) -> String {
        match self {
            DiscoveryMethod::IcmpEcho => "icmp echo reply".to_string(),
            DiscoveryMethod::TcpOpen(port) => format!("tcp {port} open"),
            DiscoveryMethod::TcpClosed(port) => format!("tcp {port} refused"),
            DiscoveryMethod::Assumed => "host discovery disabled".to_string(),
            DiscoveryMethod::InferredFromPortScan => "port probe answered".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveryResult {
    pub is_up: bool,
    pub method: Option<DiscoveryMethod>,
    pub rtt: Option<Duration>,
    pub ttl: Option<u8>,
}

impl DiscoveryResult {
    pub fn down() -> Self {
        Self {
            is_up: false,
            method: None,
            rtt: None,
            ttl: None,
        }
    }

    pub fn assumed_up() -> Self {
        Self {
            is_up: true,
            method: Some(DiscoveryMethod::Assumed),
            rtt: None,
            ttl: None,
        }
    }
}

#[derive(Debug)]
pub struct HostDiscovery {
    icmp_v4: Option<Arc<IcmpPinger>>,
    icmp_v6: Option<Arc<IcmpPinger>>,
    tcp_ports: Vec<u16>,
    timeout: Duration,
    source: Option<IpAddr>,
    sequence: std::sync::atomic::AtomicU16,
}

impl HostDiscovery {
    pub fn new(
        icmp_enabled: bool,
        tcp_ping_enabled: bool,
        tcp_ports: Vec<u16>,
        timeout: Duration,
        source: Option<IpAddr>,
    ) -> (Self, Vec<crate::error::Warning>) {
        let mut warnings = Vec::new();
        let mut icmp_v4 = None;
        let mut icmp_v6 = None;

        if icmp_enabled {
            match IcmpPinger::new(false) {
                Ok(pinger) => icmp_v4 = Some(Arc::new(pinger)),
                Err(err) => warnings.push(crate::error::Warning::global(
                    "discovery.icmp_unavailable",
                    format!("{err}; falling back to TCP ping for IPv4 host discovery"),
                )),
            }

            icmp_v6 = IcmpPinger::new(true).ok().map(Arc::new);
        }

        if !tcp_ping_enabled && icmp_v4.is_none() && icmp_enabled {
            warnings.push(crate::error::Warning::global(
                "discovery.no_method",
                "no host discovery method is available; every host will be reported as down. \
                 Use --no-discovery to scan ports regardless."
                    .to_string(),
            ));
        }

        let discovery = Self {
            icmp_v4,
            icmp_v6,
            tcp_ports: if tcp_ping_enabled {
                tcp_ports
            } else {
                Vec::new()
            },
            timeout,
            source,
            sequence: std::sync::atomic::AtomicU16::new(1),
        };
        (discovery, warnings)
    }

    pub fn is_usable(&self) -> bool {
        self.icmp_v4.is_some() || self.icmp_v6.is_some() || !self.tcp_ports.is_empty()
    }

    pub async fn probe(&self, address: IpAddr) -> DiscoveryResult {
        if !self.is_usable() {
            return DiscoveryResult::down();
        }

        let pinger = if address.is_ipv6() {
            self.icmp_v6.as_ref()
        } else {
            self.icmp_v4.as_ref()
        };

        let icmp = async {
            let pinger = pinger?;
            let sequence = self
                .sequence
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                .max(1);
            let result = pinger.ping(address, sequence, self.timeout).await;
            result.responded.then_some(DiscoveryResult {
                is_up: true,
                method: Some(DiscoveryMethod::IcmpEcho),
                rtt: result.rtt,
                ttl: result.ttl,
            })
        };

        let tcp = self.tcp_ping(address);

        tokio::select! {
            biased;
            Some(result) = icmp => result,
            Some(result) = tcp => result,
            else => DiscoveryResult::down(),
        }
    }

    async fn tcp_ping(&self, address: IpAddr) -> Option<DiscoveryResult> {
        if self.tcp_ports.is_empty() {
            return None;
        }

        let probes = self.tcp_ports.iter().map(|port| {
            let port = *port;
            async move {
                let probe = crate::protocols::tcp::connect(
                    SocketAddr::new(address, port),
                    self.timeout,
                    self.source,
                )
                .await;
                match probe.outcome.state {
                    PortState::Open => Some(DiscoveryResult {
                        is_up: true,
                        method: Some(DiscoveryMethod::TcpOpen(port)),
                        rtt: probe.outcome.rtt,
                        ttl: None,
                    }),
                    PortState::Closed => Some(DiscoveryResult {
                        is_up: true,
                        method: Some(DiscoveryMethod::TcpClosed(port)),
                        rtt: probe.outcome.rtt,
                        ttl: None,
                    }),
                    _ => None,
                }
            }
        });

        let results = futures::future::join_all(probes).await;
        results.into_iter().flatten().next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn discovery(ports: Vec<u16>) -> HostDiscovery {
        HostDiscovery::new(false, true, ports, Duration::from_millis(500), None).0
    }

    #[test]
    fn method_descriptions_are_specific() {
        assert_eq!(DiscoveryMethod::IcmpEcho.describe(), "icmp echo reply");
        assert_eq!(DiscoveryMethod::TcpOpen(443).describe(), "tcp 443 open");
        assert_eq!(DiscoveryMethod::TcpClosed(80).describe(), "tcp 80 refused");
    }

    #[test]
    fn a_discovery_with_no_methods_is_not_usable() {
        let (discovery, _) =
            HostDiscovery::new(false, false, vec![], Duration::from_millis(10), None);
        assert!(!discovery.is_usable());
    }

    #[tokio::test]
    async fn an_open_tcp_port_proves_a_host_is_up() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });

        let result = discovery(vec![addr.port()]).probe(addr.ip()).await;
        assert!(result.is_up);
        assert_eq!(result.method, Some(DiscoveryMethod::TcpOpen(addr.port())));
        assert!(result.rtt.is_some());
    }

    #[tokio::test]
    async fn a_refused_tcp_port_also_proves_a_host_is_up() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let result = discovery(vec![addr.port()]).probe(addr.ip()).await;
        assert!(result.is_up, "a RST is still an answer from a live host");
        assert_eq!(result.method, Some(DiscoveryMethod::TcpClosed(addr.port())));
    }

    #[tokio::test]
    async fn a_silent_address_is_reported_down() {
        let result =
            HostDiscovery::new(false, true, vec![80, 443], Duration::from_millis(150), None)
                .0
                .probe("198.51.100.7".parse().unwrap())
                .await;
        assert!(!result.is_up);
        assert_eq!(result.method, None);
    }

    #[tokio::test]
    async fn tcp_ping_ports_are_probed_concurrently() {
        let started = std::time::Instant::now();
        let _ = HostDiscovery::new(
            false,
            true,
            vec![80, 443, 22, 445, 3389],
            Duration::from_millis(300),
            None,
        )
        .0
        .probe("198.51.100.8".parse().unwrap())
        .await;
        assert!(
            started.elapsed() < Duration::from_millis(900),
            "ping ports were serialised: took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn icmp_unavailability_produces_exactly_one_warning() {
        let (_, warnings) =
            HostDiscovery::new(true, true, vec![80], Duration::from_millis(100), None);

        assert!(
            warnings.len() <= 1,
            "expected at most one warning, got {warnings:?}"
        );
        if let Some(warning) = warnings.first() {
            assert_eq!(warning.code, "discovery.icmp_unavailable");
        }
    }

    #[test]
    fn assumed_up_records_why() {
        let result = DiscoveryResult::assumed_up();
        assert!(result.is_up);
        assert_eq!(result.method.unwrap().describe(), "host discovery disabled");
    }
}
