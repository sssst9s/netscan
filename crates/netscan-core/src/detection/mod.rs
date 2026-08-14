pub mod fingerprint;
pub mod oui;
pub mod service;
pub mod version;

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;

use crate::config::settings::DetectionConfig;
use crate::scanner::port::Transport;
use crate::scanner::probe::{ProbeContext, ProbeRegistry};
use crate::scanner::result::{DetectionSource, ServiceInfo, TlsInfo};

pub use fingerprint::Observations;

pub const MAX_CONNECTIONS_PER_PORT: usize = 4;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DetectionOutcome {
    pub service: Option<ServiceInfo>,
    pub tls: Option<TlsInfo>,
    pub banner: Option<String>,
    pub certificate_names: Vec<String>,
}

#[derive(Debug)]
pub struct Detector {
    registry: ProbeRegistry,
    config: DetectionConfig,
    max_response_bytes: usize,
    banner_chars: usize,
}

impl Detector {
    pub fn new(
        registry: ProbeRegistry,
        config: DetectionConfig,
        max_response_bytes: usize,
    ) -> Self {
        Self {
            registry,
            config,
            max_response_bytes,
            banner_chars: 512,
        }
    }

    pub fn registry(&self) -> &ProbeRegistry {
        &self.registry
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn detect_tcp(
        &self,
        host: IpAddr,
        port: u16,
        mut stream: Option<TcpStream>,
        hostname: Option<&str>,
        read_timeout: Duration,
        connect_timeout: Duration,
        source: Option<IpAddr>,
    ) -> DetectionOutcome {
        let mut outcome = DetectionOutcome::default();
        if !self.config.any_enabled() {
            return outcome;
        }

        let target = SocketAddr::new(host, port);
        let mut connections_used = if stream.is_some() { 1 } else { 0 };

        let mut banner_bytes: Option<Vec<u8>> = None;
        if self.config.banner_grab {
            if let Some(active) = stream.as_mut() {
                banner_bytes = crate::protocols::tcp::read_banner(
                    active,
                    read_timeout,
                    self.max_response_bytes,
                )
                .await;
            }
        }
        if let Some(bytes) = &banner_bytes {
            outcome.banner = Some(crate::protocols::tcp::sanitise_banner(
                bytes,
                self.banner_chars,
            ))
            .filter(|s| !s.is_empty());
        }

        if self.config.service_detection || self.config.version_detection {
            let probes = self
                .registry
                .select(Transport::Tcp, port, self.config.max_intrusiveness);

            for probe in probes {
                if probe.intrusiveness() > 0 && stream.is_none() {
                    if connections_used >= MAX_CONNECTIONS_PER_PORT {
                        break;
                    }
                    let reconnect =
                        crate::protocols::tcp::connect(target, connect_timeout, source).await;
                    connections_used += 1;
                    stream = reconnect.stream;
                    if stream.is_none() {
                        break;
                    }
                }

                let mut context = ProbeContext {
                    host,
                    port,
                    transport: Transport::Tcp,
                    timeout: read_timeout,
                    max_response_bytes: self.max_response_bytes,
                    banner: banner_bytes.as_deref(),
                    stream: stream.as_mut(),
                    spent: false,
                };

                let found = probe.run(&mut context).await;
                let spent = context.spent;
                outcome.service = version::best_of(outcome.service.take(), found);

                if spent {
                    stream = None;
                }
                if outcome
                    .service
                    .as_ref()
                    .is_some_and(|s| s.confidence == crate::scanner::result::Confidence::High)
                {
                    break;
                }
            }
        }

        if outcome.service.is_none() {
            if let Some(text) = &outcome.banner {
                outcome.service = version::service_from_banner(Transport::Tcp, port, text);
            }
        }

        if self.config.tls_inspection && self.should_try_tls(port, &outcome) {
            if stream.is_none() && connections_used < MAX_CONNECTIONS_PER_PORT {
                let reconnect =
                    crate::protocols::tcp::connect(target, connect_timeout, source).await;
                stream = reconnect.stream;
            }
            if let Some(active) = stream.as_mut() {
                let result = crate::protocols::tls::inspect(
                    active,
                    hostname,
                    read_timeout,
                    self.max_response_bytes,
                )
                .await;
                self.apply_tls(&mut outcome, result, port);
            }
        }

        if outcome.service.is_none() {
            if let Some(name) = service::name_for_port(Transport::Tcp, port) {
                outcome.service = Some(ServiceInfo::from_port_number(name));
            }
        }

        outcome
    }

    pub fn detect_udp(&self, port: u16, response: Option<&[u8]>) -> DetectionOutcome {
        let mut outcome = DetectionOutcome::default();
        let Some(bytes) = response else {
            if let Some(name) = service::name_for_port(Transport::Udp, port) {
                outcome.service = Some(ServiceInfo::from_port_number(name));
            }
            return outcome;
        };

        outcome.banner = Some(crate::protocols::tcp::sanitise_banner(
            bytes,
            self.banner_chars,
        ))
        .filter(|s| !s.is_empty());

        if self.config.service_detection || self.config.version_detection {
            for probe in self
                .registry
                .select(Transport::Udp, port, self.config.max_intrusiveness)
            {
                if let Some(service) = probe.match_bytes(bytes) {
                    outcome.service = version::best_of(outcome.service.take(), Some(service));
                }
            }
        }

        if outcome.service.is_none() {
            if let Some(name) = service::name_for_port(Transport::Udp, port) {
                outcome.service = Some(ServiceInfo::from_port_number(name));
            }
        }
        outcome
    }

    fn should_try_tls(&self, port: u16, outcome: &DetectionOutcome) -> bool {
        const TLS_PORTS: &[u16] = &[
            443, 465, 563, 636, 989, 990, 992, 993, 994, 995, 1443, 2083, 2087, 2096, 3269, 4443,
            5061, 5986, 6443, 8443, 8843, 8883, 9443, 10443,
        ];
        if TLS_PORTS.contains(&port) {
            return true;
        }
        match &outcome.service {
            None => true,
            Some(service) => service.confidence < crate::scanner::result::Confidence::High,
        }
    }

    fn apply_tls(
        &self,
        outcome: &mut DetectionOutcome,
        result: crate::protocols::tls::TlsProbeResult,
        port: u16,
    ) {
        use crate::protocols::tls::TlsProbeResult;
        match result {
            TlsProbeResult::Tls(info) => {
                outcome.certificate_names = info.subject_alt_names.clone();
                if let Some(subject) = &info.subject {
                    if !outcome.certificate_names.iter().any(|n| n == subject) {
                        outcome.certificate_names.push(subject.clone());
                    }
                }

                let inner_name = outcome
                    .service
                    .as_ref()
                    .map(|s| s.name.clone())
                    .filter(|n| n != "unknown")
                    .or_else(|| service::name_for_port(Transport::Tcp, port).map(str::to_string))
                    .unwrap_or_else(|| "tls".to_string());

                let service = ServiceInfo {
                    name: inner_name,
                    product: outcome.service.as_ref().and_then(|s| s.product.clone()),
                    version: outcome.service.as_ref().and_then(|s| s.version.clone()),
                    extra: info.version.clone(),
                    tls: true,
                    source: DetectionSource::Tls,
                    confidence: crate::scanner::result::Confidence::High,
                };
                outcome.service = Some(service);
                outcome.tls = Some(*info);
            }
            TlsProbeResult::TlsButRefused { reason } => {
                outcome.tls = Some(TlsInfo {
                    version: Some(format!("TLS (handshake declined: {reason})")),
                    ..TlsInfo::default()
                });
                if let Some(service) = outcome.service.as_mut() {
                    service.tls = true;
                } else {
                    outcome.service = Some(ServiceInfo {
                        name: service::name_for_port(Transport::Tcp, port)
                            .unwrap_or("tls")
                            .to_string(),
                        tls: true,
                        source: DetectionSource::Tls,
                        confidence: crate::scanner::result::Confidence::Medium,
                        ..ServiceInfo::default()
                    });
                }
            }
            TlsProbeResult::NotTls => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::result::Confidence;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    fn detector(config: DetectionConfig) -> Detector {
        Detector::new(ProbeRegistry::builtin().unwrap(), config, 8192)
    }

    async fn connect_to(addr: SocketAddr) -> Option<TcpStream> {
        crate::protocols::tcp::connect(addr, Duration::from_secs(2), None)
            .await
            .stream
    }

    #[tokio::test]
    async fn detection_is_skipped_when_nothing_is_enabled() {
        let config = DetectionConfig {
            banner_grab: false,
            service_detection: false,
            version_detection: false,
            tls_inspection: false,
            os_fingerprint: false,
            ..DetectionConfig::default()
        };
        let outcome = detector(config)
            .detect_tcp(
                "127.0.0.1".parse().unwrap(),
                22,
                None,
                None,
                Duration::from_millis(50),
                Duration::from_millis(50),
                None,
            )
            .await;
        assert_eq!(outcome, DetectionOutcome::default());
    }

    #[tokio::test]
    async fn a_banner_identifies_ssh() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream
                .write_all(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
        });

        let stream = connect_to(addr).await;
        let outcome = detector(DetectionConfig::full())
            .detect_tcp(
                addr.ip(),
                addr.port(),
                stream,
                None,
                Duration::from_millis(400),
                Duration::from_millis(400),
                None,
            )
            .await;

        let service = outcome.service.expect("SSH should be identified");
        assert_eq!(service.name, "ssh");
        assert_eq!(service.product.as_deref(), Some("OpenSSH"));
        assert_eq!(service.version.as_deref(), Some("9.6p1"));
        assert_eq!(service.confidence, Confidence::High);
        assert!(outcome.banner.unwrap().contains("OpenSSH"));
    }

    #[tokio::test]
    async fn an_http_server_is_identified_by_an_active_probe() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    use tokio::io::AsyncReadExt;
                    let _ = stream.read(&mut buf).await;
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n",
                        )
                        .await;
                });
            }
        });

        let stream = connect_to(addr).await;
        let outcome = detector(DetectionConfig {
            tls_inspection: false,
            ..DetectionConfig::full()
        })
        .detect_tcp(
            addr.ip(),
            addr.port(),
            stream,
            None,
            Duration::from_millis(500),
            Duration::from_millis(500),
            None,
        )
        .await;

        let service = outcome.service.expect("HTTP should be identified");
        assert_eq!(service.name, "http");
        assert_eq!(service.product.as_deref(), Some("nginx"));
        assert_eq!(service.version.as_deref(), Some("1.24.0"));
    }

    #[tokio::test]
    async fn a_silent_port_falls_back_to_the_port_catalog() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };

                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(400)).await;
                    drop(stream);
                });
            }
        });

        let stream = connect_to(addr).await;
        let outcome = detector(DetectionConfig {
            tls_inspection: false,
            ..DetectionConfig::full()
        })
        .detect_tcp(
            addr.ip(),
            22,
            stream,
            None,
            Duration::from_millis(150),
            Duration::from_millis(150),
            None,
        )
        .await;

        let service = outcome
            .service
            .expect("the catalog should provide a fallback");
        assert_eq!(service.name, "ssh");
        assert_eq!(service.source, DetectionSource::PortNumber);
        assert_eq!(
            service.confidence,
            Confidence::Low,
            "a port-number guess is weak evidence"
        );
    }

    #[test]
    fn tls_is_attempted_on_conventional_tls_ports_regardless_of_findings() {
        let detector = detector(DetectionConfig::full());
        let confident = DetectionOutcome {
            service: Some(ServiceInfo {
                name: "http".into(),
                confidence: Confidence::High,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(detector.should_try_tls(443, &confident));
        assert!(!detector.should_try_tls(80, &confident));
        assert!(detector.should_try_tls(9999, &DetectionOutcome::default()));
    }

    #[test]
    fn udp_detection_without_a_reply_still_names_the_port() {
        let outcome = detector(DetectionConfig::full()).detect_udp(53, None);
        let service = outcome.service.unwrap();
        assert_eq!(service.name, "domain");
        assert_eq!(service.source, DetectionSource::PortNumber);
        assert!(outcome.banner.is_none());
    }

    #[test]
    fn udp_detection_identifies_a_service_from_the_reply() {
        let reply = b"\x30\x26\x02\x01\x01\x04\x06public";
        let outcome = detector(DetectionConfig::full()).detect_udp(161, Some(reply));
        let service = outcome.service.expect("SNMP should be identified");
        assert_eq!(service.name, "snmp");
        assert_eq!(service.source, DetectionSource::Probe("snmp".to_string()));
        assert!(outcome.banner.is_some());
    }

    #[test]
    fn udp_detection_falls_back_when_the_reply_matches_nothing() {
        let outcome = detector(DetectionConfig::full()).detect_udp(161, Some(b"nonsense"));
        let service = outcome.service.unwrap();
        assert_eq!(service.source, DetectionSource::PortNumber);
    }
}
