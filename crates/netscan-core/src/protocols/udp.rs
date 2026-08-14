use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use crate::error::ProbeError;
use crate::protocols::ProbeOutcome;
use crate::scanner::result::{PortReason, PortState};

#[derive(Debug, Clone, PartialEq)]
pub struct UdpProbe {
    pub outcome: ProbeOutcome,
    pub response: Option<Vec<u8>>,
}

pub async fn probe(
    target: SocketAddr,
    payload: &[u8],
    timeout: Duration,
    source: Option<IpAddr>,
) -> UdpProbe {
    let socket = match bind_socket(&target, source).await {
        Ok(socket) => socket,
        Err(err) => {
            return UdpProbe {
                outcome: ProbeOutcome::failed(ProbeError::from_io(&err)),
                response: None,
            }
        }
    };

    if let Err(err) = socket.connect(target).await {
        return UdpProbe {
            outcome: ProbeOutcome::failed(ProbeError::from_io(&err)),
            response: None,
        };
    }

    let started = Instant::now();
    if let Err(err) = socket.send(payload).await {
        return UdpProbe {
            outcome: classify_io(&err, started),
            response: None,
        };
    }

    let mut buffer = vec![0u8; 4096];
    match tokio::time::timeout(timeout, socket.recv(&mut buffer)).await {
        Ok(Ok(n)) => {
            buffer.truncate(n);
            UdpProbe {
                outcome: ProbeOutcome::open(PortReason::UdpResponse, started.elapsed()),
                response: Some(buffer),
            }
        }
        Ok(Err(err)) => UdpProbe {
            outcome: classify_io(&err, started),
            response: None,
        },
        Err(_elapsed) => UdpProbe {
            outcome: ProbeOutcome::open_filtered(PortReason::NoResponse),
            response: None,
        },
    }
}

async fn bind_socket(target: &SocketAddr, source: Option<IpAddr>) -> io::Result<UdpSocket> {
    let bind_addr = match (source, target) {
        (Some(src @ IpAddr::V4(_)), SocketAddr::V4(_)) => SocketAddr::new(src, 0),
        (Some(src @ IpAddr::V6(_)), SocketAddr::V6(_)) => SocketAddr::new(src, 0),
        (_, SocketAddr::V4(_)) => SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
        (_, SocketAddr::V6(_)) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
    };
    UdpSocket::bind(bind_addr).await
}

fn classify_io(err: &io::Error, started: Instant) -> ProbeOutcome {
    use io::ErrorKind as K;
    match err.kind() {
        K::ConnectionRefused => {
            ProbeOutcome::closed(PortReason::PortUnreachable, Some(started.elapsed()))
        }
        K::HostUnreachable | K::NetworkUnreachable | K::NetworkDown => ProbeOutcome {
            state: PortState::Filtered,
            reason: PortReason::HostUnreachable,
            rtt: None,
            error: None,
        },
        K::PermissionDenied => ProbeOutcome {
            state: PortState::Filtered,
            reason: PortReason::AdminProhibited,
            rtt: None,
            error: None,
        },
        _ => ProbeOutcome::failed(ProbeError::from_io(err)),
    }
}

const DNS_QUERY: &[u8] = &[
    0x9a, 0xbc, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'v', b'e', b'r',
    b's', b'i', b'o', b'n', 0x04, b'b', b'i', b'n', b'd', 0x00, 0x00, 0x10, 0x00, 0x03,
];

const SNMP_GET: &[u8] = &[
    0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0, 0x19, 0x02,
    0x04, 0x70, 0x6e, 0x73, 0x63, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06,
    0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00,
];

const NTP_REQUEST: &[u8] = &[
    0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const NETBIOS_STATUS: &[u8] = &[
    0x82, 0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, b'C', b'K', b'A',
    b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A',
    b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', 0x00, 0x00, 0x21,
    0x00, 0x01,
];

const MDNS_QUERY: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, b'_', b's', b'e',
    b'r', b'v', b'i', b'c', b'e', b's', 0x07, b'_', b'd', b'n', b's', b'-', b's', b'd', 0x04, b'_',
    b'u', b'd', b'p', 0x05, b'l', b'o', b'c', b'a', b'l', 0x00, 0x00, 0x0c, 0x00, 0x01,
];

const IKE_PROBE: &[u8] = &[
    0x6e, 0x73, 0x63, 0x61, 0x6e, 0x70, 0x72, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c,
];

const MEMCACHED_STATS: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, b's', b't', b'a', b't', b's', b'\r', b'\n',
];

pub fn default_payload(port: u16) -> &'static [u8] {
    match port {
        53 => DNS_QUERY,
        5353 => MDNS_QUERY,
        161 | 162 => SNMP_GET,
        123 => NTP_REQUEST,
        137 => NETBIOS_STATUS,
        500 | 4500 => IKE_PROBE,
        11211 => MEMCACHED_STATS,
        _ => b"\r\n\r\n",
    }
}

pub fn has_protocol_probe(port: u16) -> bool {
    matches!(port, 53 | 123 | 137 | 161 | 162 | 500 | 4500 | 5353 | 11211)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn open_port_answers() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            assert!(n > 0);
            let _ = server.send_to(b"pong", peer).await;
        });

        let result = probe(addr, b"ping", Duration::from_secs(2), None).await;
        assert_eq!(result.outcome.state, PortState::Open);
        assert_eq!(result.outcome.reason, PortReason::UdpResponse);
        assert_eq!(result.response.as_deref(), Some(&b"pong"[..]));
    }

    #[tokio::test]
    async fn silent_port_is_open_filtered() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let _keep_alive = server;

        let result = probe(addr, b"ping", Duration::from_millis(200), None).await;
        assert_eq!(result.outcome.state, PortState::OpenFiltered);
        assert_eq!(result.outcome.reason, PortReason::NoResponse);
    }

    #[tokio::test]
    async fn closed_port_is_detected_via_icmp() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        drop(server);

        let result = probe(addr, b"ping", Duration::from_millis(500), None).await;

        assert!(
            matches!(
                result.outcome.state,
                PortState::Closed | PortState::OpenFiltered
            ),
            "unexpected state {:?}",
            result.outcome.state
        );
        if result.outcome.state == PortState::Closed {
            assert_eq!(result.outcome.reason, PortReason::PortUnreachable);
        }
    }

    #[test]
    fn well_known_ports_get_real_probes() {
        assert_eq!(default_payload(53), DNS_QUERY);
        assert_eq!(default_payload(161), SNMP_GET);
        assert_eq!(default_payload(123), NTP_REQUEST);
        assert_eq!(default_payload(5353), MDNS_QUERY);
        assert!(has_protocol_probe(53));
        assert!(!has_protocol_probe(9999));
    }

    #[test]
    fn unknown_ports_still_get_a_non_empty_payload() {
        assert!(!default_payload(9999).is_empty());
    }

    #[test]
    fn dns_probe_is_a_well_formed_query() {
        assert!(DNS_QUERY.len() > 12);
        let questions = u16::from_be_bytes([DNS_QUERY[4], DNS_QUERY[5]]);
        assert_eq!(questions, 1, "the query must declare exactly one question");
        let answers = u16::from_be_bytes([DNS_QUERY[6], DNS_QUERY[7]]);
        assert_eq!(answers, 0);
        assert_eq!(*DNS_QUERY.last().unwrap(), 0x03, "class should be CHAOS");
    }

    #[test]
    fn snmp_probe_lengths_are_self_consistent() {
        assert_eq!(SNMP_GET[0], 0x30);
        assert_eq!(
            usize::from(SNMP_GET[1]),
            SNMP_GET.len() - 2,
            "outer SEQUENCE length is wrong"
        );
    }

    #[test]
    fn netbios_probe_is_a_full_node_status_request() {
        assert_eq!(
            NETBIOS_STATUS.len(),
            50,
            "NetBIOS node status request is 50 bytes"
        );
        assert_eq!(NETBIOS_STATUS[12], 0x20, "encoded name is 32 bytes");
        assert_eq!(NETBIOS_STATUS[45], 0x00, "name must be null terminated");
        assert_eq!(
            &NETBIOS_STATUS[46..],
            &[0x00, 0x21, 0x00, 0x01],
            "QTYPE=NBSTAT QCLASS=IN"
        );
    }

    #[test]
    fn ike_probe_length_field_matches_the_payload() {
        let declared =
            u32::from_be_bytes([IKE_PROBE[24], IKE_PROBE[25], IKE_PROBE[26], IKE_PROBE[27]]);
        assert_eq!(declared as usize, IKE_PROBE.len());
    }

    #[test]
    fn ntp_probe_declares_client_mode() {
        assert_eq!(NTP_REQUEST[0], 0x1b);
        assert_eq!(NTP_REQUEST.len(), 48, "an NTP packet is 48 bytes");
    }
}
