use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

use crate::error::{Error, Result};

const MAGIC: &[u8; 8] = b"netscan\0";

const ICMPV4_ECHO_REQUEST: u8 = 8;

const ICMPV4_ECHO_REPLY: u8 = 0;

const ICMPV6_ECHO_REQUEST: u8 = 128;

const ICMPV6_ECHO_REPLY: u8 = 129;

#[derive(Debug, Clone, PartialEq)]
pub struct PingResult {
    pub responded: bool,
    pub rtt: Option<Duration>,
    pub ttl: Option<u8>,
}

impl PingResult {
    pub fn silent() -> Self {
        Self {
            responded: false,
            rtt: None,
            ttl: None,
        }
    }
}

#[derive(Debug)]
pub struct IcmpPinger {
    socket: tokio::net::UdpSocket,
    ipv6: bool,
}

impl IcmpPinger {
    pub fn new(ipv6: bool) -> Result<Self> {
        let (domain, protocol) = if ipv6 {
            (Domain::IPV6, Protocol::ICMPV6)
        } else {
            (Domain::IPV4, Protocol::ICMPV4)
        };

        let socket =
            Socket::new(domain, Type::DGRAM, Some(protocol)).map_err(|err| match err.kind() {
                io::ErrorKind::PermissionDenied => {
                    Error::privileges("ICMP echo", icmp_permission_hint())
                }
                _ => Error::privileges("ICMP echo", format!("{err}")),
            })?;

        socket.set_nonblocking(true)?;
        let std_socket: std::net::UdpSocket = socket.into();
        let socket = tokio::net::UdpSocket::from_std(std_socket)?;

        Ok(Self { socket, ipv6 })
    }

    pub fn is_available(ipv6: bool) -> bool {
        Self::new(ipv6).is_ok()
    }

    pub async fn ping(&self, target: IpAddr, sequence: u16, timeout: Duration) -> PingResult {
        if target.is_ipv6() != self.ipv6 {
            return PingResult::silent();
        }

        let packet = build_echo_request(self.ipv6, sequence);
        let destination = SocketAddr::new(target, 0);

        let started = Instant::now();
        if self.socket.send_to(&packet, destination).await.is_err() {
            return PingResult::silent();
        }

        let deadline = started + timeout;
        let mut buffer = vec![0u8; 1500];

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return PingResult::silent();
            }
            match tokio::time::timeout(remaining, self.socket.recv_from(&mut buffer)).await {
                Ok(Ok((len, from))) => {
                    if from.ip() != target {
                        continue;
                    }
                    if let Some(ttl) = parse_echo_reply(&buffer[..len], self.ipv6, sequence) {
                        return PingResult {
                            responded: true,
                            rtt: Some(started.elapsed()),
                            ttl,
                        };
                    }
                }

                Ok(Err(_)) | Err(_) => return PingResult::silent(),
            }
        }
    }
}

fn icmp_permission_hint() -> String {
    if cfg!(target_os = "linux") {
        "on Linux, allow unprivileged ICMP with \
         `sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"`, or run as root"
            .to_string()
    } else if cfg!(windows) {
        "on Windows, ICMP echo requires Administrator".to_string()
    } else {
        "run with elevated privileges".to_string()
    }
}

fn build_echo_request(ipv6: bool, sequence: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(8 + MAGIC.len() + 8);
    packet.push(if ipv6 {
        ICMPV6_ECHO_REQUEST
    } else {
        ICMPV4_ECHO_REQUEST
    });
    packet.push(0);
    packet.extend_from_slice(&[0, 0]);

    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(MAGIC);
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&[0u8; 6]);

    if !ipv6 {
        let checksum = internet_checksum(&packet);
        packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    }

    packet
}

fn parse_echo_reply(data: &[u8], ipv6: bool, sequence: u16) -> Option<Option<u8>> {
    let (icmp, ttl) = strip_ip_header(data, ipv6);
    if icmp.len() < 8 {
        return None;
    }

    let expected_type = if ipv6 {
        ICMPV6_ECHO_REPLY
    } else {
        ICMPV4_ECHO_REPLY
    };
    if icmp[0] != expected_type || icmp[1] != 0 {
        return None;
    }

    let reply_sequence = u16::from_be_bytes([icmp[6], icmp[7]]);
    if reply_sequence != sequence {
        return None;
    }

    let payload = &icmp[8..];
    if payload.len() >= MAGIC.len() && &payload[..MAGIC.len()] == MAGIC {
        Some(ttl)
    } else {
        None
    }
}

fn strip_ip_header(data: &[u8], ipv6: bool) -> (&[u8], Option<u8>) {
    if ipv6 || data.len() < 20 {
        return (data, None);
    }
    let version = data[0] >> 4;
    let header_len = usize::from(data[0] & 0x0f) * 4;
    if version == 4 && (20..=60).contains(&header_len) && data.len() > header_len {
        (&data[header_len..], Some(data[8]))
    } else {
        (data, None)
    }
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(*last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_matches_known_values() {
        let data = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(internet_checksum(&data), 0x220d);
    }

    #[test]
    fn checksum_handles_odd_lengths() {
        let odd = [0x01u8, 0x02, 0x03];
        let even = [0x01u8, 0x02];
        assert_ne!(internet_checksum(&odd), internet_checksum(&even));
    }

    #[test]
    fn checksum_of_a_packet_including_its_own_checksum_is_zero() {
        let packet = build_echo_request(false, 42);
        assert_eq!(
            internet_checksum(&packet),
            0,
            "checksum should validate in place"
        );
    }

    #[test]
    fn echo_request_has_the_right_shape() {
        let v4 = build_echo_request(false, 7);
        assert_eq!(v4[0], ICMPV4_ECHO_REQUEST);
        assert_eq!(v4[1], 0);
        assert_eq!(u16::from_be_bytes([v4[6], v4[7]]), 7, "sequence number");
        assert_ne!(&v4[2..4], &[0, 0], "IPv4 checksum must be filled in");

        let v6 = build_echo_request(true, 7);
        assert_eq!(v6[0], ICMPV6_ECHO_REQUEST);
        assert_eq!(&v6[2..4], &[0, 0], "IPv6 checksum is the kernel's job");
    }

    #[test]
    fn reply_matching_requires_the_right_type_sequence_and_magic() {
        let mut reply = build_echo_request(false, 99);
        reply[0] = ICMPV4_ECHO_REPLY;
        assert_eq!(parse_echo_reply(&reply, false, 99), Some(None));

        assert_eq!(parse_echo_reply(&reply, false, 98), None);

        let mut foreign = reply.clone();
        foreign[8..16].copy_from_slice(b"someones");
        assert_eq!(parse_echo_reply(&foreign, false, 99), None);

        let request = build_echo_request(false, 99);
        assert_eq!(parse_echo_reply(&request, false, 99), None);
    }

    #[test]
    fn truncated_replies_are_rejected() {
        assert_eq!(parse_echo_reply(&[], false, 1), None);
        assert_eq!(parse_echo_reply(&[0, 0, 0], false, 1), None);
    }

    #[test]
    fn ip_header_is_detected_and_yields_the_ttl() {
        let mut datagram = vec![0u8; 20];
        datagram[0] = 0x45;
        datagram[8] = 57;
        let mut echo = build_echo_request(false, 5);
        echo[0] = ICMPV4_ECHO_REPLY;
        datagram.extend_from_slice(&echo);

        assert_eq!(parse_echo_reply(&datagram, false, 5), Some(Some(57)));
    }

    #[test]
    fn bare_icmp_messages_are_handled_without_an_ip_header() {
        let mut echo = build_echo_request(false, 5);
        echo[0] = ICMPV4_ECHO_REPLY;
        let (stripped, ttl) = strip_ip_header(&echo, false);
        assert_eq!(stripped.len(), echo.len());
        assert_eq!(ttl, None);
    }

    #[tokio::test]
    async fn pinging_loopback_works_or_reports_a_privilege_problem() {
        match IcmpPinger::new(false) {
            Ok(pinger) => {
                let result = pinger
                    .ping("127.0.0.1".parse().unwrap(), 1, Duration::from_secs(2))
                    .await;
                assert!(
                    result.responded,
                    "loopback should answer its own echo request"
                );
                assert!(result.rtt.is_some());
            }
            Err(err) => {
                assert!(
                    matches!(err, Error::PrivilegesRequired { .. }),
                    "unexpected error: {err}"
                );
                assert!(err.to_string().contains("ICMP echo"));
            }
        }
    }

    #[tokio::test]
    async fn family_mismatch_is_a_silent_no_op() {
        let Ok(pinger) = IcmpPinger::new(false) else {
            return;
        };
        let result = pinger
            .ping("::1".parse().unwrap(), 1, Duration::from_millis(50))
            .await;
        assert!(!result.responded);
    }
}
