use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::scanner::result::MacAddress;

const ETHERNET_HEADER: usize = 14;

const IPV4_HEADER: usize = 20;

const TCP_HEADER: usize = 20;

const ETHERTYPE_IPV4: u16 = 0x0800;

const ETHERTYPE_ARP: u16 = 0x0806;

const IPPROTO_TCP: u8 = 6;

const BROADCAST: [u8; 6] = [0xff; 6];

mod flags {
    pub const SYN: u8 = 0x02;

    pub const RST: u8 = 0x04;

    pub const ACK: u8 = 0x10;
}

fn checksum(data: &[u8], initial: u32) -> u16 {
    let mut sum = initial;
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

#[allow(clippy::too_many_arguments)]
pub fn build_syn_frame(
    source_mac: MacAddress,
    dest_mac: MacAddress,
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    source_port: u16,
    dest_port: u16,
    sequence: u32,
    ip_id: u16,
) -> Vec<u8> {
    let mut frame = vec![0u8; ETHERNET_HEADER + IPV4_HEADER + TCP_HEADER];

    frame[0..6].copy_from_slice(&dest_mac.0);
    frame[6..12].copy_from_slice(&source_mac.0);
    frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

    let ip = &mut frame[ETHERNET_HEADER..ETHERNET_HEADER + IPV4_HEADER];
    ip[0] = 0x45;
    ip[1] = 0;
    ip[2..4].copy_from_slice(&((IPV4_HEADER + TCP_HEADER) as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&ip_id.to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = IPPROTO_TCP;

    ip[12..16].copy_from_slice(&source_ip.octets());
    ip[16..20].copy_from_slice(&dest_ip.octets());
    let ip_checksum = checksum(ip, 0);
    ip[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let tcp_start = ETHERNET_HEADER + IPV4_HEADER;
    {
        let tcp = &mut frame[tcp_start..tcp_start + TCP_HEADER];
        tcp[0..2].copy_from_slice(&source_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&dest_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
        tcp[8..12].copy_from_slice(&0u32.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = flags::SYN;
        tcp[14..16].copy_from_slice(&1024u16.to_be_bytes());

        tcp[18..20].copy_from_slice(&0u16.to_be_bytes());
    }

    let pseudo = pseudo_header_sum(source_ip, dest_ip, TCP_HEADER as u16);
    let tcp_checksum = checksum(&frame[tcp_start..tcp_start + TCP_HEADER], pseudo);
    frame[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());

    frame
}

fn pseudo_header_sum(source: Ipv4Addr, dest: Ipv4Addr, length: u16) -> u32 {
    let mut sum = 0u32;
    for octets in [source.octets(), dest.octets()] {
        sum += u32::from(u16::from_be_bytes([octets[0], octets[1]]));
        sum += u32::from(u16::from_be_bytes([octets[2], octets[3]]));
    }
    sum += u32::from(IPPROTO_TCP);
    sum += u32::from(length);
    sum
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynReply {
    SynAck,
    Reset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedSynReply {
    pub source_ip: Ipv4Addr,
    pub source_port: u16,
    pub dest_port: u16,
    pub acknowledgement: u32,
    pub reply: SynReply,
    pub ttl: u8,
}

pub fn parse_syn_reply(frame: &[u8]) -> Option<ParsedSynReply> {
    if frame.len() < ETHERNET_HEADER + IPV4_HEADER + TCP_HEADER {
        return None;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != ETHERTYPE_IPV4 {
        return None;
    }

    let ip = &frame[ETHERNET_HEADER..];
    if ip[0] >> 4 != 4 {
        return None;
    }
    let ip_header_len = usize::from(ip[0] & 0x0f) * 4;
    if ip_header_len < IPV4_HEADER || ip.len() < ip_header_len + TCP_HEADER {
        return None;
    }
    if ip[9] != IPPROTO_TCP {
        return None;
    }

    let ttl = ip[8];
    let source_ip = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);

    let tcp = &ip[ip_header_len..];
    let source_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dest_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let acknowledgement = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let tcp_flags = tcp[13];

    let reply = if tcp_flags & flags::SYN != 0 && tcp_flags & flags::ACK != 0 {
        SynReply::SynAck
    } else if tcp_flags & flags::RST != 0 {
        SynReply::Reset
    } else {
        return None;
    };

    Some(ParsedSynReply {
        source_ip,
        source_port,
        dest_port,
        acknowledgement,
        reply,
        ttl,
    })
}

pub fn build_arp_request(
    source_mac: MacAddress,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut frame = vec![0u8; ETHERNET_HEADER + 28];

    frame[0..6].copy_from_slice(&BROADCAST);
    frame[6..12].copy_from_slice(&source_mac.0);
    frame[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());

    let arp = &mut frame[ETHERNET_HEADER..];
    arp[0..2].copy_from_slice(&1u16.to_be_bytes());
    arp[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    arp[4] = 6;
    arp[5] = 4;
    arp[6..8].copy_from_slice(&1u16.to_be_bytes());
    arp[8..14].copy_from_slice(&source_mac.0);
    arp[14..18].copy_from_slice(&source_ip.octets());

    arp[24..28].copy_from_slice(&target_ip.octets());

    frame
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpReply {
    pub ip: Ipv4Addr,
    pub mac: MacAddress,
}

pub fn parse_arp_reply(frame: &[u8]) -> Option<ArpReply> {
    if frame.len() < ETHERNET_HEADER + 28 {
        return None;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != ETHERTYPE_ARP {
        return None;
    }

    let arp = &frame[ETHERNET_HEADER..];
    if u16::from_be_bytes([arp[0], arp[1]]) != 1 {
        return None;
    }
    if u16::from_be_bytes([arp[2], arp[3]]) != ETHERTYPE_IPV4 {
        return None;
    }
    if arp[4] != 6 || arp[5] != 4 {
        return None;
    }
    if u16::from_be_bytes([arp[6], arp[7]]) != 2 {
        return None;
    }

    let mut mac = [0u8; 6];
    mac.copy_from_slice(&arp[8..14]);
    let ip = Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]);
    Some(ArpReply {
        ip,
        mac: MacAddress(mac),
    })
}

pub fn sequence_for(target: Ipv4Addr, port: u16, salt: u32) -> u32 {
    let base = u32::from(target);

    base.rotate_left(7) ^ (u32::from(port) << 16) ^ salt
}

pub fn acknowledges(ack: u32, target: Ipv4Addr, port: u16, salt: u32) -> bool {
    ack == sequence_for(target, port, salt).wrapping_add(1)
}

pub struct RawChannel {
    sender: Box<dyn pnet_datalink::DataLinkSender>,
    receiver: Box<dyn pnet_datalink::DataLinkReceiver>,
    pub source_mac: MacAddress,
    pub source_ip: Ipv4Addr,
    pub interface: String,
}

impl std::fmt::Debug for RawChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawChannel")
            .field("interface", &self.interface)
            .field("source_mac", &self.source_mac)
            .field("source_ip", &self.source_ip)
            .finish_non_exhaustive()
    }
}

impl RawChannel {
    pub fn open(interface: Option<&str>, read_timeout: Duration) -> Result<Self> {
        let interfaces = pnet_datalink::interfaces();

        let chosen = match interface {
            Some(name) => interfaces.iter().find(|i| i.name == name).ok_or_else(|| {
                let available: Vec<_> = interfaces.iter().map(|i| i.name.as_str()).collect();
                Error::Interface {
                    name: name.to_string(),
                    reason: format!("no such interface; available: {}", available.join(", ")),
                }
            })?,
            None => interfaces
                .iter()
                .find(|i| !i.is_loopback() && i.is_up() && i.ips.iter().any(|ip| ip.is_ipv4()))
                .ok_or_else(|| Error::Interface {
                    name: "*".to_string(),
                    reason: "no usable IPv4 interface found".to_string(),
                })?,
        };

        let source_mac = chosen
            .mac
            .map(|mac| MacAddress(mac.octets()))
            .ok_or_else(|| Error::Interface {
                name: chosen.name.clone(),
                reason: "interface has no hardware address; raw scanning needs Ethernet"
                    .to_string(),
            })?;

        let source_ip = chosen
            .ips
            .iter()
            .find_map(|ip| match ip.ip() {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            })
            .ok_or_else(|| Error::Interface {
                name: chosen.name.clone(),
                reason: "interface has no IPv4 address".to_string(),
            })?;

        let config = pnet_datalink::Config {
            read_timeout: Some(read_timeout),
            ..Default::default()
        };

        let (sender, receiver) = match pnet_datalink::channel(chosen, config) {
            Ok(pnet_datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                return Err(Error::Unsupported(
                    "the datalink backend returned a channel type netscan cannot use".to_string(),
                ))
            }
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(Error::privileges(
                    "raw socket scanning",
                    privilege_hint(&chosen.name),
                ))
            }
            Err(err) => {
                return Err(Error::Interface {
                    name: chosen.name.clone(),
                    reason: err.to_string(),
                })
            }
        };

        Ok(Self {
            sender,
            receiver,
            source_mac,
            source_ip,
            interface: chosen.name.clone(),
        })
    }

    pub fn send(&mut self, frame: &[u8]) -> Result<()> {
        match self.sender.send_to(frame, None) {
            Some(Ok(())) => Ok(()),
            Some(Err(err)) => Err(Error::Io(err)),
            None => Err(Error::Unsupported(
                "datalink send buffer unavailable".to_string(),
            )),
        }
    }

    pub fn recv(&mut self) -> Option<&[u8]> {
        self.receiver.next().ok()
    }
}

fn privilege_hint(interface: &str) -> String {
    if cfg!(target_os = "linux") {
        format!(
            "opening a datalink channel on {interface} needs root, or \
             `setcap cap_net_raw,cap_net_admin=eip` on the netscan binary"
        )
    } else if cfg!(target_os = "macos") {
        format!("opening a BPF device for {interface} needs root; run netscan with sudo")
    } else {
        format!(
            "opening a datalink channel on {interface} needs Administrator, and Npcap installed"
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynTarget {
    pub ip: Ipv4Addr,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SynOutcome {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub reply: SynReply,
    pub ttl: u8,
    pub rtt: Duration,
}

#[derive(Debug, Clone, Default)]
pub struct SynSweepResult {
    pub outcomes: Vec<SynOutcome>,
    pub macs: Vec<(Ipv4Addr, MacAddress)>,
    pub unresolved: Vec<Ipv4Addr>,
}

pub fn syn_sweep(
    interface: Option<&str>,
    targets: &[SynTarget],
    source_port: u16,
    salt: u32,
    timeout: Duration,
) -> Result<SynSweepResult> {
    let mut result = SynSweepResult::default();
    if targets.is_empty() {
        return Ok(result);
    }

    let mut channel = RawChannel::open(interface, Duration::from_millis(20))?;
    let source_mac = channel.source_mac;
    let source_ip = channel.source_ip;

    let wanted: Vec<Ipv4Addr> = targets.iter().map(|t| t.ip).collect();
    for ip in &wanted {
        let _ = channel.send(&build_arp_request(source_mac, source_ip, *ip));
    }

    let arp_deadline = Instant::now() + timeout.min(Duration::from_secs(2));
    let mut macs: HashMap<Ipv4Addr, MacAddress> = HashMap::new();
    while Instant::now() < arp_deadline && macs.len() < wanted.len() {
        let Some(frame) = channel.recv() else {
            continue;
        };
        if let Some(reply) = parse_arp_reply(frame) {
            if wanted.contains(&reply.ip) {
                macs.insert(reply.ip, reply.mac);
            }
        }
    }

    let mut sent_at: HashMap<(Ipv4Addr, u16), Instant> = HashMap::new();
    let mut expected = 0usize;
    let mut ip_id: u16 = 1;

    for target in targets {
        let Some(mac) = macs.get(&target.ip).copied() else {
            result.unresolved.push(target.ip);
            continue;
        };
        for port in &target.ports {
            let sequence = sequence_for(target.ip, *port, salt);
            ip_id = ip_id.wrapping_add(1);
            let frame = build_syn_frame(
                source_mac,
                mac,
                source_ip,
                target.ip,
                source_port,
                *port,
                sequence,
                ip_id,
            );
            if channel.send(&frame).is_ok() {
                sent_at.insert((target.ip, *port), Instant::now());
                expected += 1;
            }
        }
    }

    let deadline = Instant::now() + timeout;
    let mut seen: HashMap<(Ipv4Addr, u16), SynOutcome> = HashMap::new();

    while Instant::now() < deadline && seen.len() < expected {
        let Some(frame) = channel.recv() else {
            continue;
        };
        let Some(parsed) = parse_syn_reply(frame) else {
            continue;
        };
        if parsed.dest_port != source_port {
            continue;
        }
        let key = (parsed.source_ip, parsed.source_port);
        if !sent_at.contains_key(&key) {
            continue;
        }

        if parsed.reply == SynReply::SynAck
            && !acknowledges(
                parsed.acknowledgement,
                parsed.source_ip,
                parsed.source_port,
                salt,
            )
        {
            continue;
        }
        let rtt = sent_at.get(&key).map(|t| t.elapsed()).unwrap_or_default();
        seen.entry(key).or_insert(SynOutcome {
            ip: parsed.source_ip,
            port: parsed.source_port,
            reply: parsed.reply,
            ttl: parsed.ttl,
            rtt,
        });
    }

    result.outcomes = seen.into_values().collect();
    result.outcomes.sort_by_key(|o| (o.ip, o.port));
    result.macs = macs.into_iter().collect();
    result.macs.sort_by_key(|(ip, _)| *ip);
    Ok(result)
}

pub async fn syn_sweep_async(
    interface: Option<String>,
    targets: Vec<SynTarget>,
    source_port: u16,
    salt: u32,
    timeout: Duration,
) -> Result<SynSweepResult> {
    tokio::task::spawn_blocking(move || {
        syn_sweep(interface.as_deref(), &targets, source_port, salt, timeout)
    })
    .await
    .map_err(|e| Error::Unsupported(format!("SYN sweep task failed: {e}")))?
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC_MAC: MacAddress = MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    const DST_MAC: MacAddress = MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);

    fn syn() -> Vec<u8> {
        build_syn_frame(
            SRC_MAC,
            DST_MAC,
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(192, 168, 1, 20),
            54321,
            443,
            0xdead_beef,
            0x1234,
        )
    }

    #[test]
    fn syn_frame_has_the_right_length_and_ethertype() {
        let frame = syn();
        assert_eq!(frame.len(), ETHERNET_HEADER + IPV4_HEADER + TCP_HEADER);
        assert_eq!(&frame[0..6], &DST_MAC.0);
        assert_eq!(&frame[6..12], &SRC_MAC.0);
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), ETHERTYPE_IPV4);
    }

    #[test]
    fn syn_frame_ip_header_is_correct() {
        let frame = syn();
        let ip = &frame[ETHERNET_HEADER..ETHERNET_HEADER + IPV4_HEADER];
        assert_eq!(ip[0], 0x45, "IPv4 with a 20-byte header");
        assert_eq!(
            u16::from_be_bytes([ip[2], ip[3]]) as usize,
            IPV4_HEADER + TCP_HEADER
        );
        assert_eq!(ip[9], IPPROTO_TCP);
        assert_eq!(&ip[12..16], &[192, 168, 1, 10]);
        assert_eq!(&ip[16..20], &[192, 168, 1, 20]);
    }

    #[test]
    fn syn_frame_ip_checksum_validates() {
        let frame = syn();
        let ip = &frame[ETHERNET_HEADER..ETHERNET_HEADER + IPV4_HEADER];

        assert_eq!(checksum(ip, 0), 0, "IPv4 header checksum is wrong");
    }

    #[test]
    fn syn_frame_tcp_checksum_validates() {
        let frame = syn();
        let tcp_start = ETHERNET_HEADER + IPV4_HEADER;
        let tcp = &frame[tcp_start..tcp_start + TCP_HEADER];
        let pseudo = pseudo_header_sum(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(192, 168, 1, 20),
            TCP_HEADER as u16,
        );
        assert_eq!(checksum(tcp, pseudo), 0, "TCP checksum is wrong");
    }

    #[test]
    fn syn_frame_sets_only_the_syn_flag() {
        let frame = syn();
        let tcp_start = ETHERNET_HEADER + IPV4_HEADER;
        assert_eq!(frame[tcp_start + 13], flags::SYN);
        assert_eq!(
            frame[tcp_start + 12] >> 4,
            5,
            "data offset should be five words"
        );
        assert_eq!(
            u16::from_be_bytes([frame[tcp_start], frame[tcp_start + 1]]),
            54321
        );
        assert_eq!(
            u16::from_be_bytes([frame[tcp_start + 2], frame[tcp_start + 3]]),
            443
        );
        assert_eq!(
            u32::from_be_bytes([
                frame[tcp_start + 4],
                frame[tcp_start + 5],
                frame[tcp_start + 6],
                frame[tcp_start + 7]
            ]),
            0xdead_beef
        );
    }

    fn reply_frame(tcp_flags: u8, ack: u32) -> Vec<u8> {
        let mut frame = vec![0u8; ETHERNET_HEADER + IPV4_HEADER + TCP_HEADER];
        frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let ip = &mut frame[ETHERNET_HEADER..];
        ip[0] = 0x45;
        ip[8] = 57;
        ip[9] = IPPROTO_TCP;
        ip[12..16].copy_from_slice(&[192, 168, 1, 20]);
        ip[16..20].copy_from_slice(&[192, 168, 1, 10]);
        let tcp = &mut frame[ETHERNET_HEADER + IPV4_HEADER..];
        tcp[0..2].copy_from_slice(&443u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&54321u16.to_be_bytes());
        tcp[8..12].copy_from_slice(&ack.to_be_bytes());
        tcp[13] = tcp_flags;
        frame
    }

    #[test]
    fn syn_ack_is_recognised_as_open() {
        let parsed = parse_syn_reply(&reply_frame(flags::SYN | flags::ACK, 42)).unwrap();
        assert_eq!(parsed.reply, SynReply::SynAck);
        assert_eq!(parsed.source_ip, Ipv4Addr::new(192, 168, 1, 20));
        assert_eq!(parsed.source_port, 443);
        assert_eq!(parsed.dest_port, 54321);
        assert_eq!(parsed.acknowledgement, 42);
        assert_eq!(parsed.ttl, 57);
    }

    #[test]
    fn reset_is_recognised_as_closed() {
        let parsed = parse_syn_reply(&reply_frame(flags::RST | flags::ACK, 1)).unwrap();
        assert_eq!(parsed.reply, SynReply::Reset);
    }

    #[test]
    fn unrelated_frames_are_rejected() {
        assert!(parse_syn_reply(&reply_frame(flags::ACK, 1)).is_none());
        assert!(parse_syn_reply(&reply_frame(0x01, 1)).is_none());

        let mut arp_ish = reply_frame(flags::SYN | flags::ACK, 1);
        arp_ish[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        assert!(parse_syn_reply(&arp_ish).is_none());

        let mut udp = reply_frame(flags::SYN | flags::ACK, 1);
        udp[ETHERNET_HEADER + 9] = 17;
        assert!(parse_syn_reply(&udp).is_none());
    }

    #[test]
    fn truncated_frames_are_rejected_without_panicking() {
        let frame = reply_frame(flags::SYN | flags::ACK, 1);
        for cut in 0..frame.len() {
            let _ = parse_syn_reply(&frame[..cut]);
        }
        assert!(parse_syn_reply(&[]).is_none());
    }

    #[test]
    fn arp_request_is_well_formed() {
        let frame = build_arp_request(
            SRC_MAC,
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(192, 168, 1, 20),
        );
        assert_eq!(frame.len(), ETHERNET_HEADER + 28);
        assert_eq!(&frame[0..6], &BROADCAST, "requests must be broadcast");
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), ETHERTYPE_ARP);

        let arp = &frame[ETHERNET_HEADER..];
        assert_eq!(
            u16::from_be_bytes([arp[0], arp[1]]),
            1,
            "Ethernet hardware type"
        );
        assert_eq!(
            u16::from_be_bytes([arp[6], arp[7]]),
            1,
            "operation: request"
        );
        assert_eq!(&arp[14..18], &[192, 168, 1, 10]);
        assert_eq!(
            &arp[18..24],
            &[0; 6],
            "target hardware address is the question"
        );
        assert_eq!(&arp[24..28], &[192, 168, 1, 20]);
    }

    #[test]
    fn arp_replies_round_trip() {
        let mut frame = vec![0u8; ETHERNET_HEADER + 28];
        frame[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        let arp = &mut frame[ETHERNET_HEADER..];
        arp[0..2].copy_from_slice(&1u16.to_be_bytes());
        arp[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        arp[4] = 6;
        arp[5] = 4;
        arp[6..8].copy_from_slice(&2u16.to_be_bytes());
        arp[8..14].copy_from_slice(&[0x00, 0x1b, 0x63, 0x11, 0x22, 0x33]);
        arp[14..18].copy_from_slice(&[192, 168, 1, 20]);

        let reply = parse_arp_reply(&frame).unwrap();
        assert_eq!(reply.ip, Ipv4Addr::new(192, 168, 1, 20));
        assert_eq!(reply.mac.to_string(), "00:1b:63:11:22:33");
    }

    #[test]
    fn arp_requests_are_not_parsed_as_replies() {
        let request = build_arp_request(
            SRC_MAC,
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(192, 168, 1, 20),
        );
        assert!(
            parse_arp_reply(&request).is_none(),
            "a request is not a reply"
        );
    }

    #[test]
    fn sequence_numbers_distinguish_probes() {
        let a = Ipv4Addr::new(192, 168, 1, 10);
        let b = Ipv4Addr::new(192, 168, 1, 11);
        assert_ne!(sequence_for(a, 80, 7), sequence_for(a, 443, 7));
        assert_ne!(sequence_for(a, 80, 7), sequence_for(b, 80, 7));
        assert_ne!(sequence_for(a, 80, 7), sequence_for(a, 80, 8));
        assert_eq!(
            sequence_for(a, 80, 7),
            sequence_for(a, 80, 7),
            "must be deterministic"
        );
    }

    #[test]
    fn acknowledgements_are_matched_to_their_probe() {
        let target = Ipv4Addr::new(10, 0, 0, 5);
        let ack = sequence_for(target, 22, 99).wrapping_add(1);
        assert!(acknowledges(ack, target, 22, 99));
        assert!(!acknowledges(ack, target, 23, 99));
        assert!(!acknowledges(ack.wrapping_add(1), target, 22, 99));
    }

    #[test]
    fn sequence_matching_survives_wrapping() {
        let target = Ipv4Addr::new(255, 255, 255, 255);
        for port in [1u16, 80, 65535] {
            let seq = sequence_for(target, port, 0);
            assert!(acknowledges(seq.wrapping_add(1), target, port, 0));
        }
    }

    #[test]
    fn an_empty_sweep_needs_no_privileges() {
        let result = syn_sweep(None, &[], 40000, 1, Duration::from_millis(10)).unwrap();
        assert!(result.outcomes.is_empty());
        assert!(result.unresolved.is_empty());
    }

    #[tokio::test]
    async fn the_async_sweep_reports_errors_rather_than_panicking() {
        let result = syn_sweep_async(
            Some("definitely-not-an-interface".to_string()),
            vec![SynTarget {
                ip: Ipv4Addr::new(192, 168, 1, 1),
                ports: vec![80],
            }],
            40000,
            1,
            Duration::from_millis(50),
        )
        .await;
        assert!(result.is_err());
    }

    #[test]
    fn checksum_matches_the_rfc_example() {
        let data = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&data, 0), 0x220d);
    }
}
