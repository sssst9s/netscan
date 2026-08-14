use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
        }
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Transport {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "tcp" | "t" => Ok(Transport::Tcp),
            "udp" | "u" => Ok(Transport::Udp),
            other => Err(Error::Config(format!(
                "unknown transport `{other}`, expected tcp or udp"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn new(start: u16, end: u16) -> Result<Self> {
        if start == 0 || end == 0 {
            return Err(Error::invalid_ports(
                format!("{start}-{end}"),
                "port 0 is reserved and cannot be scanned",
            ));
        }
        if start > end {
            return Err(Error::invalid_ports(
                format!("{start}-{end}"),
                "range start must not be greater than range end",
            ));
        }
        Ok(Self { start, end })
    }

    pub fn single(port: u16) -> Result<Self> {
        Self::new(port, port)
    }

    pub fn len(&self) -> u32 {
        u32::from(self.end - self.start) + 1
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn iter(&self) -> impl Iterator<Item = u16> + '_ {
        self.start..=self.end
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PortSet {
    ports: Vec<u16>,
}

impl PortSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_iter_ordered<I: IntoIterator<Item = u16>>(iter: I) -> Self {
        let mut seen = vec![false; 65_536];
        let mut ports = Vec::new();
        for port in iter {
            if port == 0 {
                continue;
            }
            let slot = &mut seen[usize::from(port)];
            if !*slot {
                *slot = true;
                ports.push(port);
            }
        }
        Self { ports }
    }

    pub fn len(&self) -> usize {
        self.ports.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ports.is_empty()
    }

    pub fn as_slice(&self) -> &[u16] {
        &self.ports
    }

    pub fn iter(&self) -> std::slice::Iter<'_, u16> {
        self.ports.iter()
    }

    pub fn contains(&self, port: u16) -> bool {
        self.ports.contains(&port)
    }

    pub fn sorted(&self) -> Vec<u16> {
        let mut v = self.ports.clone();
        v.sort_unstable();
        v
    }

    pub fn merge(&mut self, other: &PortSet) {
        let merged = self
            .ports
            .iter()
            .copied()
            .chain(other.ports.iter().copied());
        *self = PortSet::from_iter_ordered(merged.collect::<Vec<_>>());
    }

    pub fn to_ranges(&self) -> Vec<PortRange> {
        let sorted = self.sorted();
        let mut out: Vec<PortRange> = Vec::new();
        for port in sorted {
            match out.last_mut() {
                Some(last) if port == last.end + 1 => last.end = port,
                Some(last) if port == last.end => {}
                _ => out.push(PortRange {
                    start: port,
                    end: port,
                }),
            }
        }
        out
    }
}

impl fmt::Display for PortSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ranges = self.to_ranges();
        for (i, range) in ranges.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{range}")?;
        }
        Ok(())
    }
}

impl IntoIterator for PortSet {
    type Item = u16;
    type IntoIter = std::vec::IntoIter<u16>;

    fn into_iter(self) -> Self::IntoIter {
        self.ports.into_iter()
    }
}

impl<'a> IntoIterator for &'a PortSet {
    type Item = &'a u16;
    type IntoIter = std::slice::Iter<'a, u16>;

    fn into_iter(self) -> Self::IntoIter {
        self.ports.iter()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortSelection {
    pub tcp: PortSet,
    pub udp: PortSet,
}

impl PortSelection {
    pub fn tcp(ports: PortSet) -> Self {
        Self {
            tcp: ports,
            udp: PortSet::new(),
        }
    }

    pub fn udp(ports: PortSet) -> Self {
        Self {
            tcp: PortSet::new(),
            udp: ports,
        }
    }

    pub fn total(&self) -> usize {
        self.tcp.len() + self.udp.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tcp.is_empty() && self.udp.is_empty()
    }

    pub fn merge(&mut self, other: &PortSelection) {
        self.tcp.merge(&other.tcp);
        self.udp.merge(&other.udp);
    }

    pub fn for_transport(&self, transport: Transport) -> &PortSet {
        match transport {
            Transport::Tcp => &self.tcp,
            Transport::Udp => &self.udp,
        }
    }

    pub fn for_transport_mut(&mut self, transport: Transport) -> &mut PortSet {
        match transport {
            Transport::Tcp => &mut self.tcp,
            Transport::Udp => &mut self.udp,
        }
    }
}

impl fmt::Display for PortSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.tcp.is_empty(), self.udp.is_empty()) {
            (true, true) => f.write_str("(none)"),
            (false, true) => write!(f, "{}", self.tcp),
            (true, false) => write!(f, "U:{}", self.udp),
            (false, false) => write!(f, "T:{},U:{}", self.tcp, self.udp),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PortSpec {
    pub entries: Vec<(Transport, PortRange)>,
}

impl PortSpec {
    pub fn parse(input: &str, default_transport: Transport) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(Error::invalid_ports(input, "port specification is empty"));
        }

        let mut entries = Vec::new();
        let mut transport = default_transport;

        for raw_item in trimmed.split(',') {
            let mut item = raw_item.trim();
            if item.is_empty() {
                return Err(Error::invalid_ports(input, "empty entry in port list"));
            }

            if let Some(rest) = strip_transport_prefix(item) {
                let (prefix, remainder) = rest;
                transport = prefix;
                item = remainder.trim();
                if item.is_empty() {
                    return Err(Error::invalid_ports(
                        input,
                        format!(
                            "`{}:` must be followed by at least one port",
                            prefix.as_str()
                        ),
                    ));
                }
            }

            entries.push((transport, parse_range(input, item)?));
        }

        Ok(Self { entries })
    }

    pub fn upper_bound(&self) -> u64 {
        self.entries.iter().map(|(_, r)| u64::from(r.len())).sum()
    }

    pub fn resolve(&self) -> PortSelection {
        let mut tcp = Vec::new();
        let mut udp = Vec::new();
        for (transport, range) in &self.entries {
            let sink = match transport {
                Transport::Tcp => &mut tcp,
                Transport::Udp => &mut udp,
            };
            sink.extend(range.iter());
        }
        PortSelection {
            tcp: PortSet::from_iter_ordered(tcp),
            udp: PortSet::from_iter_ordered(udp),
        }
    }
}

impl fmt::Display for PortSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut current: Option<Transport> = None;
        for (i, (transport, range)) in self.entries.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            if current != Some(*transport) {
                write!(
                    f,
                    "{}:",
                    transport
                        .as_str()
                        .to_ascii_uppercase()
                        .chars()
                        .next()
                        .unwrap_or('T')
                )?;
                current = Some(*transport);
            }
            write!(f, "{range}")?;
        }
        Ok(())
    }
}

fn strip_transport_prefix(item: &str) -> Option<(Transport, &str)> {
    let (prefix, rest) = item.split_once(':')?;
    let transport = prefix.trim().parse::<Transport>().ok()?;
    Some((transport, rest))
}

fn parse_range(original: &str, item: &str) -> Result<PortRange> {
    if item == "-" {
        return PortRange::new(1, 65_535);
    }

    if let Some(rest) = item.strip_prefix('-') {
        let end = parse_port(original, rest)?;
        return PortRange::new(1, end);
    }
    if let Some(rest) = item.strip_suffix('-') {
        let start = parse_port(original, rest)?;
        return PortRange::new(start, 65_535);
    }

    match item.split_once('-') {
        Some((lhs, rhs)) => {
            let start = parse_port(original, lhs)?;
            let end = parse_port(original, rhs)?;
            PortRange::new(start, end)
        }
        None => PortRange::single(parse_port(original, item)?),
    }
}

fn parse_port(original: &str, text: &str) -> Result<u16> {
    let text = text.trim();
    if text.is_empty() {
        return Err(Error::invalid_ports(original, "missing port number"));
    }
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::invalid_ports(
            original,
            format!("`{text}` is not a port number"),
        ));
    }
    text.parse::<u16>().map_err(|_| {
        Error::invalid_ports(
            original,
            format!("`{text}` is out of range, ports are 1-65535"),
        )
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PortPreset {
    Common,
    Web,
    Database,
    RemoteAccess,
    Mail,
    Management,
}

impl PortPreset {
    pub const ALL: &'static [PortPreset] = &[
        PortPreset::Common,
        PortPreset::Web,
        PortPreset::Database,
        PortPreset::RemoteAccess,
        PortPreset::Mail,
        PortPreset::Management,
    ];

    pub fn name(self) -> &'static str {
        match self {
            PortPreset::Common => "common",
            PortPreset::Web => "web",
            PortPreset::Database => "database",
            PortPreset::RemoteAccess => "remote-access",
            PortPreset::Mail => "mail",
            PortPreset::Management => "management",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            PortPreset::Common => "the 100 most commonly open TCP ports",
            PortPreset::Web => "HTTP, HTTPS and common alternate web ports",
            PortPreset::Database => "relational, document, cache and search databases",
            PortPreset::RemoteAccess => "SSH, RDP, VNC, Telnet and remote management",
            PortPreset::Mail => "SMTP, IMAP, POP3 and their TLS variants",
            PortPreset::Management => "SNMP, IPMI, printers and appliance interfaces",
        }
    }

    pub fn selection(self) -> PortSelection {
        match self {
            PortPreset::Common => PortSelection::tcp(crate::detection::service::top_tcp_ports(100)),
            PortPreset::Web => PortSelection::tcp(PortSet::from_iter_ordered([
                80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000, 8081, 8181, 9000, 9090, 8880,
                4443, 10000, 2082, 2083, 7001, 9200, 5601, 8090, 8009,
            ])),
            PortPreset::Database => PortSelection {
                tcp: PortSet::from_iter_ordered([
                    3306, 5432, 1433, 1521, 27017, 27018, 27019, 6379, 11211, 9042, 9200, 9300,
                    5984, 8086, 7000, 7199, 2181, 26257, 5433, 50000, 8123, 9160,
                ]),
                udp: PortSet::from_iter_ordered([1434, 11211]),
            },
            PortPreset::RemoteAccess => PortSelection::tcp(PortSet::from_iter_ordered([
                22, 23, 3389, 5900, 5901, 5902, 5985, 5986, 512, 513, 514, 992, 2222, 5938, 3283,
                4899, 6129,
            ])),
            PortPreset::Mail => PortSelection::tcp(PortSet::from_iter_ordered([
                25, 110, 143, 465, 587, 993, 995, 2525, 24, 209,
            ])),
            PortPreset::Management => PortSelection {
                tcp: PortSet::from_iter_ordered([
                    161, 623, 9100, 515, 631, 8443, 10000, 5985, 5986, 902, 903, 16992, 16993,
                    2379, 2380, 8500, 4505, 4506,
                ]),
                udp: PortSet::from_iter_ordered([161, 162, 623, 69, 67, 68, 5353, 1900]),
            },
        }
    }
}

impl fmt::Display for PortPreset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for PortPreset {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let normalised = s.trim().to_ascii_lowercase().replace('_', "-");
        PortPreset::ALL
            .iter()
            .copied()
            .find(|p| p.name() == normalised)
            .ok_or_else(|| {
                let names: Vec<_> = PortPreset::ALL.iter().map(|p| p.name()).collect();
                Error::invalid_ports(
                    s,
                    format!("unknown preset, expected one of: {}", names.join(", ")),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_ports(input: &str) -> Vec<u16> {
        PortSpec::parse(input, Transport::Tcp)
            .unwrap()
            .resolve()
            .tcp
            .as_slice()
            .to_vec()
    }

    #[test]
    fn parses_single_port() {
        assert_eq!(tcp_ports("80"), vec![80]);
    }

    #[test]
    fn parses_list() {
        assert_eq!(tcp_ports("22,80,443"), vec![22, 80, 443]);
    }

    #[test]
    fn parses_range() {
        assert_eq!(tcp_ports("20-25"), vec![20, 21, 22, 23, 24, 25]);
    }

    #[test]
    fn parses_mixed_list_and_ranges() {
        assert_eq!(
            tcp_ports("22,80,443,8000-8003"),
            vec![22, 80, 443, 8000, 8001, 8002, 8003]
        );
    }

    #[test]
    fn preserves_user_order_and_deduplicates() {
        assert_eq!(tcp_ports("443,80,443,22,80"), vec![443, 80, 22]);
    }

    #[test]
    fn open_ended_ranges() {
        assert_eq!(tcp_ports("-3"), vec![1, 2, 3]);
        let high = tcp_ports("65533-");
        assert_eq!(high, vec![65533, 65534, 65535]);
        assert_eq!(
            PortSpec::parse("-", Transport::Tcp).unwrap().upper_bound(),
            65_535
        );
    }

    #[test]
    fn transport_prefixes_split_protocols() {
        let spec = PortSpec::parse("T:80,443,U:53,161", Transport::Tcp).unwrap();
        let sel = spec.resolve();
        assert_eq!(sel.tcp.as_slice(), &[80, 443]);
        assert_eq!(sel.udp.as_slice(), &[53, 161]);
    }

    #[test]
    fn transport_prefix_is_sticky_until_changed() {
        let sel = PortSpec::parse("U:53,67,68,T:22", Transport::Tcp)
            .unwrap()
            .resolve();
        assert_eq!(sel.udp.as_slice(), &[53, 67, 68]);
        assert_eq!(sel.tcp.as_slice(), &[22]);
    }

    #[test]
    fn default_transport_is_honoured() {
        let sel = PortSpec::parse("53,161", Transport::Udp).unwrap().resolve();
        assert!(sel.tcp.is_empty());
        assert_eq!(sel.udp.as_slice(), &[53, 161]);
    }

    #[test]
    fn whitespace_is_tolerated() {
        assert_eq!(
            tcp_ports(" 22 , 80 , 100 - 102 "),
            vec![22, 80, 100, 101, 102]
        );
    }

    #[test]
    fn rejects_invalid_specifications() {
        for bad in [
            "", "  ", "abc", "0", "80,", ",80", "70000", "100-50", "80-abc", "22,,80", "T:",
        ] {
            assert!(
                PortSpec::parse(bad, Transport::Tcp).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn error_messages_quote_the_offending_token() {
        let err = PortSpec::parse("22,abc,80", Transport::Tcp).unwrap_err();
        assert!(err.to_string().contains("`abc`"), "message was: {err}");
    }

    #[test]
    fn upper_bound_does_not_materialise() {
        let spec = PortSpec::parse("1-65535", Transport::Tcp).unwrap();
        assert_eq!(spec.upper_bound(), 65_535);
    }

    #[test]
    fn port_set_compacts_into_ranges() {
        let set = PortSet::from_iter_ordered([7, 1, 2, 3, 9, 10]);
        assert_eq!(set.to_string(), "1-3,7,9-10");
    }

    #[test]
    fn port_set_merge_keeps_order_and_dedups() {
        let mut a = PortSet::from_iter_ordered([443, 80]);
        a.merge(&PortSet::from_iter_ordered([80, 22]));
        assert_eq!(a.as_slice(), &[443, 80, 22]);
    }

    #[test]
    fn selection_display_is_round_trippable() {
        let sel = PortSpec::parse("T:22,80,U:53", Transport::Tcp)
            .unwrap()
            .resolve();
        assert_eq!(sel.to_string(), "T:22,80,U:53");
        let reparsed = PortSpec::parse(&sel.to_string(), Transport::Tcp)
            .unwrap()
            .resolve();
        assert_eq!(reparsed, sel);
    }

    #[test]
    fn presets_are_non_empty_and_named() {
        for preset in PortPreset::ALL {
            let sel = preset.selection();
            assert!(!sel.is_empty(), "{} preset is empty", preset.name());
            assert_eq!(preset.name().parse::<PortPreset>().unwrap(), *preset);
            assert!(!preset.description().is_empty());
        }
    }

    #[test]
    fn preset_parsing_normalises_separators() {
        assert_eq!(
            "remote_access".parse::<PortPreset>().unwrap(),
            PortPreset::RemoteAccess
        );
        assert_eq!("  WEB ".parse::<PortPreset>().unwrap(), PortPreset::Web);
        assert!("nonsense".parse::<PortPreset>().is_err());
    }

    #[test]
    fn transport_parsing() {
        assert_eq!("tcp".parse::<Transport>().unwrap(), Transport::Tcp);
        assert_eq!("U".parse::<Transport>().unwrap(), Transport::Udp);
        assert!("sctp".parse::<Transport>().is_err());
    }

    #[test]
    fn port_range_rejects_zero() {
        assert!(PortRange::new(0, 10).is_err());
        assert!(PortRange::single(0).is_err());
    }
}
