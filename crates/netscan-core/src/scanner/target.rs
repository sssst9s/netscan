use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::{IpAddrRange, IpNet, Ipv4AddrRange, Ipv4Net, Ipv6AddrRange, Ipv6Net};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IpFamily {
    #[default]
    V4,
    V6,
    Both,
}

impl IpFamily {
    pub fn accepts(self, addr: &IpAddr) -> bool {
        match self {
            IpFamily::V4 => addr.is_ipv4(),
            IpFamily::V6 => addr.is_ipv6(),
            IpFamily::Both => true,
        }
    }
}

impl fmt::Display for IpFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpFamily::V4 => f.write_str("ipv4"),
            IpFamily::V6 => f.write_str("ipv6"),
            IpFamily::Both => f.write_str("both"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum TargetSpec {
    Address { addr: IpAddr },
    Cidr { net: IpNet },
    Range { start: IpAddr, end: IpAddr },
    Hostname { name: String },
}

impl TargetSpec {
    pub fn address_count(&self, skip_network_addresses: bool) -> u64 {
        match self {
            TargetSpec::Address { .. } | TargetSpec::Hostname { .. } => 1,
            TargetSpec::Cidr { net } => cidr_len(net, skip_network_addresses),
            TargetSpec::Range { start, end } => range_len(*start, *end),
        }
    }

    pub fn needs_resolution(&self) -> bool {
        matches!(self, TargetSpec::Hostname { .. })
    }

    pub fn matches_family(&self, family: IpFamily) -> bool {
        match self {
            TargetSpec::Hostname { .. } => true,
            TargetSpec::Address { addr } => family.accepts(addr),
            TargetSpec::Cidr { net } => family.accepts(&net.addr()),
            TargetSpec::Range { start, .. } => family.accepts(start),
        }
    }

    pub fn addresses(&self, skip_network_addresses: bool) -> Option<AddressIter> {
        match self {
            TargetSpec::Address { addr } => Some(AddressIter::Single(Some(*addr))),
            TargetSpec::Cidr { net } => {
                Some(AddressIter::Range(cidr_iter(net, skip_network_addresses)))
            }
            TargetSpec::Range { start, end } => Some(AddressIter::Range(range_iter(*start, *end)?)),
            TargetSpec::Hostname { .. } => None,
        }
    }
}

impl fmt::Display for TargetSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetSpec::Address { addr } => write!(f, "{addr}"),
            TargetSpec::Cidr { net } => write!(f, "{net}"),
            TargetSpec::Range { start, end } => write!(f, "{start}-{end}"),
            TargetSpec::Hostname { name } => f.write_str(name),
        }
    }
}

impl FromStr for TargetSpec {
    type Err = Error;

    fn from_str(raw: &str) -> Result<Self> {
        let input = raw.trim();
        if input.is_empty() {
            return Err(Error::invalid_target(raw, "target is empty"));
        }

        let unbracketed = input
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(input);

        if let Ok(addr) = unbracketed.parse::<IpAddr>() {
            return Ok(TargetSpec::Address { addr });
        }

        if input.contains('/') {
            return parse_cidr(input);
        }

        if let Some((lhs, rhs)) = input.split_once('-') {
            if lhs.parse::<IpAddr>().is_ok() {
                return parse_range(input, lhs, rhs);
            }
        }

        if is_plausible_hostname(input) {
            return Ok(TargetSpec::Hostname {
                name: input.to_ascii_lowercase(),
            });
        }

        Err(Error::invalid_target(
            raw,
            "not an IP address, CIDR block, address range or DNS name",
        ))
    }
}

fn parse_cidr(input: &str) -> Result<TargetSpec> {
    let (addr_part, prefix_part) = input.split_once('/').unwrap_or((input, ""));

    if addr_part.parse::<IpAddr>().is_err() {
        return Err(Error::invalid_target(
            input,
            "CIDR notation requires a literal IP address before the `/`",
        ));
    }

    let prefix: u8 = prefix_part
        .parse()
        .map_err(|_| Error::invalid_target(input, "prefix length must be a number"))?;

    let net: IpNet = input.parse().map_err(|_| {
        let max = if addr_part.contains(':') { 128 } else { 32 };
        Error::invalid_target(input, format!("prefix length must be between 0 and {max}"))
    })?;
    debug_assert_eq!(net.prefix_len(), prefix);

    Ok(TargetSpec::Cidr { net: net.trunc() })
}

fn parse_range(input: &str, lhs: &str, rhs: &str) -> Result<TargetSpec> {
    let start: IpAddr = lhs
        .parse()
        .map_err(|_| Error::invalid_target(input, "range start is not an IP address"))?;

    let end: IpAddr = match rhs.parse::<IpAddr>() {
        Ok(end) => end,
        Err(_) => {
            let last_octet: u8 = rhs.parse().map_err(|_| {
                Error::invalid_target(
                    input,
                    "range end must be a full IP address or a final-octet number (0-255)",
                )
            })?;
            match start {
                IpAddr::V4(v4) => {
                    let mut octets = v4.octets();
                    octets[3] = last_octet;
                    IpAddr::V4(Ipv4Addr::from(octets))
                }
                IpAddr::V6(_) => {
                    return Err(Error::invalid_target(
                        input,
                        "IPv6 ranges require a full address on both sides",
                    ))
                }
            }
        }
    };

    match (start, end) {
        (IpAddr::V4(a), IpAddr::V4(b)) if a > b => Err(Error::invalid_target(
            input,
            "range start must not be greater than range end",
        )),
        (IpAddr::V6(a), IpAddr::V6(b)) if a > b => Err(Error::invalid_target(
            input,
            "range start must not be greater than range end",
        )),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
            Ok(TargetSpec::Range { start, end })
        }
        _ => Err(Error::invalid_target(
            input,
            "range endpoints mix IPv4 and IPv6",
        )),
    }
}

fn is_plausible_hostname(input: &str) -> bool {
    if input.len() > 253 {
        return false;
    }
    let name = input.strip_suffix('.').unwrap_or(input);
    if name.is_empty() {
        return false;
    }

    let last_label = name.rsplit('.').next().unwrap_or(name);
    if last_label.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

#[derive(Debug, Clone)]
pub enum AddressIter {
    Single(Option<IpAddr>),
    Range(IpAddrRange),
}

impl Iterator for AddressIter {
    type Item = IpAddr;

    fn next(&mut self) -> Option<IpAddr> {
        match self {
            AddressIter::Single(slot) => slot.take(),
            AddressIter::Range(range) => range.next(),
        }
    }
}

fn cidr_len(net: &IpNet, skip_network_addresses: bool) -> u64 {
    match net {
        IpNet::V4(v4) => {
            let host_bits = 32 - u32::from(v4.prefix_len());
            let total = 1u64 << host_bits;
            if skip_network_addresses && v4.prefix_len() < 31 {
                total - 2
            } else {
                total
            }
        }
        IpNet::V6(v6) => {
            let host_bits = 128 - u32::from(v6.prefix_len());

            if host_bits >= 64 {
                u64::MAX
            } else {
                1u64 << host_bits
            }
        }
    }
}

fn cidr_iter(net: &IpNet, skip_network_addresses: bool) -> IpAddrRange {
    match net {
        IpNet::V4(v4) => {
            if skip_network_addresses && v4.prefix_len() < 31 {
                IpAddrRange::V4(v4.hosts())
            } else {
                IpAddrRange::V4(Ipv4AddrRange::new(v4.network(), v4.broadcast()))
            }
        }
        IpNet::V6(v6) => IpAddrRange::V6(Ipv6AddrRange::new(v6.network(), v6.broadcast())),
    }
}

fn range_len(start: IpAddr, end: IpAddr) -> u64 {
    match (start, end) {
        (IpAddr::V4(a), IpAddr::V4(b)) => u64::from(u32::from(b).saturating_sub(u32::from(a))) + 1,
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let diff = u128::from(b)
                .saturating_sub(u128::from(a))
                .saturating_add(1);
            u64::try_from(diff).unwrap_or(u64::MAX)
        }
        _ => 0,
    }
}

fn range_iter(start: IpAddr, end: IpAddr) -> Option<IpAddrRange> {
    match (start, end) {
        (IpAddr::V4(a), IpAddr::V4(b)) => Some(IpAddrRange::V4(Ipv4AddrRange::new(a, b))),
        (IpAddr::V6(a), IpAddr::V6(b)) => Some(IpAddrRange::V6(Ipv6AddrRange::new(a, b))),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    pub addr: IpAddr,
    pub source_hostname: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TargetResolver {
    pub max_targets: u64,
    pub family: IpFamily,
    pub include_network_addresses: bool,
    pub exclusions: Vec<TargetSpec>,
}

impl Default for TargetResolver {
    fn default() -> Self {
        Self {
            max_targets: crate::config::Limits::default().max_targets,
            family: IpFamily::default(),
            include_network_addresses: false,
            exclusions: Vec::new(),
        }
    }
}

impl TargetResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_targets(mut self, max: u64) -> Self {
        self.max_targets = max;
        self
    }

    pub fn with_family(mut self, family: IpFamily) -> Self {
        self.family = family;
        self
    }

    pub fn with_exclusions(mut self, exclusions: Vec<TargetSpec>) -> Self {
        self.exclusions = exclusions;
        self
    }

    pub fn estimate(&self, specs: &[TargetSpec]) -> u64 {
        specs
            .iter()
            .filter(|spec| spec.matches_family(self.family))
            .fold(0u64, |acc, spec| {
                acc.saturating_add(spec.address_count(!self.include_network_addresses))
            })
    }

    pub fn check_limit(&self, specs: &[TargetSpec]) -> Result<()> {
        let estimate = self.estimate(specs);
        if estimate > self.max_targets {
            return Err(Error::LimitExceeded {
                what: "target",
                requested: estimate,
                maximum: self.max_targets,
                hint: "narrow the range or raise --max-targets",
            });
        }
        Ok(())
    }

    pub fn expand_literals(
        &self,
        specs: &[TargetSpec],
    ) -> Result<(Vec<ResolvedTarget>, Vec<String>)> {
        self.check_limit(specs)?;

        let skip_network = !self.include_network_addresses;
        let excluded = self.exclusion_matcher()?;

        let mut seen: HashSet<IpAddr> = HashSet::new();
        let mut out: Vec<ResolvedTarget> = Vec::new();
        let mut hostnames: Vec<String> = Vec::new();

        for spec in specs {
            match spec {
                TargetSpec::Hostname { name } => {
                    if !hostnames.iter().any(|n| n == name) {
                        hostnames.push(name.clone());
                    }
                }
                _ => {
                    if !spec.matches_family(self.family) {
                        continue;
                    }
                    let Some(iter) = spec.addresses(skip_network) else {
                        continue;
                    };
                    for addr in iter {
                        if excluded.contains(&addr) {
                            continue;
                        }
                        if seen.insert(addr) {
                            if out.len() as u64 >= self.max_targets {
                                return Err(Error::LimitExceeded {
                                    what: "target",
                                    requested: self.estimate(specs),
                                    maximum: self.max_targets,
                                    hint: "narrow the range or raise --max-targets",
                                });
                            }
                            out.push(ResolvedTarget {
                                addr,
                                source_hostname: None,
                            });
                        }
                    }
                }
            }
        }

        Ok((out, hostnames))
    }

    pub fn exclusion_matcher(&self) -> Result<ExclusionSet> {
        ExclusionSet::new(&self.exclusions, !self.include_network_addresses)
    }
}

#[derive(Debug, Default, Clone)]
pub struct ExclusionSet {
    addresses: HashSet<IpAddr>,
    nets: Vec<IpNet>,
    ranges: Vec<(IpAddr, IpAddr)>,
}

impl ExclusionSet {
    pub fn new(specs: &[TargetSpec], _skip_network_addresses: bool) -> Result<Self> {
        let mut set = ExclusionSet::default();
        for spec in specs {
            match spec {
                TargetSpec::Address { addr } => {
                    set.addresses.insert(*addr);
                }
                TargetSpec::Cidr { net } => set.nets.push(*net),
                TargetSpec::Range { start, end } => set.ranges.push((*start, *end)),
                TargetSpec::Hostname { name } => {
                    return Err(Error::invalid_target(
                        name,
                        "exclusions must be addresses, CIDR blocks or ranges, not DNS names",
                    ))
                }
            }
        }
        Ok(set)
    }

    pub fn insert(&mut self, addr: IpAddr) {
        self.addresses.insert(addr);
    }

    pub fn contains(&self, addr: &IpAddr) -> bool {
        if self.addresses.contains(addr) {
            return true;
        }
        if self.nets.iter().any(|net| net.contains(addr)) {
            return true;
        }
        self.ranges
            .iter()
            .any(|(start, end)| in_range(*addr, *start, *end))
    }

    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty() && self.nets.is_empty() && self.ranges.is_empty()
    }
}

fn in_range(addr: IpAddr, start: IpAddr, end: IpAddr) -> bool {
    match (addr, start, end) {
        (IpAddr::V4(a), IpAddr::V4(s), IpAddr::V4(e)) => a >= s && a <= e,
        (IpAddr::V6(a), IpAddr::V6(s), IpAddr::V6(e)) => a >= s && a <= e,
        _ => false,
    }
}

pub fn parse_target_list(input: &str) -> Result<Vec<TargetSpec>> {
    input
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|s| !s.is_empty())
        .map(TargetSpec::from_str)
        .collect()
}

pub fn parse_targets_file(contents: &str) -> Result<Vec<TargetSpec>> {
    let mut specs = Vec::new();
    for line in contents.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        specs.extend(parse_target_list(line)?);
    }
    Ok(specs)
}

pub fn is_local_scope(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

pub fn is_private(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

pub fn enclosing_block(addr: IpAddr) -> IpNet {
    match addr {
        IpAddr::V4(v4) => IpNet::V4(
            Ipv4Net::new(v4, 24)
                .unwrap_or_else(|_| Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("valid /0"))
                .trunc(),
        ),
        IpAddr::V6(v6) => IpNet::V6(
            Ipv6Net::new(v6, 64)
                .unwrap_or_else(|_| Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).expect("valid /0"))
                .trunc(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(s: &str) -> TargetSpec {
        s.parse()
            .unwrap_or_else(|e| panic!("failed to parse {s:?}: {e}"))
    }

    #[test]
    fn parses_ipv4_address() {
        assert_eq!(
            spec("192.168.1.1"),
            TargetSpec::Address {
                addr: "192.168.1.1".parse().unwrap()
            }
        );
    }

    #[test]
    fn parses_ipv6_address_plain_and_bracketed() {
        let expected = TargetSpec::Address {
            addr: "2001:db8::1".parse().unwrap(),
        };
        assert_eq!(spec("2001:db8::1"), expected);
        assert_eq!(spec("[2001:db8::1]"), expected);
    }

    #[test]
    fn parses_cidr_and_truncates_host_bits() {
        assert_eq!(spec("192.168.1.0/24"), spec("192.168.1.77/24"));
        match spec("192.168.1.77/24") {
            TargetSpec::Cidr { net } => assert_eq!(net.to_string(), "192.168.1.0/24"),
            other => panic!("expected CIDR, got {other:?}"),
        }
    }

    #[test]
    fn parses_ipv6_cidr() {
        match spec("2001:db8::/64") {
            TargetSpec::Cidr { net } => assert_eq!(net.prefix_len(), 64),
            other => panic!("expected CIDR, got {other:?}"),
        }
    }

    #[test]
    fn parses_full_range() {
        assert_eq!(
            spec("10.0.0.1-10.0.0.50"),
            TargetSpec::Range {
                start: "10.0.0.1".parse().unwrap(),
                end: "10.0.0.50".parse().unwrap()
            }
        );
    }

    #[test]
    fn parses_last_octet_shorthand() {
        assert_eq!(spec("10.0.0.1-50"), spec("10.0.0.1-10.0.0.50"));
    }

    #[test]
    fn parses_hostname_and_lowercases() {
        assert_eq!(
            spec("Example.COM"),
            TargetSpec::Hostname {
                name: "example.com".to_string()
            }
        );
    }

    #[test]
    fn hostname_with_hyphen_is_not_a_range() {
        assert_eq!(
            spec("my-host.internal"),
            TargetSpec::Hostname {
                name: "my-host.internal".to_string()
            }
        );
    }

    #[test]
    fn rejects_bad_input() {
        for bad in [
            "",
            "   ",
            "999.1.1.1",
            "192.168.1.0/33",
            "2001:db8::/129",
            "example.com/24",
            "10.0.0.50-10.0.0.1",
            "10.0.0.1-2001:db8::1",
            "-leading-hyphen.com",
            "10.0.0.1-999",
        ] {
            assert!(
                bad.parse::<TargetSpec>().is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn error_messages_name_the_input() {
        let err = "192.168.1.0/33".parse::<TargetSpec>().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("192.168.1.0/33"), "message was: {msg}");
        assert!(msg.contains("0 and 32"), "message was: {msg}");
    }

    #[test]
    fn cidr_counts_exclude_network_and_broadcast_by_default() {
        assert_eq!(spec("192.168.1.0/24").address_count(true), 254);
        assert_eq!(spec("192.168.1.0/24").address_count(false), 256);

        assert_eq!(spec("192.168.1.0/31").address_count(true), 2);
        assert_eq!(spec("192.168.1.1/32").address_count(true), 1);
    }

    #[test]
    fn range_counts_are_inclusive() {
        assert_eq!(spec("10.0.0.1-10.0.0.50").address_count(true), 50);
        assert_eq!(spec("10.0.0.7-10.0.0.7").address_count(true), 1);
    }

    #[test]
    fn ipv6_wide_prefix_saturates_rather_than_overflowing() {
        assert_eq!(spec("2001:db8::/16").address_count(true), u64::MAX);
    }

    #[test]
    fn expansion_is_ordered_and_deduplicated() {
        let resolver = TargetResolver::new();
        let specs = vec![spec("192.168.1.5"), spec("192.168.1.0/29")];
        let (targets, names) = resolver.expand_literals(&specs).unwrap();
        assert!(names.is_empty());
        assert_eq!(targets[0].addr, "192.168.1.5".parse::<IpAddr>().unwrap());

        assert_eq!(targets.len(), 6);
        let mut sorted: Vec<_> = targets.iter().map(|t| t.addr).collect();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 6);
    }

    #[test]
    fn expansion_collects_hostnames_separately() {
        let resolver = TargetResolver::new();
        let specs = vec![spec("example.com"), spec("10.0.0.1"), spec("example.com")];
        let (targets, names) = resolver.expand_literals(&specs).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(names, vec!["example.com".to_string()]);
    }

    #[test]
    fn family_filter_drops_other_family() {
        let resolver = TargetResolver::new().with_family(IpFamily::V6);
        let specs = vec![spec("10.0.0.1"), spec("2001:db8::1")];
        let (targets, _) = resolver.expand_literals(&specs).unwrap();
        assert_eq!(targets.len(), 1);
        assert!(targets[0].addr.is_ipv6());
    }

    #[test]
    fn specifications_know_their_own_family() {
        assert!(spec("10.0.0.1").matches_family(IpFamily::V4));
        assert!(!spec("10.0.0.1").matches_family(IpFamily::V6));
        assert!(spec("2001:db8::/64").matches_family(IpFamily::V6));
        assert!(!spec("2001:db8::/64").matches_family(IpFamily::V4));
        assert!(spec("10.0.0.1-50").matches_family(IpFamily::V4));

        assert!(spec("example.com").matches_family(IpFamily::V4));
        assert!(spec("example.com").matches_family(IpFamily::V6));
        assert!(spec("10.0.0.1").matches_family(IpFamily::Both));
    }

    #[test]
    fn an_out_of_family_block_is_not_counted_against_the_limit() {
        let resolver = TargetResolver::new().with_family(IpFamily::V4);
        let specs = vec![spec("192.168.1.0/24"), spec("2001:db8::/64")];

        assert_eq!(resolver.estimate(&specs), 254);
        let (targets, _) = resolver.expand_literals(&specs).unwrap();
        assert_eq!(targets.len(), 254);
        assert!(targets.iter().all(|t| t.addr.is_ipv4()));
    }

    #[test]
    fn expanding_an_out_of_family_block_terminates() {
        let resolver = TargetResolver::new().with_family(IpFamily::V4);
        let (targets, _) = resolver.expand_literals(&[spec("2001:db8::/64")]).unwrap();
        assert!(targets.is_empty());
    }

    #[test]
    fn exclusions_remove_addresses_and_blocks() {
        let resolver = TargetResolver::new()
            .with_exclusions(vec![spec("192.168.1.0/28"), spec("192.168.1.200")]);
        let (targets, _) = resolver.expand_literals(&[spec("192.168.1.0/24")]).unwrap();
        let addrs: HashSet<_> = targets.iter().map(|t| t.addr).collect();
        assert!(!addrs.contains(&"192.168.1.5".parse::<IpAddr>().unwrap()));
        assert!(!addrs.contains(&"192.168.1.200".parse::<IpAddr>().unwrap()));
        assert!(addrs.contains(&"192.168.1.100".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn hostname_exclusions_are_rejected() {
        let err = ExclusionSet::new(&[spec("example.com")], true).unwrap_err();
        assert!(err.to_string().contains("not DNS names"));
    }

    #[test]
    fn limit_is_enforced_before_expansion() {
        let resolver = TargetResolver::new().with_max_targets(100);
        let err = resolver
            .expand_literals(&[spec("10.0.0.0/16")])
            .unwrap_err();
        assert!(matches!(err, Error::LimitExceeded { what: "target", .. }));
    }

    #[test]
    fn cidr_iteration_matches_count() {
        let s = spec("192.168.4.0/28");
        let count = s.address_count(true);
        let iterated = s.addresses(true).unwrap().count() as u64;
        assert_eq!(count, iterated);
        assert_eq!(iterated, 14);
    }

    #[test]
    fn cidr_iteration_can_include_network_addresses() {
        let s = spec("192.168.4.0/28");
        assert_eq!(s.addresses(false).unwrap().count() as u64, 16);
    }

    #[test]
    fn parses_target_lists_and_files() {
        let list = parse_target_list("10.0.0.1, 10.0.0.2  10.0.0.3").unwrap();
        assert_eq!(list.len(), 3);

        let file = "# comment\n\n10.0.0.1 # trailing\n192.168.0.0/30\n";
        let parsed = parse_targets_file(file).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn scope_helpers() {
        assert!(is_local_scope(&"127.0.0.1".parse().unwrap()));
        assert!(is_local_scope(&"169.254.1.1".parse().unwrap()));
        assert!(is_local_scope(&"fe80::1".parse().unwrap()));
        assert!(!is_local_scope(&"8.8.8.8".parse().unwrap()));

        assert!(is_private(&"192.168.1.1".parse().unwrap()));
        assert!(is_private(&"fd00::1".parse().unwrap()));
        assert!(!is_private(&"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn enclosing_block_groups_by_subnet() {
        assert_eq!(
            enclosing_block("192.168.1.77".parse().unwrap()).to_string(),
            "192.168.1.0/24"
        );
        assert_eq!(
            enclosing_block("2001:db8::5".parse().unwrap()).to_string(),
            "2001:db8::/64"
        );
    }

    #[test]
    fn display_round_trips() {
        for text in [
            "192.168.1.1",
            "192.168.1.0/24",
            "10.0.0.1-10.0.0.50",
            "example.com",
        ] {
            let parsed = spec(text);
            assert_eq!(parsed.to_string(), text);
            assert_eq!(spec(&parsed.to_string()), parsed);
        }
    }
}
