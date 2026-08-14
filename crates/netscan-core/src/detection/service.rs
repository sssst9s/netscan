use std::sync::OnceLock;

use crate::scanner::port::{PortSet, Transport};

const TCP_DATA: &str = include_str!("../../data/tcp-services.tsv");
const UDP_DATA: &str = include_str!("../../data/udp-services.tsv");

#[derive(Debug)]
pub struct Catalog {
    ranked: Vec<u16>,
    names: Vec<Option<&'static str>>,
    ranks: Vec<Option<u32>>,
}

impl Catalog {
    fn parse(data: &'static str) -> Self {
        let mut ranked = Vec::with_capacity(1024);
        let mut names: Vec<Option<&'static str>> = vec![None; 65_536];
        let mut ranks: Vec<Option<u32>> = vec![None; 65_536];

        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((port_text, name)) = line.split_once('\t') else {
                continue;
            };
            let Ok(port) = port_text.trim().parse::<u16>() else {
                continue;
            };
            if port == 0 {
                continue;
            }
            let idx = usize::from(port);
            let name = name.trim();
            if name != "unknown" && !name.is_empty() {
                names[idx] = Some(name);
            }
            if ranks[idx].is_none() {
                ranks[idx] = Some(ranked.len() as u32);
                ranked.push(port);
            }
        }

        Self {
            ranked,
            names,
            ranks,
        }
    }

    pub fn ranked(&self) -> &[u16] {
        &self.ranked
    }

    pub fn ranked_len(&self) -> usize {
        self.ranked.len()
    }

    pub fn name(&self, port: u16) -> Option<&'static str> {
        self.names.get(usize::from(port)).copied().flatten()
    }

    pub fn rank(&self, port: u16) -> Option<u32> {
        self.ranks.get(usize::from(port)).copied().flatten()
    }

    pub fn top(&self, n: usize) -> PortSet {
        PortSet::from_iter_ordered(self.ranked.iter().copied().take(n))
    }
}

fn tcp_catalog() -> &'static Catalog {
    static TCP: OnceLock<Catalog> = OnceLock::new();
    TCP.get_or_init(|| Catalog::parse(TCP_DATA))
}

fn udp_catalog() -> &'static Catalog {
    static UDP: OnceLock<Catalog> = OnceLock::new();
    UDP.get_or_init(|| Catalog::parse(UDP_DATA))
}

pub fn catalog(transport: Transport) -> &'static Catalog {
    match transport {
        Transport::Tcp => tcp_catalog(),
        Transport::Udp => udp_catalog(),
    }
}

pub fn name_for_port(transport: Transport, port: u16) -> Option<&'static str> {
    catalog(transport).name(port)
}

pub fn top_tcp_ports(n: usize) -> PortSet {
    tcp_catalog().top(n)
}

pub fn top_udp_ports(n: usize) -> PortSet {
    udp_catalog().top(n)
}

pub fn max_top_ports(transport: Transport) -> usize {
    catalog(transport).ranked_len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datasets_are_large_enough_for_top_1000() {
        assert!(tcp_catalog().ranked_len() >= 1000, "tcp dataset too small");
        assert!(udp_catalog().ranked_len() >= 1000, "udp dataset too small");
    }

    #[test]
    fn datasets_contain_no_duplicate_ports() {
        for transport in [Transport::Tcp, Transport::Udp] {
            let ranked = catalog(transport).ranked();
            let mut sorted = ranked.to_vec();
            sorted.sort_unstable();
            let before = sorted.len();
            sorted.dedup();
            assert_eq!(before, sorted.len(), "{transport} dataset has duplicates");
        }
    }

    #[test]
    fn every_dataset_line_parses() {
        for (label, data) in [("tcp", TCP_DATA), ("udp", UDP_DATA)] {
            for (n, line) in data.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let (port, name) = line.split_once('\t').unwrap_or_else(|| {
                    panic!("{label} line {} is not tab separated: {line:?}", n + 1)
                });
                port.parse::<u16>()
                    .unwrap_or_else(|_| panic!("{label} line {} has a bad port: {port:?}", n + 1));
                assert!(!name.is_empty(), "{label} line {} has an empty name", n + 1);
            }
        }
    }

    #[test]
    fn well_known_names_resolve() {
        assert_eq!(name_for_port(Transport::Tcp, 22), Some("ssh"));
        assert_eq!(name_for_port(Transport::Tcp, 443), Some("https"));
        assert_eq!(name_for_port(Transport::Tcp, 3306), Some("mysql"));
        assert_eq!(name_for_port(Transport::Udp, 53), Some("domain"));
        assert_eq!(name_for_port(Transport::Udp, 161), Some("snmp"));
    }

    #[test]
    fn unnamed_ports_return_none() {
        assert_eq!(name_for_port(Transport::Tcp, 64999), None);
    }

    #[test]
    fn top_ports_are_prefix_ordered_and_bounded() {
        let ten = top_tcp_ports(10);
        let hundred = top_tcp_ports(100);
        assert_eq!(ten.len(), 10);
        assert_eq!(hundred.len(), 100);
        assert_eq!(&hundred.as_slice()[..10], ten.as_slice());

        let top20 = top_tcp_ports(20);
        for port in [80, 443, 22, 21, 25] {
            assert!(top20.contains(port), "port {port} missing from top 20");
        }
    }

    #[test]
    fn requesting_more_than_available_clamps() {
        let all = top_tcp_ports(usize::MAX);
        assert_eq!(all.len(), max_top_ports(Transport::Tcp));
    }

    #[test]
    fn rank_and_ranked_agree() {
        let cat = catalog(Transport::Tcp);
        for (i, port) in cat.ranked().iter().enumerate().take(200) {
            assert_eq!(cat.rank(*port), Some(i as u32));
        }
    }
}
