use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    pub addresses: Vec<InterfaceAddress>,
    pub is_loopback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceAddress {
    pub address: IpAddr,
    pub network: Option<IpNet>,
}

impl Interface {
    pub fn ipv4(&self) -> Option<IpAddr> {
        self.addresses
            .iter()
            .map(|a| a.address)
            .find(IpAddr::is_ipv4)
    }

    pub fn ipv6(&self) -> Option<IpAddr> {
        self.addresses
            .iter()
            .map(|a| a.address)
            .find(IpAddr::is_ipv6)
    }

    pub fn address_for(&self, ipv6: bool) -> Option<IpAddr> {
        if ipv6 {
            self.ipv6()
        } else {
            self.ipv4()
        }
    }

    pub fn networks(&self) -> Vec<IpNet> {
        self.addresses.iter().filter_map(|a| a.network).collect()
    }

    pub fn is_usable(&self) -> bool {
        !self.is_loopback
            && self.addresses.iter().any(|a| match a.address {
                IpAddr::V4(v4) => !v4.is_unspecified() && !v4.is_link_local(),
                IpAddr::V6(v6) => !v6.is_unspecified() && (v6.segments()[0] & 0xffc0) != 0xfe80,
            })
    }
}

pub fn list() -> Result<Vec<Interface>> {
    let raw = if_addrs::get_if_addrs().map_err(|e| Error::Interface {
        name: "*".to_string(),
        reason: e.to_string(),
    })?;

    let mut interfaces: Vec<Interface> = Vec::new();
    for entry in raw {
        let network = network_for(&entry);
        let address = InterfaceAddress {
            address: entry.addr.ip(),
            network,
        };

        match interfaces.iter_mut().find(|i| i.name == entry.name) {
            Some(existing) => existing.addresses.push(address),
            None => interfaces.push(Interface {
                name: entry.name.clone(),
                is_loopback: entry.is_loopback(),
                addresses: vec![address],
            }),
        }
    }

    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(interfaces)
}

fn network_for(entry: &if_addrs::Interface) -> Option<IpNet> {
    match &entry.addr {
        if_addrs::IfAddr::V4(v4) => {
            let prefix = u32::from(v4.netmask).count_ones() as u8;
            Ipv4Net::new(v4.ip, prefix)
                .ok()
                .map(|net| IpNet::V4(net.trunc()))
        }
        if_addrs::IfAddr::V6(v6) => {
            let prefix = u128::from(v6.netmask).count_ones() as u8;
            Ipv6Net::new(v6.ip, prefix)
                .ok()
                .map(|net| IpNet::V6(net.trunc()))
        }
    }
}

pub fn find(name: &str) -> Result<Interface> {
    let interfaces = list()?;
    interfaces
        .iter()
        .find(|i| i.name == name)
        .cloned()
        .ok_or_else(|| {
            let available: Vec<_> = interfaces.iter().map(|i| i.name.as_str()).collect();
            Error::Interface {
                name: name.to_string(),
                reason: format!("no such interface; available: {}", available.join(", ")),
            }
        })
}

pub fn source_address(name: &str, ipv6: bool) -> Result<IpAddr> {
    let interface = find(name)?;
    interface.address_for(ipv6).ok_or_else(|| Error::Interface {
        name: name.to_string(),
        reason: format!(
            "interface has no {} address",
            if ipv6 { "IPv6" } else { "IPv4" }
        ),
    })
}

pub fn local_networks() -> Result<Vec<IpNet>> {
    const WIDEST_IPV4_PREFIX: u8 = 16;
    const WIDEST_IPV6_PREFIX: u8 = 64;

    let mut networks = Vec::new();
    for interface in list()?.into_iter().filter(Interface::is_usable) {
        for network in interface.networks() {
            let too_wide = match network {
                IpNet::V4(v4) => v4.prefix_len() < WIDEST_IPV4_PREFIX,
                IpNet::V6(v6) => v6.prefix_len() < WIDEST_IPV6_PREFIX,
            };
            if too_wide {
                continue;
            }
            if network.addr().is_loopback() || !networks.contains(&network) {
                networks.push(network);
            }
        }
    }
    Ok(networks)
}

pub fn route_to(target: IpAddr) -> Result<Option<Interface>> {
    let bind: std::net::SocketAddr = if target.is_ipv6() {
        "[::]:0"
            .parse()
            .map_err(|_| Error::Config("invalid bind address".into()))?
    } else {
        "0.0.0.0:0"
            .parse()
            .map_err(|_| Error::Config("invalid bind address".into()))?
    };

    let socket = std::net::UdpSocket::bind(bind)?;

    socket.connect(std::net::SocketAddr::new(target, 53))?;
    let local = socket.local_addr()?.ip();

    Ok(list()?
        .into_iter()
        .find(|i| i.addresses.iter().any(|a| a.address == local)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumeration_finds_loopback() {
        let interfaces = list().expect("interface enumeration should work");
        assert!(
            !interfaces.is_empty(),
            "every machine has at least a loopback interface"
        );
        assert!(
            interfaces.iter().any(|i| i.is_loopback),
            "loopback should be present: {:?}",
            interfaces.iter().map(|i| &i.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn addresses_carry_their_network() {
        let interfaces = list().unwrap();
        let loopback = interfaces.iter().find(|i| i.is_loopback).unwrap();
        let v4 = loopback.addresses.iter().find(|a| a.address.is_ipv4());
        if let Some(address) = v4 {
            assert_eq!(address.address.to_string(), "127.0.0.1");
            let network = address.network.expect("loopback should have a netmask");
            assert!(network.contains(&address.address));
        }
    }

    #[test]
    fn loopback_is_not_usable_as_a_scan_source() {
        let interfaces = list().unwrap();
        let loopback = interfaces.iter().find(|i| i.is_loopback).unwrap();
        assert!(!loopback.is_usable());
    }

    #[test]
    fn addresses_are_grouped_by_interface_name() {
        let interfaces = list().unwrap();
        let mut names: Vec<_> = interfaces.iter().map(|i| i.name.clone()).collect();
        let before = names.len();
        names.sort();
        names.dedup();
        assert_eq!(
            before,
            names.len(),
            "each interface should appear exactly once"
        );
    }

    #[test]
    fn unknown_interface_names_produce_a_helpful_error() {
        let err = find("definitely-not-an-interface").unwrap_err();
        let message = err.to_string();
        assert!(message.contains("definitely-not-an-interface"));
        assert!(
            message.contains("available:"),
            "the error should list real options: {message}"
        );
    }

    #[test]
    fn local_networks_excludes_loopback_and_oversized_blocks() {
        let networks = local_networks().unwrap();
        for network in &networks {
            assert!(
                !network.addr().is_loopback(),
                "loopback should be excluded: {network}"
            );
            match network {
                IpNet::V4(v4) => assert!(v4.prefix_len() >= 16, "too wide: {network}"),
                IpNet::V6(v6) => assert!(v6.prefix_len() >= 64, "too wide: {network}"),
            }
        }
    }

    #[test]
    fn routing_to_loopback_finds_the_loopback_interface() {
        let interface = route_to("127.0.0.1".parse().unwrap()).unwrap();
        if let Some(interface) = interface {
            assert!(interface.is_loopback, "127.0.0.1 should route via loopback");
        }
    }
}
