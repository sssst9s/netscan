use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::error::Result;
use crate::protocols::raw::{build_arp_request, parse_arp_reply, RawChannel};
use crate::scanner::result::MacAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpHost {
    pub ip: Ipv4Addr,
    pub mac: MacAddress,
    pub rtt: Duration,
}

pub fn sweep(
    interface: Option<&str>,
    targets: &[Ipv4Addr],
    timeout: Duration,
) -> Result<Vec<ArpHost>> {
    if targets.is_empty() {
        return Ok(Vec::new());
    }

    let mut channel = RawChannel::open(interface, Duration::from_millis(50))?;
    let source_mac = channel.source_mac;
    let source_ip = channel.source_ip;

    let wanted: HashMap<Ipv4Addr, ()> = targets.iter().map(|ip| (*ip, ())).collect();
    let started = Instant::now();

    for target in targets {
        if *target == source_ip {
            continue;
        }
        let frame = build_arp_request(source_mac, source_ip, *target);

        let _ = channel.send(&frame);
    }

    let mut found: HashMap<Ipv4Addr, ArpHost> = HashMap::new();
    while started.elapsed() < timeout && found.len() < wanted.len() {
        let Some(frame) = channel.recv() else {
            continue;
        };
        let Some(reply) = parse_arp_reply(frame) else {
            continue;
        };
        if !wanted.contains_key(&reply.ip) {
            continue;
        }
        found.entry(reply.ip).or_insert(ArpHost {
            ip: reply.ip,
            mac: reply.mac,
            rtt: started.elapsed(),
        });
    }

    let mut hosts: Vec<ArpHost> = found.into_values().collect();
    hosts.sort_by_key(|host| host.ip);
    Ok(hosts)
}

pub async fn sweep_async(
    interface: Option<String>,
    targets: Vec<Ipv4Addr>,
    timeout: Duration,
) -> Result<Vec<ArpHost>> {
    tokio::task::spawn_blocking(move || sweep(interface.as_deref(), &targets, timeout))
        .await
        .map_err(|e| crate::error::Error::Unsupported(format!("ARP sweep task failed: {e}")))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_target_list_needs_no_privileges() {
        let hosts = sweep(None, &[], Duration::from_millis(10)).unwrap();
        assert!(hosts.is_empty());
    }

    #[tokio::test]
    async fn the_async_wrapper_reports_capability_errors_rather_than_panicking() {
        let result = sweep_async(
            Some("definitely-not-an-interface".to_string()),
            vec![Ipv4Addr::new(192, 168, 1, 1)],
            Duration::from_millis(50),
        )
        .await;
        assert!(
            result.is_err(),
            "an unknown interface must be an error, not a panic"
        );
    }
}
