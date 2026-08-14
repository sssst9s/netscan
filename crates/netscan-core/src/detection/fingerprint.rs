use crate::detection::oui;
use crate::scanner::port::Transport;
use crate::scanner::result::{Confidence, OsEvidence, OsGuess, ServiceInfo};

#[derive(Debug, Default, Clone)]
pub struct Observations<'a> {
    pub ttl: Option<u8>,
    pub mac_vendor: Option<&'a str>,
    pub open_ports: Vec<(u16, Transport)>,
    pub services: Vec<&'a ServiceInfo>,
    pub banners: Vec<&'a str>,
}

pub fn infer(observations: &Observations<'_>) -> OsGuess {
    let mut guess = OsGuess {
        confidence: Confidence::Low,
        ..OsGuess::default()
    };
    let mut family_votes: Vec<(String, u32, OsEvidence)> = Vec::new();
    let mut device_votes: Vec<(String, u32, OsEvidence)> = Vec::new();

    if let Some(ttl) = observations.ttl {
        if let Some((initial, family, hops)) = classify_ttl(ttl) {
            let evidence = OsEvidence {
                kind: "ttl".to_string(),
                detail: format!("reply TTL {ttl}, consistent with an initial TTL of {initial} after {hops} hops"),
                suggests: family.to_string(),
            };

            family_votes.push((family.to_string(), 2, evidence));
        }
    }

    if let Some(vendor) = observations.mac_vendor {
        if let Some(device) = oui::device_hint(vendor) {
            device_votes.push((
                device.to_string(),
                4,
                OsEvidence {
                    kind: "mac-vendor".to_string(),
                    detail: format!("hardware address belongs to {vendor}"),
                    suggests: device.to_string(),
                },
            ));
        }
        if let Some(family) = vendor_os_hint(vendor) {
            family_votes.push((
                family.to_string(),
                3,
                OsEvidence {
                    kind: "mac-vendor".to_string(),
                    detail: format!("hardware address belongs to {vendor}"),
                    suggests: family.to_string(),
                },
            ));
        }
    }

    for text in observations
        .banners
        .iter()
        .copied()
        .chain(
            observations
                .services
                .iter()
                .filter_map(|s| s.extra.as_deref()),
        )
        .chain(
            observations
                .services
                .iter()
                .filter_map(|s| s.product.as_deref()),
        )
    {
        if let Some((family, name, weight)) = banner_os_hint(text) {
            let evidence = OsEvidence {
                kind: "banner".to_string(),
                detail: format!("service reported {text:?}"),
                suggests: name.clone(),
            };
            family_votes.push((family, weight, evidence));
            if guess.name.is_none() {
                guess.name = Some(name);
            }
        }
    }

    let ports: Vec<u16> = observations
        .open_ports
        .iter()
        .filter(|(_, t)| *t == Transport::Tcp)
        .map(|(p, _)| *p)
        .collect();

    if ports.contains(&445) || ports.contains(&135) || ports.contains(&3389) {
        family_votes.push((
            "Windows".to_string(),
            3,
            OsEvidence {
                kind: "port-mix".to_string(),
                detail: "SMB, MSRPC or RDP is open".to_string(),
                suggests: "Windows".to_string(),
            },
        ));
    }
    if ports.contains(&9100) || ports.contains(&515) || ports.contains(&631) {
        device_votes.push((
            "printer".to_string(),
            3,
            OsEvidence {
                kind: "port-mix".to_string(),
                detail: "a printing port (9100, 515 or 631) is open".to_string(),
                suggests: "printer".to_string(),
            },
        ));
    }
    if ports.contains(&548) || ports.contains(&5900) && ports.contains(&22) {
        family_votes.push((
            "macOS".to_string(),
            1,
            OsEvidence {
                kind: "port-mix".to_string(),
                detail: "Apple Filing Protocol is open".to_string(),
                suggests: "macOS".to_string(),
            },
        ));
    }
    if ports.contains(&22) && !ports.contains(&445) && !ports.contains(&135) {
        family_votes.push((
            "Unix-like".to_string(),
            1,
            OsEvidence {
                kind: "port-mix".to_string(),
                detail: "SSH is open and no Windows service is".to_string(),
                suggests: "Unix-like".to_string(),
            },
        ));
    }

    let (family, family_score, mut evidence) = tally(family_votes);
    let (device, _device_score, device_evidence) = tally(device_votes);
    evidence.extend(device_evidence);

    guess.family = family;
    guess.device_type = device;
    guess.evidence = evidence;
    guess.confidence = match family_score {
        0..=1 => Confidence::Low,
        2..=4 => Confidence::Medium,
        _ => Confidence::High,
    };

    if let (Some(name), Some(family)) = (guess.name.clone(), guess.family.clone()) {
        if !name
            .to_ascii_lowercase()
            .contains(&family.to_ascii_lowercase())
            && !family_agrees(&family, &name)
        {
            guess.name = None;
        }
    }

    if guess.is_empty() {
        guess.confidence = Confidence::Low;
        guess.evidence.clear();
    }
    guess
}

fn tally(votes: Vec<(String, u32, OsEvidence)>) -> (Option<String>, u32, Vec<OsEvidence>) {
    if votes.is_empty() {
        return (None, 0, Vec::new());
    }
    let mut totals: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    for (candidate, weight, _) in &votes {
        *totals.entry(candidate.clone()).or_insert(0) += weight;
    }
    let (winner, score) = totals
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
        .expect("votes is non-empty");

    let evidence = votes.into_iter().map(|(_, _, e)| e).collect();
    (Some(winner), score, evidence)
}

fn family_agrees(family: &str, name: &str) -> bool {
    let family = family.to_ascii_lowercase();
    let name = name.to_ascii_lowercase();
    match family.as_str() {
        "linux" | "unix-like" => [
            "ubuntu", "debian", "centos", "red hat", "alpine", "fedora", "suse", "linux",
        ]
        .iter()
        .any(|d| name.contains(d)),
        "windows" => name.contains("windows") || name.contains("server"),
        "macos" => name.contains("mac") || name.contains("darwin"),
        _ => false,
    }
}

fn classify_ttl(ttl: u8) -> Option<(u8, &'static str, u8)> {
    for (initial, family) in [
        (64u8, "Unix-like"),
        (128u8, "Windows"),
        (255u8, "Network device"),
    ] {
        if ttl <= initial && initial - ttl <= 32 {
            return Some((initial, family, initial - ttl));
        }
    }
    None
}

fn vendor_os_hint(vendor: &str) -> Option<&'static str> {
    let lower = vendor.to_ascii_lowercase();
    if lower.contains("apple") {
        Some("macOS")
    } else if lower.contains("raspberry pi") {
        Some("Linux")
    } else if lower.contains("mikrotik") || lower.contains("routerboard") {
        Some("Network device")
    } else {
        None
    }
}

fn banner_os_hint(text: &str) -> Option<(String, String, u32)> {
    let lower = text.to_ascii_lowercase();
    const DISTRIBUTIONS: &[(&str, &str, &str)] = &[
        ("ubuntu", "Linux", "Ubuntu Linux"),
        ("debian", "Linux", "Debian Linux"),
        ("raspbian", "Linux", "Raspberry Pi OS"),
        ("centos", "Linux", "CentOS Linux"),
        ("red hat", "Linux", "Red Hat Enterprise Linux"),
        ("fedora", "Linux", "Fedora Linux"),
        ("alpine", "Linux", "Alpine Linux"),
        ("suse", "Linux", "SUSE Linux"),
        ("amazon linux", "Linux", "Amazon Linux"),
        ("freebsd", "BSD", "FreeBSD"),
        ("openbsd", "BSD", "OpenBSD"),
        ("netbsd", "BSD", "NetBSD"),
        ("darwin", "macOS", "macOS"),
        ("microsoft-iis", "Windows", "Windows Server"),
        ("microsoft esmtp", "Windows", "Windows Server"),
        ("microsoft ftp", "Windows", "Windows Server"),
        ("win32", "Windows", "Windows"),
        ("win64", "Windows", "Windows"),
        ("mikrotik", "Network device", "MikroTik RouterOS"),
        ("routeros", "Network device", "MikroTik RouterOS"),
        ("cisco", "Network device", "Cisco IOS"),
        ("openwrt", "Linux", "OpenWrt"),
        ("dd-wrt", "Linux", "DD-WRT"),
    ];

    for (needle, family, name) in DISTRIBUTIONS {
        if lower.contains(needle) {
            return Some((family.to_string(), name.to_string(), 5));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observations() -> Observations<'static> {
        Observations::default()
    }

    #[test]
    fn no_evidence_yields_no_guess() {
        let guess = infer(&observations());
        assert!(guess.is_empty());
        assert!(guess.evidence.is_empty());
        assert_eq!(guess.confidence, Confidence::Low);
        assert_eq!(guess.summary(), "unknown (low confidence)");
    }

    #[test]
    fn ttl_classification_covers_the_usual_initial_values() {
        assert_eq!(classify_ttl(64), Some((64, "Unix-like", 0)));
        assert_eq!(classify_ttl(57), Some((64, "Unix-like", 7)));
        assert_eq!(classify_ttl(128), Some((128, "Windows", 0)));
        assert_eq!(classify_ttl(120), Some((128, "Windows", 8)));
        assert_eq!(classify_ttl(255), Some((255, "Network device", 0)));

        assert_eq!(classify_ttl(5), None);
    }

    #[test]
    fn ttl_alone_is_never_high_confidence() {
        let guess = infer(&Observations {
            ttl: Some(64),
            ..observations()
        });
        assert_eq!(guess.family.as_deref(), Some("Unix-like"));
        assert!(
            guess.confidence < Confidence::High,
            "TTL is trivially spoofed and must not produce a confident answer"
        );
        assert_eq!(guess.evidence.len(), 1);
        assert_eq!(guess.evidence[0].kind, "ttl");
    }

    #[test]
    fn a_named_distribution_in_a_banner_is_strong_evidence() {
        let banner = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5";
        let guess = infer(&Observations {
            banners: vec![banner],
            ..observations()
        });
        assert_eq!(guess.family.as_deref(), Some("Linux"));
        assert_eq!(guess.name.as_deref(), Some("Ubuntu Linux"));
        assert_eq!(guess.confidence, Confidence::High);
        assert!(guess.evidence.iter().any(|e| e.kind == "banner"));
    }

    #[test]
    fn windows_is_inferred_from_the_port_mix() {
        let guess = infer(&Observations {
            open_ports: vec![
                (135, Transport::Tcp),
                (445, Transport::Tcp),
                (3389, Transport::Tcp),
            ],
            ttl: Some(126),
            ..observations()
        });
        assert_eq!(guess.family.as_deref(), Some("Windows"));
        assert!(guess.confidence >= Confidence::Medium);
        assert!(guess.evidence.iter().any(|e| e.kind == "port-mix"));
        assert!(guess.evidence.iter().any(|e| e.kind == "ttl"));
    }

    #[test]
    fn printers_are_recognised_by_port_and_vendor() {
        let guess = infer(&Observations {
            open_ports: vec![(9100, Transport::Tcp), (631, Transport::Tcp)],
            mac_vendor: Some("Brother Industries"),
            ..observations()
        });
        assert_eq!(guess.device_type.as_deref(), Some("printer"));
        assert!(guess.evidence.iter().any(|e| e.kind == "mac-vendor"));
    }

    #[test]
    fn network_devices_are_recognised_by_vendor() {
        let guess = infer(&Observations {
            mac_vendor: Some("Ubiquiti Networks"),
            ..observations()
        });
        assert_eq!(guess.device_type.as_deref(), Some("network device"));
    }

    #[test]
    fn every_guess_carries_its_evidence() {
        let guess = infer(&Observations {
            ttl: Some(64),
            banners: vec!["SSH-2.0-OpenSSH_9.6p1 Debian-2"],
            open_ports: vec![(22, Transport::Tcp)],
            ..observations()
        });
        assert!(!guess.evidence.is_empty());
        for item in &guess.evidence {
            assert!(!item.kind.is_empty());
            assert!(!item.detail.is_empty());
            assert!(!item.suggests.is_empty());
        }
    }

    #[test]
    fn a_specific_name_is_dropped_when_the_family_disagrees() {
        let guess = infer(&Observations {
            banners: vec!["Server: Microsoft-IIS/10.0"],
            open_ports: vec![(22, Transport::Tcp)],
            ttl: Some(64),
            ..observations()
        });

        if let (Some(name), Some(family)) = (&guess.name, &guess.family) {
            assert!(
                family_agrees(family, name) || name.to_lowercase().contains(&family.to_lowercase()),
                "name {name:?} contradicts family {family:?}"
            );
        }
    }

    #[test]
    fn summary_is_human_readable() {
        let guess = infer(&Observations {
            banners: vec!["SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"],
            ..observations()
        });
        assert_eq!(guess.summary(), "Ubuntu Linux (high confidence)");
    }
}
