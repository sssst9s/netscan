use std::collections::HashMap;
use std::sync::OnceLock;

use crate::scanner::result::MacAddress;

const OUI_DATA: &str = include_str!("../../data/oui.tsv");

fn table() -> &'static HashMap<[u8; 3], &'static str> {
    static TABLE: OnceLock<HashMap<[u8; 3], &'static str>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut map = HashMap::with_capacity(512);
        for line in OUI_DATA.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((prefix, vendor)) = line.split_once('\t') else {
                continue;
            };
            let Some(bytes) = parse_prefix(prefix.trim()) else {
                continue;
            };
            map.insert(bytes, vendor.trim());
        }
        map
    })
}

fn parse_prefix(text: &str) -> Option<[u8; 3]> {
    let mut bytes = [0u8; 3];
    let mut parts = text.split(':');
    for slot in bytes.iter_mut() {
        *slot = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(bytes)
}

pub fn vendor_for(mac: &MacAddress) -> Option<&'static str> {
    table().get(&mac.oui()).copied()
}

pub fn bundled_prefix_count() -> usize {
    table().len()
}

pub fn device_hint(vendor: &str) -> Option<&'static str> {
    let lower = vendor.to_ascii_lowercase();
    const NETWORK: &[&str] = &[
        "cisco",
        "juniper",
        "mikrotik",
        "ubiquiti",
        "aruba",
        "netgear",
        "tp-link",
        "d-link",
        "zyxel",
        "ruckus",
        "fortinet",
        "arista",
        "extreme networks",
        "huawei",
        "brocade",
        "cambium",
        "meraki",
    ];
    const PRINTER: &[&str] = &[
        "brother", "canon", "epson", "lexmark", "ricoh", "xerox", "kyocera",
    ];
    const VIRTUAL: &[&str] = &[
        "vmware",
        "xensource",
        "parallels",
        "qemu",
        "microsoft corporation (hyper-v)",
        "oracle virtualbox",
    ];
    const PHONE: &[&str] = &["polycom", "yealink", "grandstream", "avaya", "snom"];
    const CAMERA: &[&str] = &["hikvision", "dahua", "axis communications", "hanwha"];

    if NETWORK.iter().any(|v| lower.contains(v)) {
        Some("network device")
    } else if PRINTER.iter().any(|v| lower.contains(v)) {
        Some("printer")
    } else if VIRTUAL.iter().any(|v| lower.contains(v)) {
        Some("virtual machine")
    } else if PHONE.iter().any(|v| lower.contains(v)) {
        Some("VoIP phone")
    } else if CAMERA.iter().any(|v| lower.contains(v)) {
        Some("IP camera")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundled_table_is_populated() {
        assert!(
            bundled_prefix_count() >= 100,
            "expected a useful vendor table, got {}",
            bundled_prefix_count()
        );
    }

    #[test]
    fn every_bundled_line_parses() {
        for (n, line) in OUI_DATA.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (prefix, vendor) = line
                .split_once('\t')
                .unwrap_or_else(|| panic!("line {} is not tab separated: {line:?}", n + 1));
            assert!(
                parse_prefix(prefix.trim()).is_some(),
                "line {} has a bad prefix: {prefix:?}",
                n + 1
            );
            assert!(!vendor.trim().is_empty(), "line {} has no vendor", n + 1);
        }
    }

    #[test]
    fn known_prefixes_resolve() {
        let apple: MacAddress = "00:1b:63:11:22:33".parse().unwrap();
        assert_eq!(vendor_for(&apple), Some("Apple"));

        let vmware: MacAddress = "00:50:56:aa:bb:cc".parse().unwrap();
        assert_eq!(vendor_for(&vmware), Some("VMware"));
    }

    #[test]
    fn unknown_prefixes_return_none() {
        let unknown: MacAddress = "de:ad:be:ef:00:01".parse().unwrap();
        assert_eq!(vendor_for(&unknown), None);
    }

    #[test]
    fn randomised_addresses_are_not_attributed_to_a_vendor() {
        let randomised: MacAddress = "02:50:56:aa:bb:cc".parse().unwrap();
        assert!(randomised.is_locally_administered());
        assert_eq!(vendor_for(&randomised), None);
    }

    #[test]
    fn deliberately_local_prefixes_still_resolve() {
        let qemu: MacAddress = "52:54:00:12:34:56".parse().unwrap();
        assert_eq!(vendor_for(&qemu), Some("QEMU"));
    }

    #[test]
    fn device_hints_are_only_given_when_unambiguous() {
        assert_eq!(device_hint("Cisco Systems"), Some("network device"));
        assert_eq!(device_hint("Brother Industries"), Some("printer"));
        assert_eq!(device_hint("VMware"), Some("virtual machine"));
        assert_eq!(device_hint("Hikvision"), Some("IP camera"));

        assert_eq!(device_hint("Apple"), None);
        assert_eq!(device_hint(""), None);
    }
}
