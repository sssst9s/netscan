use std::sync::OnceLock;

use regex::Regex;

use crate::scanner::port::Transport;
use crate::scanner::result::{Confidence, DetectionSource, ServiceInfo};

fn generic_version_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            r"(?i)\b([A-Za-z][A-Za-z0-9._+-]{2,30})/(\d+(?:\.\d+){1,3})\b",
            r"(?i)\b([A-Za-z][A-Za-z0-9.+]{2,30})_(\d+(?:\.\d+){1,3})\b",
            r"(?i)\b([A-Za-z][A-Za-z0-9.+-]{2,30}) (?:version )?v?(\d+(?:\.\d+){1,3})\b",
        ]
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect()
    })
}

pub fn extract_product_version(banner: &str) -> Option<(String, String)> {
    for pattern in generic_version_patterns() {
        for captures in pattern.captures_iter(banner) {
            let (Some(product), Some(version)) = (captures.get(1), captures.get(2)) else {
                continue;
            };
            let product = product.as_str().trim();
            if is_noise_word(product) {
                continue;
            }
            return Some((product.to_string(), version.as_str().trim().to_string()));
        }
    }
    None
}

fn is_noise_word(word: &str) -> bool {
    const NOISE: &[&str] = &[
        "http",
        "https",
        "rtsp",
        "sip",
        "ftp",
        "smtp",
        "ssh",
        "version",
        "protocol",
        "server",
        "service",
        "connection",
        "content",
        "date",
        "the",
        "and",
    ];
    let lower = word.to_ascii_lowercase();
    NOISE.contains(&lower.as_str())
}

pub fn service_from_banner(transport: Transport, port: u16, banner: &str) -> Option<ServiceInfo> {
    if banner.trim().is_empty() {
        return None;
    }

    let catalog_name = crate::detection::service::name_for_port(transport, port);
    let (product, version) = match extract_product_version(banner) {
        Some((p, v)) => (Some(p), Some(v)),
        None => (None, None),
    };

    let name = catalog_name
        .map(str::to_string)
        .or_else(|| product.clone().map(|p| p.to_ascii_lowercase()))
        .unwrap_or_else(|| "unknown".to_string());

    let confidence = if product.is_some() {
        Confidence::Medium
    } else {
        Confidence::Low
    };

    Some(ServiceInfo {
        name,
        product,
        version,
        extra: None,
        tls: false,
        source: DetectionSource::Banner,
        confidence,
    })
}

pub fn best_of(a: Option<ServiceInfo>, b: Option<ServiceInfo>) -> Option<ServiceInfo> {
    match (a, b) {
        (None, other) | (other, None) => other,
        (Some(a), Some(b)) => {
            if score(&b) > score(&a) {
                Some(b)
            } else {
                Some(a)
            }
        }
    }
}

fn score(service: &ServiceInfo) -> u32 {
    let mut score = u32::from(service.confidence.score()) * 10;
    if service.product.is_some() {
        score += 4;
    }
    if service.version.is_some() {
        score += 3;
    }
    if service.extra.is_some() {
        score += 1;
    }
    if service.name != "unknown" {
        score += 2;
    }
    score
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_slash_separated_versions() {
        assert_eq!(
            extract_product_version("Server: nginx/1.24.0"),
            Some(("nginx".to_string(), "1.24.0".to_string()))
        );
        assert_eq!(
            extract_product_version("Apache/2.4.57 (Debian)"),
            Some(("Apache".to_string(), "2.4.57".to_string()))
        );
    }

    #[test]
    fn extracts_underscore_separated_versions() {
        assert_eq!(
            extract_product_version("SSH-2.0-OpenSSH_9.6"),
            Some(("OpenSSH".to_string(), "9.6".to_string()))
        );
    }

    #[test]
    fn extracts_space_separated_versions() {
        assert_eq!(
            extract_product_version("220 mail.example ESMTP Postfix 3.7.4"),
            Some(("Postfix".to_string(), "3.7.4".to_string()))
        );
    }

    #[test]
    fn ignores_protocol_headers_in_the_product_position() {
        let result = extract_product_version("HTTP/1.1 200 OK\nServer: nginx/1.24.0");
        assert_eq!(result, Some(("nginx".to_string(), "1.24.0".to_string())));
    }

    #[test]
    fn returns_nothing_when_there_is_no_version() {
        assert_eq!(extract_product_version(""), None);
        assert_eq!(extract_product_version("hello"), None);
        assert_eq!(extract_product_version("+OK ready"), None);
    }

    #[test]
    fn banner_service_uses_the_port_catalog_for_its_name() {
        let service = service_from_banner(Transport::Tcp, 22, "SSH-2.0-OpenSSH_9.6").unwrap();
        assert_eq!(service.name, "ssh");
        assert_eq!(service.product.as_deref(), Some("OpenSSH"));
        assert_eq!(service.version.as_deref(), Some("9.6"));
        assert_eq!(service.source, DetectionSource::Banner);
        assert_eq!(service.confidence, Confidence::Medium);
    }

    #[test]
    fn banner_without_a_version_is_low_confidence() {
        let service = service_from_banner(Transport::Tcp, 12345, "hello there").unwrap();
        assert_eq!(service.confidence, Confidence::Low);
        assert_eq!(service.name, "unknown");
        assert!(service.product.is_none());
    }

    #[test]
    fn empty_banners_produce_nothing() {
        assert!(service_from_banner(Transport::Tcp, 22, "").is_none());
        assert!(service_from_banner(Transport::Tcp, 22, "   \n ").is_none());
    }

    #[test]
    fn best_of_prefers_higher_confidence() {
        let weak = ServiceInfo {
            name: "http".into(),
            confidence: Confidence::Low,
            source: DetectionSource::PortNumber,
            ..Default::default()
        };
        let strong = ServiceInfo {
            name: "http".into(),
            product: Some("nginx".into()),
            confidence: Confidence::High,
            source: DetectionSource::Probe("http".into()),
            ..Default::default()
        };

        assert_eq!(
            best_of(Some(weak.clone()), Some(strong.clone()))
                .unwrap()
                .confidence,
            Confidence::High
        );
        assert_eq!(
            best_of(Some(strong.clone()), Some(weak.clone()))
                .unwrap()
                .confidence,
            Confidence::High
        );
        assert_eq!(best_of(None, Some(weak.clone())).unwrap().name, "http");
        assert!(best_of(None, None).is_none());
    }

    #[test]
    fn best_of_prefers_more_detail_at_equal_confidence() {
        let bare = ServiceInfo {
            name: "http".into(),
            confidence: Confidence::Medium,
            ..Default::default()
        };
        let detailed = ServiceInfo {
            name: "http".into(),
            product: Some("nginx".into()),
            version: Some("1.24.0".into()),
            confidence: Confidence::Medium,
            ..Default::default()
        };
        let winner = best_of(Some(bare), Some(detailed)).unwrap();
        assert_eq!(winner.version.as_deref(), Some("1.24.0"));
    }
}
