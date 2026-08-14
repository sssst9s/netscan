use netscan_core::{HostReport, HostStatus, PortReport, PortState};

#[derive(Debug, Clone, PartialEq)]
pub struct Term {
    pub negated: bool,
    pub condition: Condition,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Condition {
    Port(u16),
    PortAbove(u16),
    PortBelow(u16),
    PortRange(u16, u16),
    Service(String),
    Product(String),
    Version(String),
    State(PortState),
    Status(HostStatus),
    Host(String),
    Net(ipnet::IpNet),
    Os(String),
    Vendor(String),
    Transport(netscan_core::Transport),
    Tls(bool),
    Text(String),
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Filter {
    pub terms: Vec<Term>,
    pub errors: Vec<String>,
}

impl Filter {
    pub fn parse(input: &str) -> Self {
        let mut filter = Filter::default();
        for raw in input.split_whitespace() {
            let (negated, token) = match raw.strip_prefix('!') {
                Some(rest) => (true, rest),
                None => (false, raw),
            };
            if token.is_empty() {
                continue;
            }
            match parse_term(token) {
                Ok(condition) => filter.terms.push(Term { negated, condition }),
                Err(message) => {
                    filter.errors.push(message);
                    filter.terms.push(Term {
                        negated,
                        condition: Condition::Text(token.to_ascii_lowercase()),
                    });
                }
            }
        }
        filter
    }

    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }

    pub fn matches_host(&self, host: &HostReport) -> bool {
        self.terms.iter().all(|term| {
            let matched = match &term.condition {
                condition if is_port_level(condition) => host
                    .ports
                    .iter()
                    .any(|port| matches_port_condition(condition, host, port)),
                condition => matches_host_condition(condition, host),
            };
            matched != term.negated
        })
    }

    pub fn matches_port(&self, host: &HostReport, port: &PortReport) -> bool {
        self.terms.iter().all(|term| {
            let matched = if is_port_level(&term.condition) {
                matches_port_condition(&term.condition, host, port)
            } else {
                matches_host_condition(&term.condition, host)
            };
            matched != term.negated
        })
    }
}

fn is_port_level(condition: &Condition) -> bool {
    matches!(
        condition,
        Condition::Port(_)
            | Condition::PortAbove(_)
            | Condition::PortBelow(_)
            | Condition::PortRange(_, _)
            | Condition::Service(_)
            | Condition::Product(_)
            | Condition::Version(_)
            | Condition::State(_)
            | Condition::Transport(_)
            | Condition::Tls(_)
            | Condition::Text(_)
    )
}

fn matches_port_condition(condition: &Condition, host: &HostReport, port: &PortReport) -> bool {
    let service = port.service.as_ref();
    match condition {
        Condition::Port(n) => port.port == *n,
        Condition::PortAbove(n) => port.port > *n,
        Condition::PortBelow(n) => port.port < *n,
        Condition::PortRange(low, high) => port.port >= *low && port.port <= *high,
        Condition::Service(text) => contains(port.service_name(), text),
        Condition::Product(text) => service
            .and_then(|s| s.product.as_deref())
            .is_some_and(|p| contains(p, text)),
        Condition::Version(text) => service
            .and_then(|s| s.version.as_deref())
            .is_some_and(|v| contains(v, text)),
        Condition::State(state) => port.state == *state,
        Condition::Transport(transport) => port.transport == *transport,
        Condition::Tls(expected) => {
            let has_tls = port.tls.is_some() || service.is_some_and(|s| s.tls);
            has_tls == *expected
        }
        Condition::Text(text) => {
            contains(&port.port.to_string(), text)
                || contains(port.service_name(), text)
                || service
                    .and_then(|s| s.product.as_deref())
                    .is_some_and(|p| contains(p, text))
                || service
                    .and_then(|s| s.version.as_deref())
                    .is_some_and(|v| contains(v, text))
                || port.banner.as_deref().is_some_and(|b| contains(b, text))
                || matches_host_condition(&Condition::Text(text.clone()), host)
        }
        _ => false,
    }
}

fn matches_host_condition(condition: &Condition, host: &HostReport) -> bool {
    match condition {
        Condition::Status(status) => host.status == *status,
        Condition::Host(text) => {
            contains(&host.address.to_string(), text)
                || host.hostnames.iter().any(|h| contains(&h.name, text))
        }
        Condition::Net(network) => network.contains(&host.address),
        Condition::Os(text) => host.os.as_ref().is_some_and(|os| {
            os.family.as_deref().is_some_and(|f| contains(f, text))
                || os.name.as_deref().is_some_and(|n| contains(n, text))
                || os.device_type.as_deref().is_some_and(|d| contains(d, text))
        }),
        Condition::Vendor(text) => host.vendor.as_deref().is_some_and(|v| contains(v, text)),
        Condition::Text(text) => {
            contains(&host.address.to_string(), text)
                || host.hostnames.iter().any(|h| contains(&h.name, text))
                || host.vendor.as_deref().is_some_and(|v| contains(v, text))
                || host.mac.is_some_and(|m| contains(&m.to_string(), text))
        }
        _ => false,
    }
}

fn contains(haystack: &str, needle: &str) -> bool {
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

fn parse_term(token: &str) -> Result<Condition, String> {
    let Some((key, value)) = token.split_once(':') else {
        return Ok(Condition::Text(token.to_ascii_lowercase()));
    };
    if value.is_empty() {
        return Err(format!("`{key}:` needs a value"));
    }
    let lower = value.to_ascii_lowercase();

    match key.to_ascii_lowercase().as_str() {
        "port" | "p" => parse_port_condition(value),
        "service" | "svc" => Ok(Condition::Service(lower)),
        "product" => Ok(Condition::Product(lower)),
        "version" | "ver" => Ok(Condition::Version(lower)),
        "state" => parse_state(&lower).map(Condition::State),
        "status" => parse_status(&lower).map(Condition::Status),
        "host" | "ip" | "addr" => Ok(Condition::Host(lower)),
        "net" | "subnet" | "cidr" => value
            .parse::<ipnet::IpNet>()
            .or_else(|_| value.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
            .map(Condition::Net)
            .map_err(|_| format!("`{value}` is not a network, such as 192.168.1.0/24")),
        "os" => Ok(Condition::Os(lower)),
        "vendor" | "mac" => Ok(Condition::Vendor(lower)),
        "proto" | "transport" => lower
            .parse()
            .map(Condition::Transport)
            .map_err(|_| format!("`{value}` is not a transport; use tcp or udp")),
        "tls" => match lower.as_str() {
            "true" | "yes" | "1" => Ok(Condition::Tls(true)),
            "false" | "no" | "0" => Ok(Condition::Tls(false)),
            _ => Err(format!("`tls:{value}` should be true or false")),
        },
        other => Err(format!("unknown filter field `{other}`")),
    }
}

fn parse_port_condition(value: &str) -> Result<Condition, String> {
    let invalid = |v: &str| format!("`{v}` is not a port number");

    if let Some(rest) = value.strip_prefix('>') {
        return rest
            .parse()
            .map(Condition::PortAbove)
            .map_err(|_| invalid(rest));
    }
    if let Some(rest) = value.strip_prefix('<') {
        return rest
            .parse()
            .map(Condition::PortBelow)
            .map_err(|_| invalid(rest));
    }
    if let Some((low, high)) = value.split_once('-') {
        let low: u16 = low.parse().map_err(|_| invalid(low))?;
        let high: u16 = high.parse().map_err(|_| invalid(high))?;
        if low > high {
            return Err(format!("`{value}` starts above where it ends"));
        }
        return Ok(Condition::PortRange(low, high));
    }
    value
        .parse()
        .map(Condition::Port)
        .map_err(|_| invalid(value))
}

fn parse_state(value: &str) -> Result<PortState, String> {
    match value {
        "open" => Ok(PortState::Open),
        "closed" => Ok(PortState::Closed),
        "filtered" => Ok(PortState::Filtered),
        "open|filtered" | "openfiltered" => Ok(PortState::OpenFiltered),
        "unknown" => Ok(PortState::Unknown),
        other => Err(format!("`{other}` is not a port state")),
    }
}

fn parse_status(value: &str) -> Result<HostStatus, String> {
    match value {
        "up" => Ok(HostStatus::Up),
        "down" => Ok(HostStatus::Down),
        "skipped" => Ok(HostStatus::Skipped),
        other => Err(format!("`{other}` is not a host status")),
    }
}

pub const FILTER_HELP: &[(&str, &str)] = &[
    ("port:22", "a specific port"),
    ("port:>1024", "ports above a number"),
    ("port:8000-9000", "a port range"),
    ("service:http", "service name"),
    ("product:nginx", "identified product"),
    ("state:open", "port state"),
    ("status:up", "host status"),
    ("host:192.168.1", "address or hostname"),
    ("net:192.168.1.0/24", "addresses inside a block"),
    ("os:linux", "inferred operating system"),
    ("vendor:apple", "hardware vendor"),
    ("tls:true", "ports speaking TLS"),
    ("!port:22", "negate any term"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use netscan_core::{Confidence, DetectionSource, OsGuess, PortReason, ServiceInfo, Transport};

    #[test]
    fn a_network_term_matches_by_containment_not_by_text() {
        let inside = HostReport::new("10.1.2.3".parse().unwrap());
        let outside = HostReport::new("192.168.10.1".parse().unwrap());

        let wide = Filter::parse("net:10.0.0.0/8");
        assert!(wide.errors.is_empty(), "{:?}", wide.errors);
        assert!(wide.matches_host(&inside));
        assert!(!wide.matches_host(&outside));

        let narrow = Filter::parse("net:192.168.1.0/24");
        assert!(!narrow.matches_host(&outside));
        assert!(Filter::parse("host:192.168.1").matches_host(&outside));
    }

    #[test]
    fn a_bare_address_is_accepted_as_a_network_of_one() {
        let host = HostReport::new("10.0.0.5".parse().unwrap());
        let filter = Filter::parse("net:10.0.0.5");
        assert!(filter.errors.is_empty(), "{:?}", filter.errors);
        assert!(filter.matches_host(&host));
        assert!(!filter.matches_host(&HostReport::new("10.0.0.6".parse().unwrap())));
    }

    #[test]
    fn an_ipv6_prefix_works_the_same_way() {
        let host = HostReport::new("2001:db8::1".parse().unwrap());
        assert!(Filter::parse("net:2001:db8::/64").matches_host(&host));
        assert!(!Filter::parse("net:2001:db9::/64").matches_host(&host));
    }

    #[test]
    fn a_malformed_network_is_reported_rather_than_ignored() {
        let filter = Filter::parse("net:notanetwork");
        assert_eq!(filter.errors.len(), 1);
        assert!(
            filter.errors[0].contains("192.168.1.0/24"),
            "the message should show the shape expected: {:?}",
            filter.errors
        );
    }

    fn host() -> HostReport {
        let mut host = HostReport::new("192.168.1.10".parse().unwrap());
        host.status = HostStatus::Up;
        host.vendor = Some("Apple".to_string());
        host.add_hostname(
            "web.example",
            netscan_core::scanner::result::HostnameSource::ReverseDns,
        );
        host.os = Some(OsGuess {
            family: Some("Linux".to_string()),
            confidence: Confidence::Medium,
            ..Default::default()
        });

        let mut ssh = PortReport::new(
            22,
            Transport::Tcp,
            PortState::Open,
            PortReason::ConnectionEstablished,
        );
        ssh.service = Some(ServiceInfo {
            name: "ssh".into(),
            product: Some("OpenSSH".into()),
            version: Some("9.6p1".into()),
            source: DetectionSource::Probe("ssh".into()),
            confidence: Confidence::High,
            ..Default::default()
        });
        host.ports.push(ssh);

        let mut https = PortReport::new(
            8443,
            Transport::Tcp,
            PortState::Open,
            PortReason::ConnectionEstablished,
        );
        https.service = Some(ServiceInfo {
            name: "https".into(),
            product: Some("nginx".into()),
            tls: true,
            ..Default::default()
        });
        host.ports.push(https);

        let dns = PortReport::new(
            53,
            Transport::Udp,
            PortState::OpenFiltered,
            PortReason::NoResponse,
        );
        host.ports.push(dns);
        host
    }

    fn matches(expression: &str) -> bool {
        Filter::parse(expression).matches_host(&host())
    }

    #[test]
    fn an_empty_filter_matches_everything() {
        let filter = Filter::parse("   ");
        assert!(filter.is_empty());
        assert!(filter.matches_host(&host()));
    }

    #[test]
    fn port_terms_match() {
        assert!(matches("port:22"));
        assert!(!matches("port:9999"));
        assert!(matches("port:>1000"));
        assert!(matches("port:<100"));
        assert!(matches("port:8000-9000"));
        assert!(!matches("port:100-200"));
        assert!(matches("p:22"), "the short form should work too");
    }

    #[test]
    fn service_and_product_terms_match() {
        assert!(matches("service:ssh"));
        assert!(matches("service:SSH"), "matching is case insensitive");
        assert!(matches("product:openssh"));
        assert!(matches("product:nginx"));
        assert!(!matches("product:apache"));
        assert!(matches("version:9.6"));
    }

    #[test]
    fn state_and_status_terms_match() {
        assert!(matches("state:open"));
        assert!(matches("status:up"));
        assert!(!matches("status:down"));
    }

    #[test]
    fn host_terms_match_address_and_name() {
        assert!(matches("host:192.168.1"));
        assert!(matches("host:web.example"));
        assert!(!matches("host:10.0.0"));
    }

    #[test]
    fn os_and_vendor_terms_match() {
        assert!(matches("os:linux"));
        assert!(!matches("os:windows"));
        assert!(matches("vendor:apple"));
    }

    #[test]
    fn transport_and_tls_terms_match() {
        assert!(matches("proto:udp"));
        assert!(matches("proto:tcp"));
        assert!(matches("tls:true"));
    }

    #[test]
    fn free_text_searches_everything() {
        assert!(matches("openssh"));
        assert!(matches("192.168"));
        assert!(matches("apple"));
        assert!(!matches("nonexistent"));
    }

    #[test]
    fn terms_are_combined_with_and() {
        assert!(matches("status:up service:ssh"));
        assert!(!matches("status:up service:ftp"));
        assert!(!matches("status:down service:ssh"));
    }

    #[test]
    fn negation_inverts_a_term() {
        assert!(!matches("!port:22"));
        assert!(matches("!port:9999"));
        assert!(matches("status:up !os:windows"));
    }

    #[test]
    fn port_level_terms_filter_rows_as_well_as_hosts() {
        let host = host();
        let filter = Filter::parse("port:22");
        assert!(filter.matches_host(&host), "the host has port 22");
        assert!(filter.matches_port(&host, &host.ports[0]));
        assert!(
            !filter.matches_port(&host, &host.ports[1]),
            "other rows should be hidden"
        );
    }

    #[test]
    fn host_level_terms_keep_every_row_of_a_matching_host() {
        let host = host();
        let filter = Filter::parse("status:up");
        for port in &host.ports {
            assert!(filter.matches_port(&host, port));
        }
    }

    #[test]
    fn unrecognised_fields_are_reported_and_treated_as_text() {
        let filter = Filter::parse("nonsense:value");
        assert_eq!(filter.errors.len(), 1);
        assert!(
            filter.errors[0].contains("nonsense"),
            "errors were {:?}",
            filter.errors
        );

        assert_eq!(filter.terms.len(), 1);
    }

    #[test]
    fn malformed_values_are_reported() {
        assert!(!Filter::parse("port:abc").errors.is_empty());
        assert!(!Filter::parse("state:sideways").errors.is_empty());
        assert!(!Filter::parse("tls:maybe").errors.is_empty());
        assert!(!Filter::parse("port:").errors.is_empty());
        assert!(!Filter::parse("port:90-10").errors.is_empty());
    }

    #[test]
    fn a_partially_typed_filter_still_works() {
        assert!(Filter::parse("service:htt").errors.is_empty());
        let filter = Filter::parse("port:2");
        assert!(filter.errors.is_empty());
        assert!(!filter.matches_host(&host()), "port:2 is not port 22");
    }

    #[test]
    fn every_documented_example_parses_cleanly() {
        for (expression, _) in FILTER_HELP {
            let filter = Filter::parse(expression);
            assert!(
                filter.errors.is_empty(),
                "the documented example `{expression}` did not parse: {:?}",
                filter.errors
            );
        }
    }
}
