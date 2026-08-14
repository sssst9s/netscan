use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;

use crate::error::{Error, Result};
use crate::scanner::port::Transport;
use crate::scanner::result::{Confidence, DetectionSource, ServiceInfo};

const BUILTIN_PROBES: &str = include_str!("../../data/probes.toml");

#[derive(Debug)]
pub struct ProbeContext<'a> {
    pub host: std::net::IpAddr,
    pub port: u16,
    pub transport: Transport,
    pub timeout: std::time::Duration,
    pub max_response_bytes: usize,
    pub banner: Option<&'a [u8]>,
    pub stream: Option<&'a mut TcpStream>,
    pub spent: bool,
}

impl ProbeContext<'_> {
    pub fn host_header(&self) -> String {
        match self.host {
            std::net::IpAddr::V4(v4) => v4.to_string(),
            std::net::IpAddr::V6(v6) => format!("[{v6}]"),
        }
    }
}

#[async_trait]
pub trait Probe: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &str;

    fn transport(&self) -> Transport;

    fn intrusiveness(&self) -> u8;

    fn ports(&self) -> &[u16];

    fn applies_to(&self, port: u16) -> bool {
        self.ports().is_empty() || self.ports().contains(&port)
    }

    async fn run(&self, ctx: &mut ProbeContext<'_>) -> Option<ServiceInfo>;

    fn match_bytes(&self, _response: &[u8]) -> Option<ServiceInfo> {
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchRuleDefinition {
    pub pattern: String,
    pub service: String,
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub extra: Option<String>,
    #[serde(default = "default_confidence")]
    pub confidence: Confidence,
}

fn default_confidence() -> Confidence {
    Confidence::High
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeDefinition {
    pub name: String,
    #[serde(default = "default_transport")]
    pub transport: Transport,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub intrusiveness: u8,
    #[serde(default)]
    pub send: Option<String>,
    #[serde(default)]
    pub use_banner: bool,
    #[serde(default, rename = "match")]
    pub matches: Vec<MatchRuleDefinition>,
}

fn default_transport() -> Transport {
    Transport::Tcp
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeFile {
    #[serde(default, rename = "probe")]
    pub probes: Vec<ProbeDefinition>,
}

#[derive(Debug)]
struct MatchRule {
    regex: Regex,
    service: String,
    product: Option<String>,
    version: Option<String>,
    extra: Option<String>,
    confidence: Confidence,
}

impl MatchRule {
    fn compile(definition: &MatchRuleDefinition, probe: &str) -> Result<Self> {
        let regex = Regex::new(&definition.pattern).map_err(|e| {
            Error::Config(format!(
                "probe `{probe}` has an invalid pattern `{}`: {e}",
                definition.pattern
            ))
        })?;
        Ok(Self {
            regex,
            service: definition.service.clone(),
            product: definition.product.clone(),
            version: definition.version.clone(),
            extra: definition.extra.clone(),
            confidence: definition.confidence,
        })
    }

    fn apply(&self, response: &[u8], probe_name: &str) -> Option<ServiceInfo> {
        let captures = self.regex.captures(response)?;
        Some(ServiceInfo {
            name: self.service.clone(),
            product: self.product.as_deref().map(|t| expand(t, &captures)),
            version: self.version.as_deref().map(|t| expand(t, &captures)),
            extra: self.extra.as_deref().map(|t| expand(t, &captures)),
            tls: false,
            source: DetectionSource::Probe(probe_name.to_string()),
            confidence: self.confidence,
        })
    }
}

fn expand(template: &str, captures: &regex::bytes::Captures<'_>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        let mut index = String::new();
        while let Some(d) = chars.peek() {
            if d.is_ascii_digit() {
                index.push(*d);
                chars.next();
            } else {
                break;
            }
        }
        if index.is_empty() {
            out.push('$');
            continue;
        }
        let group: usize = index.parse().unwrap_or(0);
        if let Some(matched) = captures.get(group) {
            out.push_str(&crate::protocols::tcp::sanitise_banner(
                matched.as_bytes(),
                128,
            ));
        }
    }
    out.trim().to_string()
}

#[derive(Debug)]
pub struct DeclarativeProbe {
    name: String,
    transport: Transport,
    ports: Vec<u16>,
    intrusiveness: u8,
    payload: Option<Vec<u8>>,
    use_banner: bool,
    rules: Vec<MatchRule>,
}

impl DeclarativeProbe {
    pub fn compile(definition: &ProbeDefinition) -> Result<Self> {
        if definition.name.trim().is_empty() {
            return Err(Error::Config("a probe definition has an empty name".into()));
        }
        if definition.intrusiveness > 9 {
            return Err(Error::Config(format!(
                "probe `{}` has intrusiveness {} but the range is 0-9",
                definition.name, definition.intrusiveness
            )));
        }
        if definition.matches.is_empty() {
            return Err(Error::Config(format!(
                "probe `{}` defines no match rules, so it can never identify anything",
                definition.name
            )));
        }
        if definition.send.is_none() && !definition.use_banner {
            return Err(Error::Config(format!(
                "probe `{}` neither sends a payload nor reads the banner",
                definition.name
            )));
        }

        let rules = definition
            .matches
            .iter()
            .map(|rule| MatchRule::compile(rule, &definition.name))
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            name: definition.name.clone(),
            transport: definition.transport,
            ports: definition.ports.clone(),
            intrusiveness: definition.intrusiveness,
            payload: definition.send.as_deref().map(|s| s.as_bytes().to_vec()),
            use_banner: definition.use_banner,
            rules,
        })
    }

    pub fn match_response(&self, response: &[u8]) -> Option<ServiceInfo> {
        self.rules
            .iter()
            .find_map(|rule| rule.apply(response, &self.name))
    }

    pub fn payload_for(&self, host_header: &str) -> Option<Vec<u8>> {
        let raw = self.payload.as_ref()?;
        let text = String::from_utf8_lossy(raw).replace("{host}", host_header);
        Some(decode_escapes(&text))
    }
}

#[async_trait]
impl Probe for DeclarativeProbe {
    fn name(&self) -> &str {
        &self.name
    }

    fn transport(&self) -> Transport {
        self.transport
    }

    fn intrusiveness(&self) -> u8 {
        self.intrusiveness
    }

    fn ports(&self) -> &[u16] {
        &self.ports
    }

    fn match_bytes(&self, response: &[u8]) -> Option<ServiceInfo> {
        self.match_response(response)
    }

    async fn run(&self, ctx: &mut ProbeContext<'_>) -> Option<ServiceInfo> {
        if self.use_banner {
            if let Some(banner) = ctx.banner {
                if let Some(service) = self.match_response(banner) {
                    return Some(service);
                }
            }
            self.payload.as_ref()?;
        }

        let payload = self.payload_for(&ctx.host_header())?;
        let stream = ctx.stream.as_deref_mut()?;
        let response = crate::protocols::tcp::request_response(
            stream,
            &payload,
            ctx.timeout,
            ctx.max_response_bytes,
        )
        .await?;

        ctx.spent = true;
        self.match_response(&response)
    }
}

fn decode_escapes(input: &str) -> Vec<u8> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' || i + 1 >= bytes.len() {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        match bytes[i + 1] {
            b'r' => {
                out.push(b'\r');
                i += 2;
            }
            b'n' => {
                out.push(b'\n');
                i += 2;
            }
            b't' => {
                out.push(b'\t');
                i += 2;
            }
            b'0' => {
                out.push(0);
                i += 2;
            }
            b'\\' => {
                out.push(b'\\');
                i += 2;
            }
            b'x' if i + 3 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 2..i + 4]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 4;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            other => {
                out.push(b'\\');
                out.push(other);
                i += 2;
            }
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct ProbeRegistry {
    probes: Vec<Arc<dyn Probe>>,
}

impl ProbeRegistry {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn builtin() -> Result<Self> {
        let mut registry = Self::empty();
        registry.load_toml(BUILTIN_PROBES).map_err(|e| match e {
            Error::Config(msg) => Error::Config(format!("built-in probes: {msg}")),
            other => other,
        })?;
        Ok(registry)
    }

    pub fn register(&mut self, probe: Arc<dyn Probe>) {
        self.probes.push(probe);
    }

    pub fn load_toml(&mut self, text: &str) -> Result<usize> {
        let file: ProbeFile = toml::from_str(text)
            .map_err(|e| Error::Config(format!("invalid probe definitions: {e}")))?;

        let mut added = 0;
        for definition in &file.probes {
            let probe = Arc::new(DeclarativeProbe::compile(definition)?);
            let name = probe.name().to_string();
            self.probes.retain(|existing| existing.name() != name);
            self.probes.push(probe);
            added += 1;
        }
        Ok(added)
    }

    pub fn load_file(&mut self, path: &Path) -> Result<usize> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("could not read {}: {e}", path.display())))?;
        self.load_toml(&text).map_err(|e| match e {
            Error::Config(msg) => Error::Config(format!("{}: {msg}", path.display())),
            other => other,
        })
    }

    pub fn len(&self) -> usize {
        self.probes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.probes.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Arc<dyn Probe>> {
        self.probes.iter()
    }

    pub fn select(
        &self,
        transport: Transport,
        port: u16,
        max_intrusiveness: u8,
    ) -> Vec<Arc<dyn Probe>> {
        let candidates = || {
            self.probes
                .iter()
                .filter(|probe| probe.transport() == transport)
                .filter(|probe| probe.intrusiveness() <= max_intrusiveness)
        };

        let claims_port = candidates().any(|probe| probe.ports().contains(&port));

        let mut selected: Vec<_> = if claims_port {
            candidates()
                .filter(|probe| probe.applies_to(port))
                .cloned()
                .collect()
        } else {
            candidates().cloned().collect()
        };

        selected.sort_by_key(|probe| {
            let port_specific = probe.ports().contains(&port);
            (!port_specific, probe.intrusiveness())
        });
        selected
    }

    pub fn by_port(&self) -> BTreeMap<u16, Vec<&str>> {
        let mut map: BTreeMap<u16, Vec<&str>> = BTreeMap::new();
        for probe in &self.probes {
            for port in probe.ports() {
                map.entry(*port).or_default().push(probe.name());
            }
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn definition(name: &str, pattern: &str) -> ProbeDefinition {
        ProbeDefinition {
            name: name.to_string(),
            transport: Transport::Tcp,
            ports: vec![80],
            intrusiveness: 2,
            send: Some("GET / HTTP/1.0\\r\\n\\r\\n".to_string()),
            use_banner: false,
            matches: vec![MatchRuleDefinition {
                pattern: pattern.to_string(),
                service: "http".to_string(),
                product: Some("$1".to_string()),
                version: Some("$2".to_string()),
                extra: None,
                confidence: Confidence::High,
            }],
        }
    }

    #[test]
    fn escapes_are_decoded() {
        assert_eq!(decode_escapes("a\\r\\nb"), b"a\r\nb");
        assert_eq!(decode_escapes("\\x41\\x42"), b"AB");
        assert_eq!(decode_escapes("\\0"), &[0u8]);
        assert_eq!(decode_escapes("back\\\\slash"), b"back\\slash");

        assert_eq!(decode_escapes("\\q"), b"\\q");

        assert_eq!(decode_escapes("end\\"), b"end\\");
        assert_eq!(decode_escapes("\\xZZ"), b"\\xZZ");
    }

    #[test]
    fn payload_substitutes_the_host() {
        let probe = DeclarativeProbe::compile(&ProbeDefinition {
            send: Some("GET / HTTP/1.1\\r\\nHost: {host}\\r\\n\\r\\n".to_string()),
            ..definition("http", "^HTTP/1")
        })
        .unwrap();
        let payload = probe.payload_for("192.0.2.1").unwrap();
        assert_eq!(payload, b"GET / HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n");
    }

    #[test]
    fn ipv6_hosts_are_bracketed_in_headers() {
        let ctx = ProbeContext {
            host: "2001:db8::1".parse().unwrap(),
            port: 80,
            transport: Transport::Tcp,
            timeout: std::time::Duration::from_secs(1),
            max_response_bytes: 4096,
            banner: None,
            stream: None,
            spent: false,
        };
        assert_eq!(ctx.host_header(), "[2001:db8::1]");
    }

    #[test]
    fn capture_groups_are_substituted() {
        let probe = DeclarativeProbe::compile(&definition(
            "http",
            r"^HTTP/1\.[01].*\r\nServer: ([A-Za-z\-]+)/([0-9.]+)",
        ))
        .unwrap();
        let service = probe
            .match_response(b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n")
            .expect("should match");
        assert_eq!(service.name, "http");
        assert_eq!(service.product.as_deref(), Some("nginx"));
        assert_eq!(service.version.as_deref(), Some("1.24.0"));
        assert_eq!(service.source, DetectionSource::Probe("http".to_string()));
        assert_eq!(service.confidence, Confidence::High);
    }

    #[test]
    fn non_matching_responses_yield_nothing() {
        let probe = DeclarativeProbe::compile(&definition("http", "^HTTP/1")).unwrap();
        assert!(probe.match_response(b"SSH-2.0-OpenSSH_9.6").is_none());
        assert!(probe.match_response(b"").is_none());
    }

    #[test]
    fn matching_works_on_non_utf8_responses() {
        let probe = DeclarativeProbe::compile(&ProbeDefinition {
            matches: vec![MatchRuleDefinition {
                pattern: r"(?-u)^\xff\xfe".to_string(),
                service: "binary".to_string(),
                product: None,
                version: None,
                extra: None,
                confidence: Confidence::Medium,
            }],
            ..definition("binary", "unused")
        })
        .unwrap();
        assert!(probe.match_response(&[0xff, 0xfe, 0x00, 0x80]).is_some());
    }

    #[test]
    fn captured_text_is_sanitised() {
        let probe =
            DeclarativeProbe::compile(&definition("http", r"Server: (.+?)/([0-9.]+)")).unwrap();
        let hostile = b"HTTP/1.0 200 OK\r\nServer: \x1b[31mevil/1.0\r\n";
        let service = probe.match_response(hostile).unwrap();
        assert!(
            !service
                .product
                .as_deref()
                .unwrap_or_default()
                .contains('\x1b'),
            "escape sequence leaked into the product name"
        );
    }

    #[test]
    fn missing_capture_groups_expand_to_nothing() {
        let probe = DeclarativeProbe::compile(&definition("http", r"^(HTTP)/1\.[01]")).unwrap();
        let service = probe.match_response(b"HTTP/1.1 200 OK\r\n").unwrap();
        assert_eq!(service.product.as_deref(), Some("HTTP"));
        assert_eq!(
            service.version.as_deref(),
            Some(""),
            "$2 has no group to fill it"
        );
    }

    #[test]
    fn invalid_definitions_are_rejected_with_context() {
        let bad_pattern = ProbeDefinition {
            matches: vec![MatchRuleDefinition {
                pattern: "([unclosed".to_string(),
                service: "x".to_string(),
                product: None,
                version: None,
                extra: None,
                confidence: Confidence::High,
            }],
            ..definition("broken", "unused")
        };
        let err = DeclarativeProbe::compile(&bad_pattern).unwrap_err();
        assert!(
            err.to_string().contains("broken"),
            "error should name the probe: {err}"
        );

        let no_rules = ProbeDefinition {
            matches: vec![],
            ..definition("empty", "x")
        };
        assert!(DeclarativeProbe::compile(&no_rules).is_err());

        let silent = ProbeDefinition {
            send: None,
            use_banner: false,
            ..definition("silent", "x")
        };
        assert!(DeclarativeProbe::compile(&silent).is_err());

        let too_intrusive = ProbeDefinition {
            intrusiveness: 20,
            ..definition("loud", "x")
        };
        assert!(DeclarativeProbe::compile(&too_intrusive).is_err());
    }

    #[test]
    fn builtin_probes_compile() {
        let registry = ProbeRegistry::builtin().expect("built-in probes must compile");
        assert!(
            registry.len() >= 10,
            "expected a useful set of built-ins, got {}",
            registry.len()
        );
    }

    #[test]
    fn builtin_probes_cover_the_expected_protocols() {
        let registry = ProbeRegistry::builtin().unwrap();
        let names: Vec<_> = registry.iter().map(|p| p.name().to_string()).collect();
        for expected in [
            "http",
            "ssh",
            "ftp",
            "smtp",
            "redis",
            "mysql",
            "postgresql",
            "smb",
        ] {
            assert!(
                names.iter().any(|n| n == expected),
                "missing built-in probe `{expected}`"
            );
        }
    }

    #[test]
    fn selection_prefers_port_specific_then_least_intrusive() {
        let mut registry = ProbeRegistry::empty();
        registry
            .load_toml(
                r#"
[[probe]]
name = "generic-loud"
intrusiveness = 5
send = "x"
[[probe.match]]
pattern = "x"
service = "x"

[[probe]]
name = "http-quiet"
ports = [80]
intrusiveness = 1
send = "y"
[[probe.match]]
pattern = "y"
service = "http"

[[probe]]
name = "http-loud"
ports = [80]
intrusiveness = 4
send = "z"
[[probe.match]]
pattern = "z"
service = "http"
"#,
            )
            .unwrap();

        let selected = registry.select(Transport::Tcp, 80, 9);
        let names: Vec<_> = selected.iter().map(|p| p.name()).collect();
        assert_eq!(names, vec!["http-quiet", "http-loud", "generic-loud"]);
    }

    #[test]
    fn an_unclaimed_port_gets_every_probe_rather_than_none() {
        let registry = ProbeRegistry::builtin().unwrap();

        let selected = registry.select(Transport::Tcp, 47823, 9);
        assert!(!selected.is_empty(), "an unknown port must still be probed");
        assert!(
            selected.iter().any(|p| p.name() == "http"),
            "HTTP is the most likely thing on an unknown port"
        );

        assert_eq!(selected[0].intrusiveness(), 0);
        assert!(selected
            .windows(2)
            .all(|w| w[0].intrusiveness() <= w[1].intrusiveness()));
    }

    #[test]
    fn intrusiveness_cap_filters_probes() {
        let registry = ProbeRegistry::builtin().unwrap();
        let passive = registry.select(Transport::Tcp, 22, 0);
        assert!(
            passive.iter().all(|p| p.intrusiveness() == 0),
            "a cap of 0 must only allow passive probes"
        );
        let all = registry.select(Transport::Tcp, 22, 9);
        assert!(all.len() >= passive.len());
    }

    #[test]
    fn wrong_transport_probes_are_excluded() {
        let registry = ProbeRegistry::builtin().unwrap();
        for probe in registry.select(Transport::Udp, 53, 9) {
            assert_eq!(probe.transport(), Transport::Udp);
        }
    }

    #[test]
    fn later_definitions_override_earlier_ones_by_name() {
        let mut registry = ProbeRegistry::empty();
        let base = r#"
[[probe]]
name = "http"
ports = [80]
send = "a"
[[probe.match]]
pattern = "a"
service = "http"
"#;
        registry.load_toml(base).unwrap();
        assert_eq!(registry.len(), 1);

        registry
            .load_toml(
                r#"
[[probe]]
name = "http"
ports = [8080]
send = "b"
[[probe.match]]
pattern = "b"
service = "http-custom"
"#,
            )
            .unwrap();
        assert_eq!(
            registry.len(),
            1,
            "same-named probe should replace, not duplicate"
        );
        let on_8080 = registry.select(Transport::Tcp, 8080, 9);
        assert_eq!(on_8080.len(), 1);
        assert!(
            on_8080[0].ports().contains(&8080),
            "the replacement's ports should be in force"
        );
    }

    #[test]
    fn malformed_probe_files_are_rejected() {
        let mut registry = ProbeRegistry::empty();
        assert!(registry.load_toml("not toml [[[").is_err());
        assert!(registry.load_toml("[[probe]]\nname = \"x\"\n").is_err());
    }
}
