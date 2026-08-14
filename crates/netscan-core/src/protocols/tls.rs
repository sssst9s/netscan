use std::time::Duration;

use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use tokio::net::TcpStream;

use crate::scanner::result::TlsInfo;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsProbeResult {
    Tls(Box<TlsInfo>),
    TlsButRefused { reason: String },
    NotTls,
}

pub async fn inspect(
    stream: &mut TcpStream,
    server_name: Option<&str>,
    timeout: Duration,
    max_bytes: usize,
) -> TlsProbeResult {
    let hello = build_client_hello(server_name);
    let Some(response) =
        crate::protocols::tcp::request_response(stream, &hello, timeout, max_bytes.max(16 * 1024))
            .await
    else {
        return TlsProbeResult::NotTls;
    };
    interpret_server_response(&response)
}

pub fn interpret_server_response(response: &[u8]) -> TlsProbeResult {
    let records = split_records(response);
    if records.is_empty() {
        return TlsProbeResult::NotTls;
    }

    let mut alert_reason = None;
    let mut handshake = Vec::new();
    for record in &records {
        match record.content_type {
            HANDSHAKE => handshake.extend_from_slice(record.payload),
            ALERT if alert_reason.is_none() => {
                alert_reason = Some(describe_alert(record.payload));
            }
            _ => {}
        }
    }

    if handshake.is_empty() {
        return match alert_reason {
            Some(reason) => TlsProbeResult::TlsButRefused { reason },
            None => TlsProbeResult::NotTls,
        };
    }

    let mut info = TlsInfo::default();
    let mut saw_server_hello = false;

    for message in split_handshake_messages(&handshake) {
        match message.msg_type {
            SERVER_HELLO => {
                saw_server_hello = true;
                if let Some((version, cipher)) = parse_server_hello(message.body) {
                    info.version = Some(version.to_string());
                    info.cipher = Some(cipher_name(cipher));
                }
            }
            CERTIFICATE => {
                if let Some(der) = first_certificate(message.body) {
                    apply_certificate(&mut info, der);
                }
            }
            _ => {}
        }
    }

    if !saw_server_hello {
        return match alert_reason {
            Some(reason) => TlsProbeResult::TlsButRefused { reason },
            None => TlsProbeResult::NotTls,
        };
    }

    TlsProbeResult::Tls(Box::new(info))
}

const HANDSHAKE: u8 = 22;
const ALERT: u8 = 21;
const SERVER_HELLO: u8 = 2;
const CERTIFICATE: u8 = 11;

struct Record<'a> {
    content_type: u8,
    payload: &'a [u8],
}

fn split_records(data: &[u8]) -> Vec<Record<'_>> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + 5 <= data.len() {
        let content_type = data[offset];

        if !matches!(content_type, 20..=24) || data[offset + 1] != 0x03 {
            break;
        }
        let length = usize::from(u16::from_be_bytes([data[offset + 3], data[offset + 4]]));
        let start = offset + 5;
        let end = start.saturating_add(length).min(data.len());
        if start >= end {
            break;
        }
        out.push(Record {
            content_type,
            payload: &data[start..end],
        });
        offset = start + length;
    }
    out
}

struct HandshakeMessage<'a> {
    msg_type: u8,
    body: &'a [u8],
}

fn split_handshake_messages(data: &[u8]) -> Vec<HandshakeMessage<'_>> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + 4 <= data.len() {
        let msg_type = data[offset];
        let length = u24(&data[offset + 1..offset + 4]);
        let start = offset + 4;
        let end = start.saturating_add(length).min(data.len());
        if start > end {
            break;
        }
        out.push(HandshakeMessage {
            msg_type,
            body: &data[start..end],
        });
        if length == 0 {
            break;
        }
        offset = start + length;
    }
    out
}

fn u24(bytes: &[u8]) -> usize {
    (usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2])
}

fn parse_server_hello(body: &[u8]) -> Option<(&'static str, u16)> {
    if body.len() < 35 {
        return None;
    }
    let version = version_name(u16::from_be_bytes([body[0], body[1]]))?;
    let session_len = usize::from(body[34]);
    let cipher_offset = 35 + session_len;
    if body.len() < cipher_offset + 2 {
        return None;
    }
    let cipher = u16::from_be_bytes([body[cipher_offset], body[cipher_offset + 1]]);
    Some((version, cipher))
}

fn version_name(raw: u16) -> Option<&'static str> {
    match raw {
        0x0300 => Some("SSL 3.0"),
        0x0301 => Some("TLS 1.0"),
        0x0302 => Some("TLS 1.1"),
        0x0303 => Some("TLS 1.2"),
        0x0304 => Some("TLS 1.3"),
        _ => None,
    }
}

fn cipher_name(id: u16) -> String {
    let name = match id {
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x003c => "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0xc013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xc014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0xc027 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        _ => return format!("0x{id:04x}"),
    };
    name.to_string()
}

fn describe_alert(payload: &[u8]) -> String {
    if payload.len() < 2 {
        return "unspecified alert".to_string();
    }
    let description = match payload[1] {
        40 => "handshake failure",
        70 => "protocol version",
        71 => "insufficient security",
        80 => "internal error",
        112 => "unrecognised name",
        _ => "alert",
    };
    format!("{description} ({})", payload[1])
}

fn first_certificate(body: &[u8]) -> Option<&[u8]> {
    if body.len() < 6 {
        return None;
    }
    let cert_len = u24(&body[3..6]);
    let start = 6usize;
    let end = start.checked_add(cert_len)?;
    if end > body.len() || cert_len == 0 {
        return None;
    }
    Some(&body[start..end])
}

fn apply_certificate(info: &mut TlsInfo, der: &[u8]) {
    let Some(cert) = parse_certificate(der) else {
        return;
    };
    info.subject = cert.subject_cn;
    info.issuer = cert.issuer_cn;
    info.subject_alt_names = cert.subject_alt_names;
    info.not_before = cert.not_before;
    info.not_after = cert.not_after;
    info.self_signed = cert.subject_raw == cert.issuer_raw;
    info.expired = cert.not_after.map(|end| end < Utc::now()).unwrap_or(false);
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ParsedCertificate {
    pub subject_cn: Option<String>,
    pub issuer_cn: Option<String>,
    pub subject_alt_names: Vec<String>,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub subject_raw: Vec<u8>,
    pub issuer_raw: Vec<u8>,
}

pub fn parse_certificate(der: &[u8]) -> Option<ParsedCertificate> {
    let certificate = der_read(der, 0)?;
    if certificate.tag != 0x30 {
        return None;
    }
    let tbs = der_read(der, certificate.content_start)?;
    if tbs.tag != 0x30 {
        return None;
    }

    let mut out = ParsedCertificate::default();
    let mut offset = tbs.content_start;
    let tbs_end = tbs.content_end;
    let mut field = 0usize;

    while offset < tbs_end {
        let element = der_read(der, offset)?;

        if field == 0 && element.tag == 0xa0 {
            offset = element.content_end;
            continue;
        }

        match field {
            2 => {
                out.issuer_raw = der[element.header_start..element.content_end].to_vec();
                out.issuer_cn = find_common_name(der, &element);
            }
            3 => {
                let (start, end) = parse_validity(der, &element);
                out.not_before = start;
                out.not_after = end;
            }
            4 => {
                out.subject_raw = der[element.header_start..element.content_end].to_vec();
                out.subject_cn = find_common_name(der, &element);
            }
            _ => {}
        }

        if element.tag == 0xa3 {
            out.subject_alt_names = find_subject_alt_names(der, &element);
        }

        offset = element.content_end;
        field += 1;
    }

    Some(out)
}

#[derive(Debug, Clone, Copy)]
struct DerElement {
    tag: u8,
    header_start: usize,
    content_start: usize,
    content_end: usize,
}

fn der_read(data: &[u8], offset: usize) -> Option<DerElement> {
    let tag = *data.get(offset)?;
    let first_len = *data.get(offset + 1)?;

    let (content_start, length) = if first_len & 0x80 == 0 {
        (offset + 2, usize::from(first_len))
    } else {
        let count = usize::from(first_len & 0x7f);

        if count == 0 || count > 4 {
            return None;
        }
        let bytes = data.get(offset + 2..offset + 2 + count)?;
        let mut length = 0usize;
        for byte in bytes {
            length = length.checked_mul(256)?.checked_add(usize::from(*byte))?;
        }
        (offset + 2 + count, length)
    };

    let content_end = content_start.checked_add(length)?;
    if content_end > data.len() {
        return None;
    }
    Some(DerElement {
        tag,
        header_start: offset,
        content_start,
        content_end,
    })
}

const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];

const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];

fn find_common_name(data: &[u8], name: &DerElement) -> Option<String> {
    let mut offset = name.content_start;
    let mut last: Option<String> = None;
    while offset < name.content_end {
        let set = der_read(data, offset)?;
        let mut inner = set.content_start;
        while inner < set.content_end {
            let pair = der_read(data, inner)?;
            if pair.tag == 0x30 {
                let oid = der_read(data, pair.content_start)?;
                if oid.tag == 0x06 && &data[oid.content_start..oid.content_end] == OID_COMMON_NAME {
                    let value = der_read(data, oid.content_end)?;
                    last = Some(der_string(&data[value.content_start..value.content_end]));
                }
            }
            inner = pair.content_end;
        }
        offset = set.content_end;
    }
    last
}

fn find_subject_alt_names(data: &[u8], extensions_tag: &DerElement) -> Vec<String> {
    let mut names = Vec::new();
    let Some(sequence) = der_read(data, extensions_tag.content_start) else {
        return names;
    };

    let mut offset = sequence.content_start;
    while offset < sequence.content_end {
        let Some(extension) = der_read(data, offset) else {
            break;
        };
        offset = extension.content_end;
        if extension.tag != 0x30 {
            continue;
        }

        let Some(oid) = der_read(data, extension.content_start) else {
            continue;
        };
        if oid.tag != 0x06 || &data[oid.content_start..oid.content_end] != OID_SUBJECT_ALT_NAME {
            continue;
        }

        let mut inner = oid.content_end;
        while inner < extension.content_end {
            let Some(element) = der_read(data, inner) else {
                break;
            };
            inner = element.content_end;
            if element.tag != 0x04 {
                continue;
            }
            let Some(general_names) = der_read(data, element.content_start) else {
                continue;
            };
            let mut name_offset = general_names.content_start;
            while name_offset < general_names.content_end {
                let Some(general_name) = der_read(data, name_offset) else {
                    break;
                };
                name_offset = general_name.content_end;
                let value = &data[general_name.content_start..general_name.content_end];
                match general_name.tag {
                    0x82 => names.push(der_string(value)),
                    0x87 => {
                        if let Some(ip) = ip_from_bytes(value) {
                            names.push(ip);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    names
}

fn ip_from_bytes(bytes: &[u8]) -> Option<String> {
    match bytes.len() {
        4 => {
            let octets: [u8; 4] = bytes.try_into().ok()?;
            Some(std::net::Ipv4Addr::from(octets).to_string())
        }
        16 => {
            let octets: [u8; 16] = bytes.try_into().ok()?;
            Some(std::net::Ipv6Addr::from(octets).to_string())
        }
        _ => None,
    }
}

fn der_string(bytes: &[u8]) -> String {
    crate::protocols::tcp::sanitise_banner(bytes, 256)
}

fn parse_validity(
    data: &[u8],
    validity: &DerElement,
) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
    let Some(not_before) = der_read(data, validity.content_start) else {
        return (None, None);
    };
    let start = parse_der_time(
        not_before.tag,
        &data[not_before.content_start..not_before.content_end],
    );
    let Some(not_after) = der_read(data, not_before.content_end) else {
        return (start, None);
    };
    let end = parse_der_time(
        not_after.tag,
        &data[not_after.content_start..not_after.content_end],
    );
    (start, end)
}

fn parse_der_time(tag: u8, bytes: &[u8]) -> Option<DateTime<Utc>> {
    let text = std::str::from_utf8(bytes).ok()?;
    let text = text.trim_end_matches('Z');
    let (year, rest) = match tag {
        0x17 if text.len() >= 10 => {
            let two: i32 = text[0..2].parse().ok()?;

            let year = if two >= 50 { 1900 + two } else { 2000 + two };
            (year, &text[2..])
        }
        0x18 if text.len() >= 12 => (text[0..4].parse().ok()?, &text[4..]),
        _ => return None,
    };

    if rest.len() < 8 {
        return None;
    }
    let month: u32 = rest[0..2].parse().ok()?;
    let day: u32 = rest[2..4].parse().ok()?;
    let hour: u32 = rest[4..6].parse().ok()?;
    let minute: u32 = rest[6..8].parse().ok()?;
    let second: u32 = if rest.len() >= 10 {
        rest[8..10].parse().ok()?
    } else {
        0
    };

    let date = NaiveDate::from_ymd_opt(year, month, day)?;
    let naive = date.and_hms_opt(hour, minute, second)?;
    Utc.from_local_datetime(&naive).single()
}

pub fn build_client_hello(server_name: Option<&str>) -> Vec<u8> {
    let cipher_suites: [u16; 14] = [
        0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc014, 0xc013, 0xc027, 0x009d, 0x009c,
        0x003c, 0x0035, 0x002f,
    ];

    let mut body = Vec::with_capacity(256);
    body.extend_from_slice(&0x0303u16.to_be_bytes());

    body.extend_from_slice(b"netscan-probe---not-a-real-tls--");

    body.push(0);

    body.extend_from_slice(&((cipher_suites.len() * 2) as u16).to_be_bytes());
    for suite in cipher_suites {
        body.extend_from_slice(&suite.to_be_bytes());
    }

    body.push(1);
    body.push(0);

    let mut extensions = Vec::with_capacity(128);

    if let Some(name) =
        server_name.filter(|n| !n.is_empty() && n.parse::<std::net::IpAddr>().is_err())
    {
        let name_bytes = name.as_bytes();
        let mut sni = Vec::with_capacity(name_bytes.len() + 5);
        sni.extend_from_slice(&((name_bytes.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        sni.extend_from_slice(name_bytes);
        push_extension(&mut extensions, 0x0000, &sni);
    }

    push_extension(
        &mut extensions,
        0x000a,
        &[0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18],
    );

    push_extension(&mut extensions, 0x000b, &[0x01, 0x00]);

    push_extension(
        &mut extensions,
        0x000d,
        &[
            0x00, 0x0c, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01,
        ],
    );

    push_extension(&mut extensions, 0xff01, &[0x00]);

    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::with_capacity(body.len() + 4);
    handshake.push(1);
    let len = body.len();
    handshake.push((len >> 16) as u8);
    handshake.push((len >> 8) as u8);
    handshake.push(len as u8);
    handshake.extend_from_slice(&body);

    let mut record = Vec::with_capacity(handshake.len() + 5);
    record.push(HANDSHAKE);
    record.extend_from_slice(&0x0301u16.to_be_bytes());
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn push_extension(out: &mut Vec<u8>, id: u16, payload: &[u8]) {
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CERT: &[u8] = include_bytes!("../../tests/fixtures/test-cert.der");

    #[test]
    fn client_hello_is_a_well_formed_record() {
        let hello = build_client_hello(Some("example.test"));
        assert_eq!(hello[0], HANDSHAKE);
        assert_eq!(&hello[1..3], &[0x03, 0x01], "legacy record version");
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(
            record_len,
            hello.len() - 5,
            "record length must match the payload"
        );

        assert_eq!(hello[5], 1, "handshake type client_hello");
        let handshake_len = u24(&hello[6..9]);
        assert_eq!(handshake_len, hello.len() - 9);
        assert_eq!(&hello[9..11], &[0x03, 0x03], "client_version TLS 1.2");
    }

    #[test]
    fn client_hello_carries_sni_for_names_but_not_addresses() {
        let with_name = build_client_hello(Some("example.test"));
        assert!(
            with_name.windows(12).any(|w| w == b"example.test"),
            "SNI should contain the server name"
        );

        let with_ip = build_client_hello(Some("192.0.2.1"));
        assert!(!with_ip.windows(9).any(|w| w == b"192.0.2.1"));

        let without = build_client_hello(None);
        assert!(without.len() < with_name.len());
    }

    #[test]
    fn client_hello_does_not_offer_tls_13() {
        let hello = build_client_hello(None);
        let extensions_marker = hello.windows(2).any(|w| w == [0x00, 0x2b]);
        assert!(
            !extensions_marker,
            "TLS 1.3 must not be offered; see the module docs"
        );
    }

    fn server_flight(version: u16, cipher: u16, certificate: Option<&[u8]>) -> Vec<u8> {
        let mut hello_body = Vec::new();
        hello_body.extend_from_slice(&version.to_be_bytes());
        hello_body.extend_from_slice(&[0u8; 32]);
        hello_body.push(0);
        hello_body.extend_from_slice(&cipher.to_be_bytes());
        hello_body.push(0);

        let mut handshake = Vec::new();
        push_handshake(&mut handshake, SERVER_HELLO, &hello_body);

        if let Some(der) = certificate {
            let mut body = Vec::new();
            let list_len = der.len() + 3;
            body.extend_from_slice(&[
                (list_len >> 16) as u8,
                (list_len >> 8) as u8,
                list_len as u8,
            ]);
            body.extend_from_slice(&[
                (der.len() >> 16) as u8,
                (der.len() >> 8) as u8,
                der.len() as u8,
            ]);
            body.extend_from_slice(der);
            push_handshake(&mut handshake, CERTIFICATE, &body);
        }

        let mut record = Vec::new();
        record.push(HANDSHAKE);
        record.extend_from_slice(&0x0303u16.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn push_handshake(out: &mut Vec<u8>, msg_type: u8, body: &[u8]) {
        out.push(msg_type);
        out.push((body.len() >> 16) as u8);
        out.push((body.len() >> 8) as u8);
        out.push(body.len() as u8);
        out.extend_from_slice(body);
    }

    #[test]
    fn server_hello_yields_version_and_cipher() {
        let flight = server_flight(0x0303, 0xc02f, None);
        let TlsProbeResult::Tls(info) = interpret_server_response(&flight) else {
            panic!("expected a TLS result");
        };
        assert_eq!(info.version.as_deref(), Some("TLS 1.2"));
        assert_eq!(
            info.cipher.as_deref(),
            Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        );
    }

    #[test]
    fn unknown_ciphers_are_reported_numerically() {
        let flight = server_flight(0x0301, 0xdead, None);
        let TlsProbeResult::Tls(info) = interpret_server_response(&flight) else {
            panic!("expected a TLS result");
        };
        assert_eq!(info.version.as_deref(), Some("TLS 1.0"));
        assert_eq!(info.cipher.as_deref(), Some("0xdead"));
    }

    #[test]
    fn non_tls_responses_are_rejected() {
        assert_eq!(interpret_server_response(b""), TlsProbeResult::NotTls);
        assert_eq!(
            interpret_server_response(b"HTTP/1.1 400 Bad Request\r\n\r\n"),
            TlsProbeResult::NotTls
        );
        assert_eq!(
            interpret_server_response(b"SSH-2.0-OpenSSH_9.6\r\n"),
            TlsProbeResult::NotTls
        );
    }

    #[test]
    fn alerts_still_identify_a_tls_speaker() {
        let alert = [ALERT, 0x03, 0x03, 0x00, 0x02, 0x02, 70];
        match interpret_server_response(&alert) {
            TlsProbeResult::TlsButRefused { reason } => {
                assert!(reason.contains("protocol version"), "reason was {reason}");
            }
            other => panic!("expected TlsButRefused, got {other:?}"),
        }
    }

    #[test]
    fn truncated_records_do_not_panic() {
        for cut in 1..40 {
            let flight = server_flight(0x0303, 0xc02f, Some(TEST_CERT));
            let truncated = &flight[..flight.len().min(cut)];
            let _ = interpret_server_response(truncated);
        }
    }

    #[test]
    fn certificate_fields_are_extracted() {
        let cert = parse_certificate(TEST_CERT).expect("fixture should parse");
        assert_eq!(cert.subject_cn.as_deref(), Some("test.netscan.invalid"));
        assert_eq!(cert.issuer_cn.as_deref(), Some("test.netscan.invalid"));
        assert_eq!(
            cert.subject_raw, cert.issuer_raw,
            "the fixture is self-signed"
        );

        let not_before = cert.not_before.expect("notBefore");
        let not_after = cert.not_after.expect("notAfter");
        assert!(not_after > not_before);
        assert!(
            not_after.signed_duration_since(not_before).num_days() > 3000,
            "the fixture was issued for ten years"
        );
    }

    #[test]
    fn subject_alt_names_are_extracted() {
        let cert = parse_certificate(TEST_CERT).expect("fixture should parse");
        assert!(
            cert.subject_alt_names
                .iter()
                .any(|n| n == "test.netscan.invalid"),
            "SANs were {:?}",
            cert.subject_alt_names
        );
        assert!(cert
            .subject_alt_names
            .iter()
            .any(|n| n == "alt.netscan.invalid"));
        assert!(
            cert.subject_alt_names.iter().any(|n| n == "127.0.0.1"),
            "IP SANs should be decoded: {:?}",
            cert.subject_alt_names
        );
    }

    #[test]
    fn certificate_in_a_server_flight_populates_tls_info() {
        let flight = server_flight(0x0303, 0xc030, Some(TEST_CERT));
        let TlsProbeResult::Tls(info) = interpret_server_response(&flight) else {
            panic!("expected a TLS result");
        };
        assert_eq!(info.subject.as_deref(), Some("test.netscan.invalid"));
        assert!(info.self_signed);
        assert!(!info.expired, "the fixture is valid for ten years");
        assert!(!info.subject_alt_names.is_empty());
    }

    #[test]
    fn malformed_certificates_are_rejected_without_panicking() {
        assert!(parse_certificate(&[]).is_none());
        assert!(parse_certificate(&[0x30, 0x82, 0xff, 0xff]).is_none());
        assert!(parse_certificate(b"not a certificate at all").is_none());

        for cut in 0..TEST_CERT.len() {
            let _ = parse_certificate(&TEST_CERT[..cut]);
        }
    }

    #[test]
    fn der_lengths_are_bounds_checked() {
        let lying = [0x30u8, 0x84, 0x7f, 0xff, 0xff, 0xff, 0x00];
        assert!(der_read(&lying, 0).is_none());

        let absurd = [0x30u8, 0x88, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(der_read(&absurd, 0).is_none());
    }

    #[test]
    fn der_times_parse_both_encodings() {
        let utc = parse_der_time(0x17, b"260812182019Z").unwrap();
        assert_eq!(
            utc.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2026-08-12 18:20:19"
        );

        let old = parse_der_time(0x17, b"990101000000Z").unwrap();
        assert_eq!(old.format("%Y").to_string(), "1999");

        let generalized = parse_der_time(0x18, b"20360809182019Z").unwrap();
        assert_eq!(generalized.format("%Y-%m-%d").to_string(), "2036-08-09");

        assert!(parse_der_time(0x17, b"garbage").is_none());
        assert!(
            parse_der_time(0x17, b"261332000000Z").is_none(),
            "month 13 is not a month"
        );
    }

    #[test]
    fn certificate_strings_are_sanitised() {
        let hostile = b"\x1b[31mevil";
        assert!(!der_string(hostile).contains('\x1b'));
    }
}
