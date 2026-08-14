use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

use crate::error::ProbeError;
use crate::protocols::ProbeOutcome;
use crate::scanner::result::PortReason;

#[derive(Debug)]
pub struct ConnectProbe {
    pub outcome: ProbeOutcome,
    pub stream: Option<TcpStream>,
}

pub async fn connect(
    target: SocketAddr,
    timeout: Duration,
    source: Option<IpAddr>,
) -> ConnectProbe {
    let started = Instant::now();

    let socket = match make_socket(&target, source) {
        Ok(socket) => socket,
        Err(err) => {
            return ConnectProbe {
                outcome: ProbeOutcome::failed(ProbeError::from_io(&err)),
                stream: None,
            }
        }
    };

    match tokio::time::timeout(timeout, socket.connect(target)).await {
        Ok(Ok(stream)) => {
            let rtt = started.elapsed();

            let _ = stream.set_nodelay(true);
            ConnectProbe {
                outcome: ProbeOutcome::open(PortReason::ConnectionEstablished, rtt),
                stream: Some(stream),
            }
        }
        Ok(Err(err)) => ConnectProbe {
            outcome: classify_error(&err, started),
            stream: None,
        },
        Err(_elapsed) => ConnectProbe {
            outcome: ProbeOutcome::filtered(PortReason::NoResponse),
            stream: None,
        },
    }
}

fn make_socket(target: &SocketAddr, source: Option<IpAddr>) -> io::Result<TcpSocket> {
    let socket = match target {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };

    if let Some(source) = source {
        let compatible = matches!(
            (source, target),
            (IpAddr::V4(_), SocketAddr::V4(_)) | (IpAddr::V6(_), SocketAddr::V6(_))
        );
        if compatible {
            socket.bind(SocketAddr::new(source, 0))?;
        }
    }

    Ok(socket)
}

fn classify_error(err: &io::Error, started: Instant) -> ProbeOutcome {
    use io::ErrorKind as K;
    match err.kind() {
        K::ConnectionRefused | K::ConnectionReset => {
            ProbeOutcome::closed(PortReason::Refused, Some(started.elapsed()))
        }

        K::HostUnreachable | K::NetworkUnreachable | K::NetworkDown => ProbeOutcome {
            state: crate::scanner::result::PortState::Filtered,
            reason: PortReason::HostUnreachable,
            rtt: None,
            error: None,
        },
        K::PermissionDenied => ProbeOutcome {
            state: crate::scanner::result::PortState::Filtered,
            reason: PortReason::AdminProhibited,
            rtt: None,
            error: None,
        },
        K::TimedOut => ProbeOutcome::filtered(PortReason::NoResponse),
        _ => ProbeOutcome::failed(ProbeError::from_io(err)),
    }
}

pub async fn read_banner(
    stream: &mut TcpStream,
    timeout: Duration,
    max_bytes: usize,
) -> Option<Vec<u8>> {
    let mut buffer = vec![0u8; max_bytes.min(64 * 1024)];
    let mut filled = 0usize;

    for attempt in 0..2 {
        let remaining = buffer.len() - filled;
        if remaining == 0 {
            break;
        }
        let per_read = if attempt == 0 {
            timeout
        } else {
            Duration::from_millis(120)
        };
        match tokio::time::timeout(per_read, stream.read(&mut buffer[filled..])).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                filled += n;

                if buffer[..filled].contains(&b'\n') {
                    break;
                }
            }
            Ok(Err(_)) | Err(_) => break,
        }
    }

    if filled == 0 {
        return None;
    }
    buffer.truncate(filled);
    Some(buffer)
}

pub async fn request_response(
    stream: &mut TcpStream,
    payload: &[u8],
    timeout: Duration,
    max_bytes: usize,
) -> Option<Vec<u8>> {
    if !payload.is_empty() {
        match tokio::time::timeout(timeout, stream.write_all(payload)).await {
            Ok(Ok(())) => {}
            _ => return None,
        }
        let _ = tokio::time::timeout(timeout, stream.flush()).await;
    }

    let mut buffer = vec![0u8; max_bytes.min(64 * 1024)];
    let mut filled = 0usize;
    let deadline = Instant::now() + timeout;

    loop {
        let remaining_time = deadline.saturating_duration_since(Instant::now());
        if remaining_time.is_zero() || filled == buffer.len() {
            break;
        }
        match tokio::time::timeout(remaining_time, stream.read(&mut buffer[filled..])).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                filled += n;

                if filled >= 2048 {
                    break;
                }
            }
            Ok(Err(_)) | Err(_) => break,
        }
    }

    if filled == 0 {
        return None;
    }
    buffer.truncate(filled);
    Some(buffer)
}

pub fn sanitise_banner(bytes: &[u8], max_chars: usize) -> String {
    let mut out = String::with_capacity(bytes.len().min(max_chars));
    for &byte in bytes {
        if out.chars().count() >= max_chars {
            out.push('…');
            break;
        }
        match byte {
            b'\t' => out.push(' '),
            b'\r' => {}
            b'\n' => out.push_str("\\n"),
            0x20..=0x7e => out.push(byte as char),
            _ => out.push('.'),
        }
    }
    out.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn banners_are_stripped_of_control_characters() {
        let hostile = b"HTTP/1.1 200 OK\x1b[2J\x1b[31mgotcha\r\nServer: x";
        let safe = sanitise_banner(hostile, 200);
        assert!(!safe.contains('\x1b'), "escape sequence survived: {safe:?}");
        assert!(safe.contains("HTTP/1.1 200 OK"));
        assert!(
            safe.contains("\\n"),
            "newlines should be shown, not executed"
        );
    }

    #[test]
    fn banners_are_truncated_with_an_ellipsis() {
        let long = vec![b'a'; 500];
        let safe = sanitise_banner(&long, 32);
        assert_eq!(
            safe.chars().count(),
            33,
            "expected 32 characters plus an ellipsis"
        );
        assert!(safe.ends_with('…'));
    }

    #[test]
    fn empty_banner_is_empty() {
        assert_eq!(sanitise_banner(b"", 100), "");
        assert_eq!(sanitise_banner(b"   \r\n", 100), "\\n");
    }

    #[tokio::test]
    async fn open_port_is_detected_and_the_stream_is_returned() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;

            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let probe = connect(addr, Duration::from_secs(2), None).await;
        assert_eq!(probe.outcome.state, crate::scanner::result::PortState::Open);
        assert_eq!(probe.outcome.reason, PortReason::ConnectionEstablished);
        assert!(probe.outcome.rtt.is_some());
        assert!(
            probe.stream.is_some(),
            "an open port should hand back its stream"
        );
    }

    #[tokio::test]
    async fn closed_port_is_detected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let probe = connect(addr, Duration::from_secs(2), None).await;
        assert_eq!(
            probe.outcome.state,
            crate::scanner::result::PortState::Closed
        );
        assert_eq!(probe.outcome.reason, PortReason::Refused);
        assert!(probe.stream.is_none());
    }

    #[tokio::test]
    async fn timeout_is_reported_as_filtered() {
        let addr: SocketAddr = "198.51.100.1:80".parse().unwrap();
        let probe = connect(addr, Duration::from_millis(150), None).await;
        assert!(
            matches!(
                probe.outcome.state,
                crate::scanner::result::PortState::Filtered
                    | crate::scanner::result::PortState::Unknown
            ),
            "unexpected state {:?}",
            probe.outcome.state
        );
    }

    #[tokio::test]
    async fn banner_is_read_from_a_talkative_service() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let mut probe = connect(addr, Duration::from_secs(2), None).await;
        let stream = probe.stream.as_mut().unwrap();
        let banner = read_banner(stream, Duration::from_secs(1), 1024)
            .await
            .unwrap();
        assert_eq!(sanitise_banner(&banner, 100), "SSH-2.0-OpenSSH_9.6\\n");
    }

    #[tokio::test]
    async fn silent_service_yields_no_banner() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(500)).await;
        });

        let mut probe = connect(addr, Duration::from_secs(2), None).await;
        let stream = probe.stream.as_mut().unwrap();
        assert!(read_banner(stream, Duration::from_millis(100), 1024)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn request_response_round_trips() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"PING\n");
            stream.write_all(b"PONG\n").await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let mut probe = connect(addr, Duration::from_secs(2), None).await;
        let stream = probe.stream.as_mut().unwrap();
        let reply = request_response(stream, b"PING\n", Duration::from_secs(1), 1024).await;
        assert_eq!(reply.as_deref(), Some(&b"PONG\n"[..]));
    }

    #[tokio::test]
    async fn banner_reading_respects_the_byte_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let flood = vec![b'x'; 1024 * 1024];
            let _ = stream.write_all(&flood).await;
        });

        let mut probe = connect(addr, Duration::from_secs(2), None).await;
        let stream = probe.stream.as_mut().unwrap();
        let banner = read_banner(stream, Duration::from_millis(500), 256)
            .await
            .unwrap();
        assert!(
            banner.len() <= 256,
            "read {} bytes despite a 256 byte limit",
            banner.len()
        );
    }
}
