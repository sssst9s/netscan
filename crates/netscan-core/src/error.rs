use std::net::IpAddr;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid target `{input}`: {reason}")]
    InvalidTarget { input: String, reason: String },
    #[error("invalid port specification `{input}`: {reason}")]
    InvalidPorts { input: String, reason: String },
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("{what} limit exceeded: requested {requested}, maximum {maximum} ({hint})")]
    LimitExceeded {
        what: &'static str,
        requested: u64,
        maximum: u64,
        hint: &'static str,
    },
    #[error("{operation} requires elevated privileges ({detail})")]
    PrivilegesRequired {
        operation: &'static str,
        detail: String,
    },
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("dns lookup for `{name}` failed: {source}")]
    Dns {
        name: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("network interface `{name}` unavailable: {reason}")]
    Interface { name: String, reason: String },
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("scan cancelled")]
    Cancelled,
}

impl Error {
    pub fn invalid_target(input: impl Into<String>, reason: impl Into<String>) -> Self {
        Error::InvalidTarget {
            input: input.into(),
            reason: reason.into(),
        }
    }

    pub fn invalid_ports(input: impl Into<String>, reason: impl Into<String>) -> Self {
        Error::InvalidPorts {
            input: input.into(),
            reason: reason.into(),
        }
    }

    pub fn privileges(operation: &'static str, detail: impl Into<String>) -> Self {
        Error::PrivilegesRequired {
            operation,
            detail: detail.into(),
        }
    }

    pub fn dns<E>(name: impl Into<String>, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Error::Dns {
            name: name.into(),
            source: Box::new(source),
        }
    }

    pub fn is_transient(&self) -> bool {
        match self {
            Error::Io(e) => matches!(
                e.kind(),
                std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::AddrInUse
            ),
            Error::Dns { .. } => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "detail")]
#[non_exhaustive]
pub enum ProbeError {
    Timeout,
    Unreachable(String),
    LocalResourceExhausted(String),
    Os(String),
    Cancelled,
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeError::Timeout => write!(f, "timed out"),
            ProbeError::Unreachable(d) => write!(f, "unreachable: {d}"),
            ProbeError::LocalResourceExhausted(d) => write!(f, "local resources exhausted: {d}"),
            ProbeError::Os(d) => write!(f, "os error: {d}"),
            ProbeError::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl ProbeError {
    pub fn from_io(err: &std::io::Error) -> Self {
        use std::io::ErrorKind as K;
        match err.kind() {
            K::TimedOut | K::WouldBlock => ProbeError::Timeout,
            K::HostUnreachable | K::NetworkUnreachable | K::NetworkDown => {
                ProbeError::Unreachable(err.to_string())
            }
            K::AddrInUse | K::OutOfMemory => ProbeError::LocalResourceExhausted(err.to_string()),
            _ => match err.raw_os_error() {
                Some(24) | Some(23) => ProbeError::LocalResourceExhausted(err.to_string()),
                _ => ProbeError::Os(err.to_string()),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Warning {
    pub code: String,
    pub message: String,
    pub host: Option<IpAddr>,
}

impl Warning {
    pub fn global(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            host: None,
        }
    }

    pub fn for_host(code: impl Into<String>, message: impl Into<String>, host: IpAddr) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            host: Some(host),
        }
    }
}

impl std::fmt::Display for Warning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.host {
            Some(h) => write!(f, "[{}] {}: {}", self.code, h, self.message),
            None => write!(f, "[{}] {}", self.code, self.message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_classification() {
        let timeout = Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "t"));
        assert!(timeout.is_transient());

        let refused = Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "r",
        ));
        assert!(!refused.is_transient());

        assert!(!Error::Cancelled.is_transient());
    }

    #[test]
    fn probe_error_from_io_maps_timeouts() {
        let err = std::io::Error::new(std::io::ErrorKind::TimedOut, "x");
        assert_eq!(ProbeError::from_io(&err), ProbeError::Timeout);
    }

    #[test]
    fn probe_error_from_io_maps_fd_exhaustion() {
        let err = std::io::Error::from_raw_os_error(24);
        assert!(matches!(
            ProbeError::from_io(&err),
            ProbeError::LocalResourceExhausted(_)
        ));
    }

    #[test]
    fn limit_error_message_is_actionable() {
        let err = Error::LimitExceeded {
            what: "target",
            requested: 16_777_216,
            maximum: 65_536,
            hint: "raise --max-targets or narrow the range",
        };
        let text = err.to_string();
        assert!(text.contains("16777216"));
        assert!(text.contains("--max-targets"));
    }

    #[test]
    fn warning_display_includes_host() {
        let w = Warning::for_host("x.y", "boom", "10.0.0.1".parse().unwrap());
        assert_eq!(w.to_string(), "[x.y] 10.0.0.1: boom");
    }
}
