pub mod icmp;
#[cfg(feature = "raw")]
#[cfg_attr(docsrs, doc(cfg(feature = "raw")))]
pub mod raw;
pub mod tcp;
pub mod tls;
pub mod udp;

use std::time::Duration;

use crate::error::ProbeError;
use crate::scanner::result::{PortReason, PortState};

#[derive(Debug, Clone, PartialEq)]
pub struct ProbeOutcome {
    pub state: PortState,
    pub reason: PortReason,
    pub rtt: Option<Duration>,
    pub error: Option<ProbeError>,
}

impl ProbeOutcome {
    pub fn open(reason: PortReason, rtt: Duration) -> Self {
        Self {
            state: PortState::Open,
            reason,
            rtt: Some(rtt),
            error: None,
        }
    }

    pub fn closed(reason: PortReason, rtt: Option<Duration>) -> Self {
        Self {
            state: PortState::Closed,
            reason,
            rtt,
            error: None,
        }
    }

    pub fn filtered(reason: PortReason) -> Self {
        Self {
            state: PortState::Filtered,
            reason,
            rtt: None,
            error: None,
        }
    }

    pub fn open_filtered(reason: PortReason) -> Self {
        Self {
            state: PortState::OpenFiltered,
            reason,
            rtt: None,
            error: None,
        }
    }

    pub fn failed(error: ProbeError) -> Self {
        Self {
            state: PortState::Unknown,
            reason: PortReason::ProbeFailed,
            rtt: None,
            error: Some(error),
        }
    }

    pub fn is_conclusive(&self) -> bool {
        matches!(self.state, PortState::Open | PortState::Closed)
    }

    pub fn is_retryable(&self) -> bool {
        match self.state {
            PortState::Filtered | PortState::OpenFiltered => true,
            PortState::Unknown => {
                matches!(
                    self.error,
                    Some(ProbeError::Timeout) | Some(ProbeError::Os(_))
                )
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conclusive_outcomes_are_not_retried() {
        let open = ProbeOutcome::open(PortReason::ConnectionEstablished, Duration::from_millis(1));
        assert!(open.is_conclusive());
        assert!(!open.is_retryable());

        let closed = ProbeOutcome::closed(PortReason::Refused, None);
        assert!(closed.is_conclusive());
        assert!(!closed.is_retryable());
    }

    #[test]
    fn timeouts_are_retried() {
        let filtered = ProbeOutcome::filtered(PortReason::NoResponse);
        assert!(!filtered.is_conclusive());
        assert!(filtered.is_retryable());

        let open_filtered = ProbeOutcome::open_filtered(PortReason::NoResponse);
        assert!(open_filtered.is_retryable());
    }

    #[test]
    fn local_resource_failures_are_not_retried() {
        let exhausted =
            ProbeOutcome::failed(ProbeError::LocalResourceExhausted("too many files".into()));
        assert!(
            !exhausted.is_retryable(),
            "retrying will not free file descriptors"
        );

        let cancelled = ProbeOutcome::failed(ProbeError::Cancelled);
        assert!(!cancelled.is_retryable());
    }
}
