// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Failure from a bounded offline analysis run.

use std::time::Duration;
use thiserror::Error;

use crate::analysis::pcap::Error as CaptureError;
use crate::analysis::reassembly::ip::Error as IpError;
use crate::analysis::reassembly::tcp::Error as TcpError;
use crate::budget::DeadlineExceeded;

use crate::error::{Classification, Classified, Kind};

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid analysis limit {field}={value}: {reason}")]
    InvalidLimit {
        field: &'static str,
        value: u64,
        reason: &'static str,
    },
    #[error("capture read failed at frame {number}: {source}")]
    Capture {
        number: u64,
        #[source]
        source: CaptureError,
    },
    #[error("dissection failed at frame {number}: {source}")]
    Decode {
        number: u64,
        #[source]
        source: crate::decode::Error,
    },
    #[error("derived IP datagram construction failed at frame {number}: {source}")]
    DerivedFrame {
        number: u64,
        #[source]
        source: crate::frame::Error,
    },
    #[error("derived IP datagram dissection failed at frame {number}: {source}")]
    DerivedDecode {
        number: u64,
        #[source]
        source: crate::decode::Error,
    },
    #[error("display filter failed at frame {number}: {source}")]
    Filter {
        number: u64,
        #[source]
        source: crate::filter::Error,
    },
    #[error("conversation table reached the configured limit of {limit} flows at frame {number}")]
    StreamLimit { number: u64, limit: usize },
    #[error("capture scope indexing failed at frame {number}: {source}")]
    Scope {
        number: u64,
        #[source]
        source: crate::analysis::scope::Error,
    },
    #[error("TCP reassembly failed at frame {number}: {source}")]
    Reassembly {
        number: u64,
        #[source]
        source: crate::analysis::reassembly::tcp::Error,
    },
    #[error("IP reassembly failed at frame {number}: {source}")]
    IpReassembly {
        number: u64,
        #[source]
        source: crate::analysis::reassembly::ip::Error,
    },
    #[error("analysis ran {actual:?}, exceeding the configured duration of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
    #[error("capture timestamp at frame {number} exceeds the monotonic analysis clock range")]
    TimestampRange { number: u64 },
    #[error("capture frame {number} has no timestamp required by offline analysis")]
    TimestampUnavailable { number: u64 },
    #[error("analysis consumer failed at frame {number}: {source}")]
    Sink {
        number: u64,
        #[source]
        source: crate::error::BoundaryError,
    },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::InvalidLimit { .. } => Classification::new(
                "cli.analysis_limit",
                Kind::Cli,
                Some("use finite non-zero analysis frame, byte, flow, and duration limits"),
            ),
            Self::Capture { source, .. } => source.classification(),
            // A frame refused for exceeding the configured per-frame budget
            // is a resource condition, not malformed input.
            Self::Decode {
                source: crate::decode::Error::PacketSizeLimit { .. },
                ..
            } => resource_limit(GENERAL_RESOURCE_REMEDIATION),
            Self::Decode { .. } | Self::DerivedDecode { .. } => Classification::new(
                "packet.decode",
                Kind::Packet,
                Some("repair the frame or raise the per-frame byte limit it was read under"),
            ),
            Self::DerivedFrame { .. } => Classification::new(
                "internal.derived_frame",
                Kind::Internal,
                Some("report the capture and command as an internal reconstruction failure"),
            ),
            Self::TimestampRange { .. } => Classification::new(
                "packet.timestamp",
                Kind::Packet,
                Some("repair the capture timestamp that exceeds the platform clock range"),
            ),
            Self::TimestampUnavailable { .. } => Classification::new(
                "packet.timestamp_unavailable",
                Kind::Packet,
                Some("use timestamped packet blocks for time-dependent offline analysis"),
            ),
            Self::Filter {
                source: crate::filter::Error::TimestampUnavailable,
                ..
            } => Classification::new(
                "packet.timestamp_unavailable",
                Kind::Packet,
                Some("remove frame.time_epoch from the filter or use timestamped packet blocks"),
            ),
            Self::Filter { .. } => {
                Classification::new("cli.filter", Kind::Cli, Some("repair the display filter"))
            }
            Self::StreamLimit { .. } | Self::DurationLimit { .. } => {
                resource_limit(GENERAL_RESOURCE_REMEDIATION)
            }
            Self::Scope {
                source:
                    crate::analysis::scope::Error::Capacity
                    | crate::analysis::scope::Error::Limit { .. },
                ..
            } => resource_limit(GENERAL_RESOURCE_REMEDIATION),
            Self::Scope { .. } => Classification::new(
                "internal.scope_composition",
                Kind::Internal,
                Some("report the capture and command as an internal scope-composition failure"),
            ),
            // Reassembly fails for two distinct reasons: a finite budget was
            // exhausted, or the capture itself carries conflicting data. Only
            // the former is answered by raising budgets, and both engines
            // make the caller choose a side rather than leaving a catch-all
            // here to misfile a future variant.
            Self::Reassembly { source, .. } => match source {
                TcpError::Resource(_) => resource_limit(TCP_RESOURCE_REMEDIATION),
                TcpError::Malformed(_) => malformed_reassembly(),
            },
            Self::IpReassembly { source, .. } => match source {
                IpError::Resource(_) => resource_limit(IP_RESOURCE_REMEDIATION),
                IpError::Malformed(_) => malformed_reassembly(),
                IpError::Inconsistent { .. } => Classification::new(
                    "internal.ip_reassembly",
                    Kind::Internal,
                    Some("report the capture and command as an internal IP reassembly failure"),
                ),
            },
            Self::Sink { source, .. } => source.classification(),
        }
    }

    /// Walked from the retained `#[source]` chain rather than hand-written.
    /// The consumer variant delegates instead: a [`BoundaryError`] carries a
    /// captured `causes` snapshot that its own source chain no longer holds.
    ///
    /// [`BoundaryError`]: crate::error::BoundaryError
    fn causes(&self) -> Vec<String> {
        match self {
            Self::Sink { source, .. } => source.causes(),
            error => crate::error::source_chain(error),
        }
    }
}

impl From<DeadlineExceeded> for Error {
    fn from(error: DeadlineExceeded) -> Self {
        Self::DurationLimit {
            actual: error.actual,
            limit: error.limit,
        }
    }
}

const GENERAL_RESOURCE_REMEDIATION: &str =
    "narrow the input with a filter or deliberately raise the finite analysis budget";
const IP_RESOURCE_REMEDIATION: &str = "trim or pre-filter the capture, or deliberately raise the \
                                       relevant finite --max-ip-* analysis budget";
const TCP_RESOURCE_REMEDIATION: &str = "trim or pre-filter the capture, or deliberately raise the \
                                        relevant finite --max-tcp-* analysis budget";

fn resource_limit(remediation: &'static str) -> Classification {
    Classification::new(
        "policy.analysis_resource_limit",
        Kind::Policy,
        Some(remediation),
    )
}

fn malformed_reassembly() -> Classification {
    Classification::new(
        "packet.reassembly",
        Kind::Packet,
        Some(
            "the capture carries conflicting or malformed reassembly data; inspect the flow \
             rather than raising budgets",
        ),
    )
}
