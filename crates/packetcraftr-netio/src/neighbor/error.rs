// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Neighbor resolution failures and internal error construction.

use std::net::IpAddr;

use packetcraftr_core::{
    error::{Classification, Classified, Kind},
    frame::Frame,
};

use super::Request;
use crate::{capture::Statistics, interface::Id as InterfaceId};

/// The provider failures this wraps retain their own platform source, which
/// is not comparable, so these failures are matched on rather than equated.
#[derive(Debug, thiserror::Error, Clone)]
#[non_exhaustive]
pub enum Error {
    #[error("neighbor resolution for {target} on {interface} failed: {message}")]
    Resolution {
        interface: String,
        target: IpAddr,
        message: String,
    },
    #[error(
        "neighbor resolution returned no address for {target} on {interface} after {attempts} attempt(s)"
    )]
    NotFound {
        interface: String,
        target: IpAddr,
        attempts: u32,
        captured: Vec<Frame>,
        evidence_truncated: bool,
        capture_statistics: Statistics,
    },
    #[error("neighbor request is invalid: {message}")]
    InvalidRequest { message: String },
    #[error("neighbor resolver options are invalid: {message}")]
    InvalidOptions { message: String },
    #[error("neighbor resolver state failed: {message}")]
    State { message: String },
    #[error("neighbor resolution for {target} on {interface} failed while {operation}: {source}")]
    Io {
        interface: String,
        target: IpAddr,
        operation: &'static str,
        source: crate::Error,
    },
    #[error(
        "neighbor resolution for {target} on {interface} completed but capture cleanup failed: {source}"
    )]
    Cleanup {
        interface: String,
        target: IpAddr,
        source: crate::Error,
    },
    #[error(
        "neighbor resolution for {target} on {interface} failed and capture cleanup also failed: operation={operation}; cleanup={cleanup}"
    )]
    OperationAndCleanup {
        interface: String,
        target: IpAddr,
        operation: Box<Error>,
        cleanup: crate::Error,
    },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Io { source, .. } => source.classification(),
            Self::Cleanup { source, .. } => source.classification(),
            Self::OperationAndCleanup { operation, .. } => operation.classification(),
            Self::NotFound { .. } => Classification::new(
                "io.neighbor_timeout",
                Kind::Io,
                Some(
                    "inspect the selected gateway, VLAN, and interface; the finite neighbor-resolution budget was exhausted",
                ),
            ),
            Self::Resolution { .. } => Classification::new(
                "io.neighbor",
                Kind::Io,
                Some(
                    "inspect the correlated ARP/NDP evidence and selected logical link before retrying",
                ),
            ),
            Self::InvalidOptions { .. } => Classification::new(
                "cli.neighbor_limit",
                Kind::Cli,
                Some(
                    "use finite non-zero neighbor attempts, timeouts, cache limits, and capture bounds",
                ),
            ),
            Self::InvalidRequest { .. } | Self::State { .. } => Classification::new(
                "internal.neighbor_invariant",
                Kind::Internal,
                Some(
                    "do not transmit with the incomplete neighbor request or inconsistent resolver state",
                ),
            ),
        }
    }

    /// Walks the retained `#[source]` chain, except for the dual failure, which
    /// carries two unrelated errors at once and so has no single chain to walk.
    fn causes(&self) -> Vec<String> {
        match self {
            Self::OperationAndCleanup {
                operation, cleanup, ..
            } => vec![operation.to_string(), cleanup.to_string()],
            error => packetcraftr_core::error::source_chain(error),
        }
    }
}

pub(super) fn resolution_error(interface: &InterfaceId, target: IpAddr, message: String) -> Error {
    Error::Resolution {
        interface: interface.name.clone(),
        target,
        message,
    }
}

pub(super) fn map_io_error(
    request: &Request,
    operation: &'static str,
    error: crate::Error,
) -> Error {
    Error::Io {
        interface: request.interface.name.clone(),
        target: request.target,
        operation,
        source: error,
    }
}

pub(super) fn invalid_options(message: String) -> Error {
    Error::InvalidOptions { message }
}

pub(super) fn invalid_request(message: impl Into<String>) -> Error {
    Error::InvalidRequest {
        message: message.into(),
    }
}
