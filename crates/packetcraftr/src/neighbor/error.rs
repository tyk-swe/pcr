// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use packetcraftr_core::{
    error::{Classification, Classified, Kind, Source},
    frame::Frame,
};

use super::Request;
use packetcraftr_netio::{capture::Stats, interface::Id as InterfaceId};

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
        capture_statistics: Stats,
    },
    #[error("neighbor request is invalid: {message}")]
    InvalidRequest {
        message: String,
        #[source]
        source: Option<Source>,
    },
    #[error("neighbor resolver options are invalid: {message}")]
    InvalidOptions {
        message: String,
        #[source]
        source: Option<packetcraftr_netio::Error>,
    },
    #[error("neighbor resolver state failed: {message}")]
    State { message: String },
    #[error("neighbor resolution for {target} on {interface} failed while {operation}")]
    Io {
        interface: String,
        target: IpAddr,
        operation: &'static str,
        #[source]
        source: packetcraftr_netio::Error,
    },
    #[error("neighbor resolution for {target} on {interface} completed but capture cleanup failed")]
    Cleanup {
        interface: String,
        target: IpAddr,
        /// Requests sent before the cleanup failed.
        attempts: u32,
        #[source]
        source: packetcraftr_netio::Error,
    },
    #[error(
        "neighbor resolution for {target} on {interface} failed and capture cleanup also failed"
    )]
    OperationAndCleanup {
        interface: String,
        target: IpAddr,
        #[source]
        operation: Box<Self>,
        cleanup: packetcraftr_netio::Error,
    },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Io { source, .. } | Self::Cleanup { source, .. } => source.classification(),
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
                Kind::Usage,
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

    fn causes(&self) -> Vec<String> {
        match self {
            Self::OperationAndCleanup {
                operation, cleanup, ..
            } => {
                let mut causes = vec![operation.to_string()];
                causes.extend(operation.causes());
                causes.push(cleanup.to_string());
                causes.extend(cleanup.causes());
                causes
            }
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
    error: packetcraftr_netio::Error,
) -> Error {
    Error::Io {
        interface: request.interface.name.clone(),
        target: request.target,
        operation,
        source: error,
    }
}

pub(super) fn invalid_options(message: String) -> Error {
    Error::InvalidOptions {
        message,
        source: None,
    }
}

pub(super) fn invalid_request(message: impl Into<String>) -> Error {
    Error::InvalidRequest {
        message: message.into(),
        source: None,
    }
}

pub(super) fn unbuildable_request(
    message: impl Into<String>,
    source: impl std::error::Error + Send + Sync + 'static,
) -> Error {
    Error::InvalidRequest {
        message: message.into(),
        source: Some(Source::new(source)),
    }
}
