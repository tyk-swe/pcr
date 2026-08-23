// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Neighbor resolution failures and internal error construction.

#![forbid(unsafe_code)]

use std::net::IpAddr;

use packetcraftr_core::{
    error::{Classification, Classified},
    frame::Frame,
};

use super::Request;
use crate::{Error as LiveIoError, capture::Statistics, interface::Id as InterfaceId};

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
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
    #[error("interface {interface} has no source MAC for Layer 2 transmission")]
    MissingSourceMac { interface: String },
    #[error("Layer 2 plan on {interface} has no neighbor target")]
    MissingNeighborTarget { interface: String },
    #[error("Layer 2 plan on {interface} has no interface-owned neighbor source address")]
    MissingNeighborSource { interface: String },
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
        source: LiveIoError,
    },
    #[error(
        "neighbor resolution for {target} on {interface} completed but capture cleanup failed: {source}"
    )]
    Cleanup {
        interface: String,
        target: IpAddr,
        source: LiveIoError,
    },
    #[error(
        "neighbor resolution for {target} on {interface} failed and capture cleanup also failed: operation={operation}; cleanup={cleanup}"
    )]
    OperationAndCleanup {
        interface: String,
        target: IpAddr,
        operation: Box<Error>,
        cleanup: LiveIoError,
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
                Some(
                    "inspect the selected gateway, VLAN, and interface; the finite neighbor-resolution budget was exhausted",
                ),
            ),
            Self::Resolution { .. } => Classification::new(
                "io.neighbor",
                Some(
                    "inspect the correlated ARP/NDP evidence and selected logical link before retrying",
                ),
            ),
            Self::InvalidOptions { .. } => Classification::new(
                "cli.neighbor_limit",
                Some(
                    "use finite non-zero neighbor attempts, timeouts, cache limits, and capture bounds",
                ),
            ),
            Self::MissingSourceMac { .. }
            | Self::MissingNeighborTarget { .. }
            | Self::MissingNeighborSource { .. }
            | Self::InvalidRequest { .. }
            | Self::State { .. } => Classification::new(
                "internal.neighbor_invariant",
                Some(
                    "do not transmit with the incomplete neighbor request or inconsistent resolver state",
                ),
            ),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Io { source, .. } | Self::Cleanup { source, .. } => {
                vec![source.to_string()]
            }
            Self::OperationAndCleanup {
                operation, cleanup, ..
            } => vec![operation.to_string(), cleanup.to_string()],
            _ => Vec::new(),
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
    error: LiveIoError,
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
