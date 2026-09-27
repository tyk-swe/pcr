// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Why a native route or interface-route lookup failed.

use std::net::IpAddr;

use thiserror::Error as ThisError;

use packetcraftr_core::budget::{Cancelled, Interrupted};
use packetcraftr_core::error::{Classification, Classified, Kind, Source};

use crate::Unsupported;

/// Native route/interface errors. An operating-system refusal keeps the
/// platform's own error as its `source`.
#[derive(Debug, ThisError, Clone)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Cancelled(#[from] Cancelled),
    /// The caller's deadline expired before the native lookup answered.
    #[error("live operation deadline expired while {operation}")]
    DeadlineExceeded { operation: &'static str },
    #[error(transparent)]
    Unsupported(#[from] Unsupported),
    #[error("no route to {destination} was found")]
    RouteNotFound { destination: IpAddr },
    #[error("interface {name} (index {index}) was not found")]
    InterfaceNotFound { name: String, index: u32 },
    #[error(
        "interface preference {requested} (index {requested_index}) resolved to {actual} (index {actual_index})"
    )]
    InterfaceMismatch {
        requested: String,
        requested_index: u32,
        actual: String,
        actual_index: u32,
    },
    #[error(
        "preferred source {preferred_source} has a different address family than destination {destination}"
    )]
    SourceFamilyMismatch {
        preferred_source: IpAddr,
        destination: IpAddr,
    },
    #[error("preferred source {preferred_source} is not assigned to interface {interface}")]
    SourceUnavailable {
        preferred_source: IpAddr,
        interface: String,
    },
    #[error("native route response was invalid: {message}")]
    InvalidResponse { message: String },
    #[error("native operation {operation} failed: {message}")]
    OperatingSystem {
        operation: &'static str,
        message: String,
        #[source]
        source: Option<Source>,
    },
}

impl Error {
    /// The failure a backend reports when its caller's deadline stopped it
    /// while `operation` was in progress.
    pub(crate) fn interrupted(interrupted: Interrupted, operation: &'static str) -> Self {
        match interrupted {
            Interrupted::Cancelled(cancelled) => cancelled.into(),
            _ => Self::DeadlineExceeded { operation },
        }
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Cancelled(source) => source.classification(),
            Self::DeadlineExceeded { operation } => {
                crate::Error::DeadlineExceeded { operation }.classification()
            }
            Self::Unsupported(unsupported) => unsupported.classification(),
            Self::RouteNotFound { .. } => Classification::new(
                "io.route_not_found",
                Kind::Io,
                Some(
                    "add or select a route for the destination; PacketcraftR will not fall back to another link mode",
                ),
            ),
            Self::InterfaceNotFound { .. } => Classification::new(
                "io.interface_not_found",
                Kind::Io,
                Some("select an existing interface using its current name and index"),
            ),
            Self::InterfaceMismatch { .. }
            | Self::SourceFamilyMismatch { .. }
            | Self::SourceUnavailable { .. } => Classification::new(
                "io.route_selection",
                Kind::Io,
                Some(
                    "choose an interface-owned source and interface compatible with the destination family",
                ),
            ),
            Self::InvalidResponse { .. } => Classification::new(
                "internal.route_response",
                Kind::Internal,
                Some("report the invalid native route response; do not use it for transmission"),
            ),
            Self::OperatingSystem { .. } => Classification::new(
                "io.route",
                Kind::Io,
                Some(
                    "inspect the operating-system route diagnostic and current network configuration",
                ),
            ),
        }
    }
}
