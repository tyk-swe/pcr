// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Why interface enumeration failed.

use packetcraftr_core::budget::{Cancelled, Interrupted};
use packetcraftr_core::error::{Classification, Classified, Kind, Source};

use crate::Unsupported;
use thiserror::Error as ThisError;

/// Why interface enumeration failed.
#[derive(Debug, ThisError, Clone)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Cancelled(#[from] Cancelled),
    /// The caller's deadline expired before enumeration finished.
    #[error("live operation deadline expired while {operation}")]
    DeadlineExceeded { operation: &'static str },
    /// This build or target has no native interface enumeration.
    #[error(transparent)]
    Unsupported(#[from] Unsupported),
    /// The provider refused the query or answered with an invalid snapshot;
    /// `source` holds that failure.
    #[error("interface discovery failed: {message}")]
    Discovery {
        message: String,
        #[source]
        source: Source,
    },
}

impl Error {
    /// The failure enumeration reports when its caller's deadline stopped it.
    pub(crate) fn interrupted(interrupted: Interrupted) -> Self {
        match interrupted {
            Interrupted::Cancelled(cancelled) => cancelled.into(),
            _ => Self::DeadlineExceeded {
                operation: "enumerating interfaces",
            },
        }
    }

    /// Wraps the failure a native backend reported while enumerating.
    #[cfg(native_route)]
    pub(crate) fn native(error: crate::route::Error) -> Self {
        match error {
            crate::route::Error::Unsupported(unsupported) => unsupported.into(),
            crate::route::Error::Cancelled(cancelled) => cancelled.into(),
            crate::route::Error::DeadlineExceeded { operation } => {
                Self::DeadlineExceeded { operation }
            }
            error => Self::Discovery {
                message: "the native route backend refused the interface query".to_owned(),
                source: Source::new(error),
            },
        }
    }
}

/// Interface failures surface as the live I/O failures they are, with the
/// same classification.
impl From<Error> for crate::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::Cancelled(cancelled) => cancelled.into(),
            Error::DeadlineExceeded { operation } => Self::DeadlineExceeded { operation },
            Error::Unsupported(unsupported) => unsupported.into(),
            Error::Discovery { message, source } => Self::InterfaceDiscovery {
                message,
                source: Some(source),
            },
        }
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Cancelled(cancelled) => cancelled.classification(),
            Self::DeadlineExceeded { operation } => {
                crate::Error::DeadlineExceeded { operation }.classification()
            }
            Self::Unsupported(unsupported) => unsupported.classification(),
            Self::Discovery { .. } => discovery_classification(),
        }
    }
}

/// The classification of a failed interface discovery, shared with the
/// live-I/O failure a capture reports for the same condition.
pub(crate) fn discovery_classification() -> Classification {
    Classification::new(
        "io.interface_discovery",
        Kind::Io,
        Some("inspect the operating-system interface state and retry with an available interface"),
    )
}
