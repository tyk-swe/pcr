// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::budget::{Cancelled, Interrupted};
use packetcraftr_core::error::{Classification, Classified, Kind, Source};

use crate::Unsupported;
use thiserror::Error as ThisError;

#[derive(Debug, ThisError, Clone)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Cancelled(#[from] Cancelled),
    #[error("live operation deadline expired while {operation}")]
    DeadlineExceeded { operation: &'static str },
    #[error(transparent)]
    Unsupported(#[from] Unsupported),
    #[error("interface discovery failed: {message}")]
    Discovery {
        message: String,
        #[source]
        source: Source,
    },
}

impl Error {
    pub(crate) fn interrupted(interrupted: Interrupted) -> Self {
        match interrupted {
            Interrupted::Cancelled(cancelled) => cancelled.into(),
            _ => Self::DeadlineExceeded {
                operation: "enumerating interfaces",
            },
        }
    }

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

pub(crate) fn discovery_classification() -> Classification {
    Classification::new(
        "io.interface_discovery",
        Kind::Io,
        Some("inspect the operating-system interface state and retry with an available interface"),
    )
}
