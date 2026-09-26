// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::error::{Classification, Classified};
use thiserror::Error as ThisError;

use crate::SystemFault;

/// Why interface enumeration failed.
#[derive(Debug, ThisError, Clone)]
#[non_exhaustive]
pub enum Error {
    /// This build or target has no native interface enumeration.
    #[error("live packet I/O is unavailable: {message}")]
    Unsupported { message: String },
    /// The provider refused the query or answered with an invalid snapshot;
    /// `source` holds that failure.
    #[error("interface discovery failed: {message}")]
    Discovery {
        message: String,
        #[source]
        source: SystemFault,
    },
}

impl Error {
    /// Wraps the failure a native backend reported while enumerating.
    #[cfg(native_route)]
    pub(crate) fn native(error: crate::route::SystemError) -> Self {
        match error {
            crate::route::SystemError::Unsupported { message } => Self::Unsupported { message },
            error => Self::Discovery {
                message: "the native route adapter refused the interface query".to_owned(),
                source: std::sync::Arc::new(error),
            },
        }
    }
}

/// Interface failures surface as the live I/O failures they are, with the
/// same classification.
impl From<Error> for crate::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::Unsupported { message } => Self::Unsupported {
                message,
                source: None,
            },
            Error::Discovery { message, source } => Self::InterfaceDiscovery {
                message,
                source: Some(source),
            },
        }
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        crate::Error::from(self.clone()).classification()
    }
}
