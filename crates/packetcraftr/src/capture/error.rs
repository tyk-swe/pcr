// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::error::{Classification, Classified, Coordinate, Kind};

use crate::BoundaryError;

use super::Report;

/// Why a capture failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Cause {
    #[error(transparent)]
    Native(packetcraftr_netio::Error),
    #[error(transparent)]
    Budget(#[from] crate::policy::Error),
    #[error(transparent)]
    Cancelled(#[from] packetcraftr_core::budget::Cancelled),
    /// The selector or the sink failed, or the sink did not answer in time.
    #[error("capture consumer failed: {0}")]
    Consumer(#[source] BoundaryError),
    #[error("invalid capture operation: {0}")]
    Invalid(&'static str),
    #[error("capture statistics cannot be combined without overflow")]
    Statistics,
    #[error("capture evidence was lost at source {source_index}: {error}")]
    Loss {
        source_index: usize,
        #[source]
        error: packetcraftr_netio::Error,
    },
}

impl Classified for Cause {
    fn classification(&self) -> Classification {
        match self {
            Self::Native(error) | Self::Loss { error, .. } => error.classification(),
            Self::Budget(error) => error.classification(),
            Self::Cancelled(error) => error.classification(),
            Self::Consumer(error) => error.classification(),
            Self::Invalid(_) => Classification::new("cli.capture_options", Kind::Usage, None),
            Self::Statistics => {
                Classification::new("internal.capture_statistics", Kind::Internal, None)
            }
        }
    }
}

/// A failed capture, with the report of everything it did before failing.
#[derive(Debug, thiserror::Error)]
#[error("{cause}")]
pub struct Error {
    #[source]
    pub cause: Box<Cause>,
    pub report: Box<Report>,
    /// Capture shutdown failures that followed the primary failure.
    pub cleanup: Vec<packetcraftr_netio::Error>,
    pub source_frame: Option<u64>,
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        self.cause.classification()
    }
    fn context(&self) -> Option<Coordinate> {
        self.source_frame.map(Coordinate::SourceFrame)
    }
    fn causes(&self) -> Vec<String> {
        let mut causes = match self.cause.as_ref() {
            // A boundary error carries a captured causes snapshot that its own
            // source chain no longer holds.
            Cause::Consumer(error) => error.causes(),
            Cause::Native(error) => error.causes(),
            _ => packetcraftr_core::error::source_chain(self),
        };
        for failure in &self.cleanup {
            causes.push(failure.to_string());
            causes.extend(failure.causes());
        }
        causes
    }
}
