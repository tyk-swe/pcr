// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::budget::{Cancelled, DeadlineExceeded, Interrupted};
use packetcraftr_core::error::{BoundaryError, Classification, Classified, Coordinate, Kind};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid OS identification request: {0}")]
    Invalid(String),
    #[error(transparent)]
    Corpus(#[from] packetcraftr_core::document::os_fingerprints::Error),
    #[error(transparent)]
    Cancelled(#[from] Cancelled),
    #[error("OS identification deadline exceeded")]
    Deadline(#[from] DeadlineExceeded),
    #[error("OS identification authorization failed")]
    Authorization(#[source] BoundaryError),
    #[error("OS identification execution failed at probe {sequence}")]
    Execution {
        sequence: u64,
        #[source]
        source: BoundaryError,
    },
    #[error("invalid OS identification evidence at probe {sequence}: {message}")]
    Evidence { sequence: u64, message: String },
    #[error("OS identification output failed")]
    Output(#[source] BoundaryError),
}

impl From<Interrupted> for Error {
    fn from(source: Interrupted) -> Self {
        match source {
            Interrupted::Cancelled(source) => Self::Cancelled(source),
            Interrupted::Exceeded(source) => Self::Deadline(source),
            _ => Self::Cancelled(Cancelled),
        }
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Corpus(source) => source.classification(),
            Self::Cancelled(source) => source.classification(),
            Self::Deadline(source) => source.classification(),
            Self::Authorization(source) | Self::Execution { source, .. } | Self::Output(source) => {
                source.classification()
            }
            Self::Invalid(_) => Classification::new("cli.identify_os_limit", Kind::Usage, None),
            Self::Evidence { .. } => {
                Classification::new("internal.identify_os_evidence", Kind::Internal, None)
            }
        }
    }

    fn context(&self) -> Option<Coordinate> {
        match self {
            Self::Execution { sequence, .. } | Self::Evidence { sequence, .. } => {
                Some(Coordinate::ProbeSequence(*sequence))
            }
            Self::Authorization(source) | Self::Output(source) => source.context(),
            _ => None,
        }
    }
}

pub(crate) fn probe_error(sequence: u64, failure: crate::error::Failure) -> Error {
    match failure {
        crate::error::Failure::InvalidLimit {
            field,
            value,
            reason,
        } => Error::Invalid(format!("{field}={value}: {reason}")),
        crate::error::Failure::Authorization(source) => Error::Authorization(source),
        crate::error::Failure::DurationLimit(source) => source.into(),
        crate::error::Failure::Interrupted(source) => source.into(),
        crate::error::Failure::Clock(source) => Error::Execution {
            sequence,
            source: BoundaryError::with_source(
                "OS probe clock failed",
                Classification::new("io.identify_os_clock", Kind::Io, None),
                Vec::new(),
                std::io::Error::other(source),
            ),
        },
        crate::error::Failure::Execution(source) => Error::Execution { sequence, source },
        crate::error::Failure::InvalidEvidence(source) => Error::Evidence {
            sequence,
            message: crate::probe::Workflow::Os.describe_evidence(&source),
        },
        crate::error::Failure::StatsOverflow(_) => Error::Evidence {
            sequence,
            message: "statistics overflow".into(),
        },
    }
}
