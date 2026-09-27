// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error as ThisError;

use packetcraftr_core::error::{BoundaryError, Classification, Classified, Coordinate, Kind};

/// Why a send stopped.
#[derive(Debug, ThisError)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Preparation(#[from] crate::Error),
    #[error("invalid send option {field}: {message}")]
    InvalidRequest {
        field: &'static str,
        message: String,
    },
    #[error("send progressive output failed")]
    Output {
        #[source]
        source: BoundaryError,
    },
    #[error("send events are incoherent: {message}")]
    IncoherentEvents { message: String },
    #[error("send pacing clock failed")]
    Clock {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Preparation(error) => error.classification(),
            Self::InvalidRequest { .. } => Classification::new(
                "cli.send_limit",
                Kind::Usage,
                Some("use finite repetition, rate, and expansion limits for one send operation"),
            ),
            Self::Output { source } => source.classification(),
            Self::IncoherentEvents { .. } => Classification::new(
                "internal.send_event_coherence",
                Kind::Internal,
                Some("collect every send event once, from one send, in publication order"),
            ),
            Self::Clock { .. } => Classification::new(
                "io.send_clock",
                Kind::Io,
                Some("inspect the pacing clock and account for frames already transmitted"),
            ),
        }
    }

    fn context(&self) -> Option<Coordinate> {
        match self {
            Self::Preparation(error) => error.context(),
            Self::Output { source } => source.context(),
            Self::InvalidRequest { .. } | Self::IncoherentEvents { .. } | Self::Clock { .. } => {
                None
            }
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Preparation(error) => error.causes(),
            Self::Output { source } => source.as_causes(),
            error => packetcraftr_core::error::source_chain(error),
        }
    }
}
