// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error as ThisError;

use packetcraftr_core::error::{BoundaryError, Classification, Classified, Coordinate, Kind};

/// Why a send stopped.
#[derive(Debug, ThisError)]
#[non_exhaustive]
pub enum Error {
    /// Preparation refused a packet, or a provider failed.
    #[error(transparent)]
    Preparation(#[from] crate::Error),
    /// The request asked for unbounded or impossible work.
    #[error("invalid send option {field}: {message}")]
    InvalidRequest {
        field: &'static str,
        message: String,
    },
    /// The sink refused an event, or publishing it failed.
    #[error("send progressive output failed: {source}")]
    Output {
        #[source]
        source: BoundaryError,
    },
    /// A collector saw events that disagree with the report.
    #[error("send events are incoherent: {message}")]
    IncoherentEvents { message: String },
    /// The pacing clock failed while the send could still continue.
    #[error("send pacing clock failed: {source}")]
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

    /// Delegates to the wrapped preparation failure and to the sink's
    /// [`BoundaryError`] snapshot, which keeps its own causes.
    fn causes(&self) -> Vec<String> {
        match self {
            Self::Preparation(error) => error.causes(),
            Self::Output { source } => source.causes(),
            error => packetcraftr_core::error::source_chain(error),
        }
    }
}
