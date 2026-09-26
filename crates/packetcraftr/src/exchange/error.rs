// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error as ThisError;

use packetcraftr_core::error::{BoundaryError, Classification, Classified, Coordinate, Kind};
use packetcraftr_netio::Error as LiveIoError;

/// Why an exchange stopped.
#[derive(Debug, ThisError)]
#[non_exhaustive]
pub enum Error {
    /// Preparation refused a packet, or a provider failed.
    #[error(transparent)]
    Preparation(#[from] crate::Error),
    /// The request asked for an unbounded window or impossible retention.
    #[error("invalid exchange option {field}: {message}")]
    InvalidRequest {
        field: &'static str,
        message: String,
    },
    #[error("exchange packets selected different interfaces or link modes")]
    HeterogeneousRoute,
    /// Boxed because this variant is the only one that carries two complete
    /// live-I/O failures, and no other failure should make room for them.
    #[error("{operation}; capture shutdown also failed: {shutdown}")]
    OperationAndCaptureShutdown {
        operation: Box<LiveIoError>,
        shutdown: Box<LiveIoError>,
    },
    /// The sink refused an event, or publishing it failed.
    #[error("exchange progressive output failed: {source}")]
    Output {
        #[source]
        source: Box<BoundaryError>,
    },
    #[error(
        "exchange progressive output failed: {output}; capture shutdown also failed: {shutdown}"
    )]
    OutputAndCaptureShutdown {
        output: Box<BoundaryError>,
        shutdown: Box<LiveIoError>,
    },
    /// A collector saw events that disagree with the report.
    #[error("exchange events are incoherent: {message}")]
    IncoherentEvents { message: String },
}

impl From<LiveIoError> for Error {
    fn from(error: LiveIoError) -> Self {
        Self::Preparation(crate::Error::Io(error))
    }
}

/// A `cli.*` code means "caller or request error": the request was not
/// something the exchange could run.
impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Preparation(error) => error.classification(),
            Self::InvalidRequest { .. } => Classification::new(
                "cli.exchange_limit",
                Kind::Usage,
                Some(
                    "use finite exchange timeout and retention limits no larger than the aggregate capture ceiling",
                ),
            ),
            Self::HeterogeneousRoute => Classification::new(
                "cli.heterogeneous_exchange_route",
                Kind::Usage,
                Some("split the exchange so every packet uses the same interface and link mode"),
            ),
            Self::OperationAndCaptureShutdown { operation, .. } => operation.classification(),
            Self::Output { source } => source.classification(),
            Self::OutputAndCaptureShutdown { output, .. } => output.classification(),
            Self::IncoherentEvents { .. } => Classification::new(
                "internal.exchange_event_coherence",
                Kind::Internal,
                Some("collect every exchange event once in publication order"),
            ),
        }
    }

    fn context(&self) -> Option<Coordinate> {
        match self {
            Self::Preparation(error) => error.context(),
            Self::OperationAndCaptureShutdown { operation, .. } => operation.context(),
            Self::Output { source } => source.context(),
            Self::OutputAndCaptureShutdown { output, .. } => output.context(),
            Self::InvalidRequest { .. }
            | Self::HeterogeneousRoute
            | Self::IncoherentEvents { .. } => None,
        }
    }

    /// Walks retained sources, delegating to the wrapped preparation failure
    /// and to [`BoundaryError`] snapshots. Paired operation and cleanup
    /// failures combine both chains.
    fn causes(&self) -> Vec<String> {
        match self {
            Self::Preparation(error) => error.causes(),
            Self::Output { source } => source.causes(),
            Self::OperationAndCaptureShutdown {
                operation,
                shutdown,
            } => vec![operation.to_string(), shutdown.to_string()],
            Self::OutputAndCaptureShutdown { output, shutdown } => {
                let mut causes = output.causes();
                if causes.is_empty() {
                    causes.push(output.to_string());
                }
                causes.push(shutdown.to_string());
                causes
            }
            error => packetcraftr_core::error::source_chain(error),
        }
    }
}
