// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error as ThisError;

use packetcraftr_core::error::{BoundaryError, Classification, Classified, Coordinate, Kind};
use packetcraftr_netio::Error as LiveIoError;

#[derive(Debug, ThisError)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Preparation(#[from] crate::Error),
    #[error("invalid exchange option {field}: {message}")]
    InvalidRequest {
        field: &'static str,
        message: String,
    },
    #[error("exchange packets selected different interfaces or link modes")]
    HeterogeneousRoute,
    /// Boxed: the only variant carrying two complete live-I/O failures.
    #[error("exchange failed and its capture shutdown also failed")]
    OperationAndCaptureShutdown {
        #[source]
        operation: Box<LiveIoError>,
        shutdown: Box<LiveIoError>,
    },
    #[error("exchange progressive output failed")]
    Output {
        #[source]
        source: Box<BoundaryError>,
    },
    #[error("exchange progressive output failed and capture shutdown also failed")]
    OutputAndCaptureShutdown {
        #[source]
        output: Box<BoundaryError>,
        shutdown: Box<LiveIoError>,
    },
    #[error("exchange events are incoherent: {message}")]
    IncoherentEvents { message: String },
}

impl From<LiveIoError> for Error {
    fn from(error: LiveIoError) -> Self {
        Self::Preparation(crate::Error::Io(error))
    }
}

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

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Preparation(error) => error.causes(),
            Self::Output { source } => source.as_causes(),
            Self::OperationAndCaptureShutdown {
                operation,
                shutdown,
            } => {
                let mut causes = vec![operation.to_string()];
                causes.extend(operation.causes());
                causes.push(shutdown.to_string());
                causes.extend(shutdown.causes());
                causes
            }
            Self::OutputAndCaptureShutdown { output, shutdown } => {
                let mut causes = output.as_causes();
                causes.push(shutdown.to_string());
                causes.extend(shutdown.causes());
                causes
            }
            error => packetcraftr_core::error::source_chain(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::*;

    fn shutdown() -> Box<LiveIoError> {
        Box::new(LiveIoError::UnresolvedLinkMode)
    }

    #[test]
    fn operation_and_shutdown_failure_expose_the_operation_as_a_source() {
        let operation = LiveIoError::PartialSend {
            expected: 60,
            actual: 42,
        };
        let error = Error::OperationAndCaptureShutdown {
            operation: Box::new(operation.clone()),
            shutdown: shutdown(),
        };

        let source = error.source().expect("the operation failure is the source");
        assert_eq!(source.to_string(), operation.to_string());
    }

    #[test]
    fn output_and_shutdown_failure_expose_the_output_failure_as_a_source() {
        let output = BoundaryError::new(
            "callback failed",
            Classification::new("io.fixture", Kind::Io, None),
            Vec::new(),
        );
        let error = Error::OutputAndCaptureShutdown {
            output: Box::new(output),
            shutdown: shutdown(),
        };

        let source = error.source().expect("the output failure is the source");
        assert_eq!(source.to_string(), "callback failed");
    }
}
