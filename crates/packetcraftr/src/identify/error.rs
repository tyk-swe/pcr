// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::error::{Classification, Classified, Kind};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid service identification request: {reason}")]
    Request { reason: String },
    #[error(transparent)]
    Corpus(#[from] packetcraftr_core::document::service_probes::Error),
    #[error(transparent)]
    Exclusions(#[from] packetcraftr_core::document::service_exclusions::Error),
    #[error(transparent)]
    Policy(#[from] crate::policy::Error),
    #[error(transparent)]
    Cancelled(#[from] packetcraftr_core::budget::Cancelled),
    #[error("service identification provider violated its bounded exchange contract: {reason}")]
    Provider { reason: String },
}

impl Error {
    pub(super) fn request(reason: impl Into<String>) -> Self {
        Self::Request {
            reason: reason.into(),
        }
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Corpus(source) => source.classification(),
            Self::Exclusions(source) => source.classification(),
            Self::Policy(source) => source.classification(),
            Self::Cancelled(source) => source.classification(),
            Self::Request { .. } => Classification::new(
                "cli.identify_request",
                Kind::Usage,
                Some("select numeric TCP/UDP endpoints and finite identification limits"),
            ),
            Self::Provider { .. } => Classification::new(
                "internal.identify_provider",
                Kind::Internal,
                Some("correct the provider's endpoint and byte accounting"),
            ),
        }
    }
}
