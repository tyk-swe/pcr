// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::analysis::{application, provenance};
use crate::budget::{DeadlineExceeded, Interrupted};
use crate::error::{Classification, Classified};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("HTTP/2 collector cannot continue after a fatal analysis error")]
    Failed,
    #[error(transparent)]
    Application(#[from] application::Error),
    #[error(transparent)]
    Provenance(#[from] provenance::Error),
    #[error(transparent)]
    Analysis(#[from] crate::analysis::Error),
    #[error(transparent)]
    Wire(#[from] crate::protocol::application::http2::Error),
    #[error(transparent)]
    Http(#[from] crate::protocol::application::http::Error),
    #[error("application event output failed")]
    Output(#[source] crate::error::BoundaryError),
}
impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Failed => Classification::new(
                "internal.http2_failed",
                crate::error::Kind::Internal,
                Some("resolve the original error and create a new collector"),
            ),
            Self::Application(source) => source.classification(),
            Self::Provenance(source) => source.classification(),
            Self::Analysis(source) => source.classification(),
            Self::Wire(source) => source.classification(),
            Self::Http(source) => source.classification(),
            Self::Output(source) => source.classification(),
        }
    }
    fn causes(&self) -> Vec<String> {
        match self {
            Self::Analysis(source) => source.causes(),
            Self::Output(source) => source.as_causes(),
            error => crate::error::source_chain(error),
        }
    }
}
impl From<DeadlineExceeded> for Error {
    fn from(error: DeadlineExceeded) -> Self {
        Self::Analysis(error.into())
    }
}
impl From<Interrupted> for Error {
    fn from(interrupted: Interrupted) -> Self {
        Self::Analysis(interrupted.into_error())
    }
}
