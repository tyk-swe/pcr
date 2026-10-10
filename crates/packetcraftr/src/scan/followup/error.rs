// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::error::{BoundaryError, Classification, Classified, Coordinate, Kind};

use crate::StatsOverflow;

/// A follow-up stage failed; each variant keeps the failing stage's own error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Scan(#[from] crate::scan::Error),
    #[error(transparent)]
    Trace(#[from] crate::traceroute::Error),
    #[error(transparent)]
    Dns(#[from] crate::dns::Error),
    #[error(transparent)]
    Neighbor(Box<crate::neighbor::Error>),
    #[error(transparent)]
    Target(#[from] crate::target::Error),
    #[error(transparent)]
    Boundary(#[from] BoundaryError),
    #[error(transparent)]
    StatsOverflow(#[from] StatsOverflow),
}

impl From<crate::neighbor::Error> for Error {
    fn from(error: crate::neighbor::Error) -> Self {
        Self::Neighbor(Box::new(error))
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Scan(source) => source.classification(),
            Self::Trace(source) => source.classification(),
            Self::Dns(source) => source.classification(),
            Self::Neighbor(source) => source.classification(),
            Self::Target(source) => source.classification(),
            Self::Boundary(source) => source.classification(),
            Self::StatsOverflow(_) => Classification::new("internal.error", Kind::Internal, None),
        }
    }

    fn context(&self) -> Option<Coordinate> {
        match self {
            Self::Scan(source) => source.context(),
            Self::Trace(source) => source.context(),
            Self::Dns(source) => source.context(),
            Self::Neighbor(source) => source.context(),
            Self::Target(source) => source.context(),
            Self::Boundary(source) => source.context(),
            Self::StatsOverflow(_) => None,
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Scan(source) => source.causes(),
            Self::Trace(source) => source.causes(),
            Self::Dns(source) => source.causes(),
            Self::Neighbor(source) => source.causes(),
            Self::Target(source) => source.causes(),
            Self::Boundary(source) => source.causes(),
            Self::StatsOverflow(source) => packetcraftr_core::error::source_chain(source),
        }
    }
}
