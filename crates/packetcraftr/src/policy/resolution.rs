// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Failures from resolving and authorizing one live target.

use packetcraftr_core::error::{Classification, Classified, Coordinate};

/// Target resolution and policy authorization failures remain distinct at
/// the policy boundary instead of making target errors contain policy errors.
#[derive(Debug)]
#[non_exhaustive]
pub enum ResolutionError {
    Target(crate::target::Error),
    Policy(super::Error),
}

impl std::fmt::Display for ResolutionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Target(source) => source.fmt(formatter),
            Self::Policy(source) => source.fmt(formatter),
        }
    }
}

impl std::error::Error for ResolutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Target(source) => source.source(),
            Self::Policy(_) => None,
        }
    }
}

impl From<crate::target::Error> for ResolutionError {
    fn from(source: crate::target::Error) -> Self {
        Self::Target(source)
    }
}

impl From<super::Error> for ResolutionError {
    fn from(source: super::Error) -> Self {
        Self::Policy(source)
    }
}

impl Classified for ResolutionError {
    fn classification(&self) -> Classification {
        match self {
            Self::Target(source) => source.classification(),
            Self::Policy(source) => source.classification(),
        }
    }

    fn context(&self) -> Option<Coordinate> {
        match self {
            Self::Target(source) => source.context(),
            Self::Policy(source) => source.context(),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Target(source) => source.causes(),
            Self::Policy(source) => source.causes(),
        }
    }
}
