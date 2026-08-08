// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Stable failure taxonomy shared by the Rust API and command-line renderer.

#![forbid(unsafe_code)]

use serde::Serialize;

mod boundary;

pub use boundary::BoundaryError;

/// Top-level failure classes shared by API boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Cli,
    Packet,
    Capability,
    Io,
    Policy,
    Internal,
}

impl Kind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Packet => "packet",
            Self::Capability => "capability",
            Self::Io => "io",
            Self::Policy => "policy",
            Self::Internal => "internal",
        }
    }
}

/// Deterministic machine code, CLI class, and operator guidance for an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub struct Classification {
    pub code: &'static str,
    pub kind: Kind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<&'static str>,
}

impl Classification {
    pub const fn new(code: &'static str, kind: Kind, remediation: Option<&'static str>) -> Self {
        Self {
            code,
            kind,
            remediation,
        }
    }
}

/// Implemented by public errors that cross a live-workflow or CLI boundary.
pub trait Classified {
    fn classification(&self) -> Classification;

    /// Ordered source diagnostics retained for structured renderers. The main
    /// error remains authoritative; implementations use this for dual
    /// operation/cleanup failures and typed adapter causes.
    fn causes(&self) -> Vec<String> {
        Vec::new()
    }
}
