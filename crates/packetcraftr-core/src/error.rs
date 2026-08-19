// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Stable failure taxonomy shared by the Rust API and command-line renderer.

#![forbid(unsafe_code)]

use serde::Serialize;

mod boundary;

pub use boundary::BoundaryError;

/// Stable domain coordinates associated with a classified failure.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Context {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_frame: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_index: Option<u64>,
}

impl Context {
    #[must_use]
    pub const fn source_frame(source_frame: u64) -> Self {
        Self {
            source_frame: Some(source_frame),
            probe_sequence: None,
            attempt: None,
            case_index: None,
        }
    }

    #[must_use]
    pub const fn probe_sequence(probe_sequence: u64) -> Self {
        Self {
            source_frame: None,
            probe_sequence: Some(probe_sequence),
            attempt: None,
            case_index: None,
        }
    }

    #[must_use]
    pub const fn attempt(attempt: u32) -> Self {
        Self {
            source_frame: None,
            probe_sequence: None,
            attempt: Some(attempt),
            case_index: None,
        }
    }

    #[must_use]
    pub const fn case_index(case_index: u64) -> Self {
        Self {
            source_frame: None,
            probe_sequence: None,
            attempt: None,
            case_index: Some(case_index),
        }
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.source_frame.is_none()
            && self.probe_sequence.is_none()
            && self.attempt.is_none()
            && self.case_index.is_none()
    }
}

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

    /// Stable domain coordinates for automation and partial-stream recovery.
    fn context(&self) -> Context {
        Context::default()
    }

    /// Ordered source diagnostics retained for structured renderers. The main
    /// error remains authoritative; implementations use this for dual
    /// operation/cleanup failures and typed adapter causes.
    fn causes(&self) -> Vec<String> {
        Vec::new()
    }
}
