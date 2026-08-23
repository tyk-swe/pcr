// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Stable failure taxonomy shared by the Rust API and command-line renderer.

#![forbid(unsafe_code)]

use std::fmt;

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

impl fmt::Display for Context {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts = [
            self.source_frame.map(|n| format!("frame {n}")),
            self.probe_sequence.map(|n| format!("probe {n}")),
            self.attempt.map(|n| format!("attempt {n}")),
            self.case_index.map(|n| format!("case {n}")),
        ];
        let parts = parts.into_iter().flatten().collect::<Vec<_>>();
        if parts.is_empty() {
            return formatter.write_str("unknown position");
        }
        formatter.write_str(&parts.join(", "))
    }
}

const fn starts_with(bytes: &[u8], prefix: &[u8]) -> bool {
    if bytes.len() < prefix.len() {
        return false;
    }
    let mut index = 0;
    while index < prefix.len() {
        if bytes[index] != prefix[index] {
            return false;
        }
        index += 1;
    }
    true
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
    pub const fn from_code(code: &str) -> Option<Kind> {
        let bytes = code.as_bytes();
        if starts_with(bytes, b"cli.") {
            Some(Self::Cli)
        } else if starts_with(bytes, b"packet.") {
            Some(Self::Packet)
        } else if starts_with(bytes, b"capability.") {
            Some(Self::Capability)
        } else if starts_with(bytes, b"io.") {
            Some(Self::Io)
        } else if starts_with(bytes, b"policy.") {
            Some(Self::Policy)
        } else if starts_with(bytes, b"internal.") {
            Some(Self::Internal)
        } else {
            None
        }
    }

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
    /// Creates a classification whose kind is derived from the code prefix.
    ///
    /// # Panics
    ///
    /// Panics if `code` does not start with a recognized [`Kind`] prefix.
    pub const fn new(code: &'static str, remediation: Option<&'static str>) -> Self {
        let kind = match Kind::from_code(code) {
            Some(kind) => kind,
            None => panic!("classification code must start with a Kind prefix"),
        };
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

#[cfg(test)]
mod tests {
    use super::Context;

    #[test]
    fn context_displays_coordinates_in_field_order() {
        let context = Context {
            source_frame: Some(3),
            probe_sequence: Some(5),
            attempt: Some(7),
            case_index: Some(9),
        };
        assert_eq!(context.to_string(), "frame 3, probe 5, attempt 7, case 9");
        assert_eq!(Context::default().to_string(), "unknown position");
    }
}
