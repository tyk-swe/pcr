// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Stable failure taxonomy shared by the Rust API and command-line renderer.

#![forbid(unsafe_code)]

use serde::Serialize;

pub const EXIT_CLI: u8 = 2;
pub const EXIT_PACKET: u8 = 3;
pub const EXIT_CAPABILITY: u8 = 4;
pub const EXIT_IO: u8 = 5;
pub const EXIT_POLICY: u8 = 6;
pub const EXIT_INTERNAL: u8 = 70;

/// Top-level failure classes frozen by the v0.2 CLI contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    Cli,
    Packet,
    Capability,
    Io,
    Policy,
    Internal,
}

impl FailureKind {
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

    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Cli => EXIT_CLI,
            Self::Packet => EXIT_PACKET,
            Self::Capability => EXIT_CAPABILITY,
            Self::Io => EXIT_IO,
            Self::Policy => EXIT_POLICY,
            Self::Internal => EXIT_INTERNAL,
        }
    }
}

/// Deterministic machine code, CLI class, and operator guidance for an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct ErrorClassification {
    pub code: &'static str,
    pub kind: FailureKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<&'static str>,
}

impl ErrorClassification {
    pub const fn new(
        code: &'static str,
        kind: FailureKind,
        remediation: Option<&'static str>,
    ) -> Self {
        Self {
            code,
            kind,
            remediation,
        }
    }

    pub const fn exit_code(self) -> u8 {
        self.kind.exit_code()
    }
}

/// Implemented by public errors that cross a live-workflow or CLI boundary.
pub trait ClassifiedError {
    fn classification(&self) -> ErrorClassification;

    /// Ordered source diagnostics retained for structured renderers. The main
    /// error remains authoritative; implementations use this for dual
    /// operation/cleanup failures and typed adapter causes.
    fn causes(&self) -> Vec<String> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_failure_classes_have_distinct_documented_exit_codes() {
        assert_eq!(FailureKind::Cli.exit_code(), 2);
        assert_eq!(FailureKind::Packet.exit_code(), 3);
        assert_eq!(FailureKind::Capability.exit_code(), 4);
        assert_eq!(FailureKind::Io.exit_code(), 5);
        assert_eq!(FailureKind::Policy.exit_code(), 6);
        assert_eq!(FailureKind::Internal.exit_code(), 70);
    }
}
