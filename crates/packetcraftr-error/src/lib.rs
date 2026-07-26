// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Stable failure taxonomy shared by the Rust API and command-line renderer.

#![forbid(unsafe_code)]

use serde::Serialize;

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

/// Stable semantic category for programmatic recovery and policy decisions.
///
/// Unlike [`Kind`], which controls the CLI exit-code family, this
/// category distinguishes failures that share an exit code but require
/// different handling (for example an I/O timeout versus cleanup failure).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Validation,
    Capability,
    Policy,
    Timeout,
    Io,
    Cleanup,
    Invariant,
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

/// Deterministic machine code, CLI class, semantic category, and operator
/// guidance for an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub struct Classification {
    pub code: &'static str,
    pub kind: Kind,
    pub category: Category,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<&'static str>,
}

impl Classification {
    pub const fn new(code: &'static str, kind: Kind, remediation: Option<&'static str>) -> Self {
        Self {
            code,
            kind,
            category: match kind {
                Kind::Cli | Kind::Packet => Category::Validation,
                Kind::Capability => Category::Capability,
                Kind::Io => Category::Io,
                Kind::Policy => Category::Policy,
                Kind::Internal => Category::Invariant,
            },
            remediation,
        }
    }

    /// Overrides the default semantic category while preserving the stable
    /// machine code and CLI exit-code family.
    #[must_use]
    pub const fn with_category(mut self, category: Category) -> Self {
        self.category = category;
        self
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_kind_strings_are_stable() {
        assert_eq!(Kind::Cli.as_str(), "cli");
        assert_eq!(Kind::Packet.as_str(), "packet");
        assert_eq!(Kind::Capability.as_str(), "capability");
        assert_eq!(Kind::Io.as_str(), "io");
        assert_eq!(Kind::Policy.as_str(), "policy");
        assert_eq!(Kind::Internal.as_str(), "internal");
    }

    #[test]
    fn classifications_separate_exit_family_from_recovery_category() {
        let timeout =
            Classification::new("io.timeout", Kind::Io, None).with_category(Category::Timeout);
        assert_eq!(timeout.kind, Kind::Io);
        assert_eq!(timeout.category, Category::Timeout);
        assert_eq!(
            Classification::new("packet.invalid", Kind::Packet, None).category,
            Category::Validation
        );
        assert_eq!(
            Classification::new("internal.invariant", Kind::Internal, None).category,
            Category::Invariant
        );
    }
}
