// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured diagnostics produced by build and decode operations.

use std::fmt;

use serde::{Deserialize, Serialize};

pub const IPV4_CHECKSUM: &str = "decode.ipv4_checksum";
pub const TCP_CHECKSUM: &str = "decode.tcp_checksum";
pub const UDP_CHECKSUM: &str = "decode.udp_checksum";
pub const SCTP_CHECKSUM: &str = "decode.sctp_checksum";
pub const ICMPV4_CHECKSUM: &str = "decode.icmpv4_checksum";
pub const ICMPV6_CHECKSUM: &str = "decode.icmpv6_checksum";
pub const IGMP_CHECKSUM: &str = "decode.igmp_checksum";
pub const GRE_CHECKSUM: &str = "decode.gre_checksum";

/// Integrity rejection matches these codes exactly; no other code counts as a
/// checksum failure.
pub const CHECKSUM_FAILURE_CODES: &[&str] = &[
    IPV4_CHECKSUM,
    TCP_CHECKSUM,
    UDP_CHECKSUM,
    SCTP_CHECKSUM,
    ICMPV4_CHECKSUM,
    ICMPV6_CHECKSUM,
    IGMP_CHECKSUM,
    GRE_CHECKSUM,
];

/// Diagnostic weight, ordered from least to most severe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    /// The serialized spelling, so text and machine output never disagree.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A machine-readable build, decode, session, or policy finding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    pub code: String,
    pub severity: Severity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

impl Diagnostic {
    pub fn info(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(Severity::Info, code, message)
    }

    pub fn warning(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(Severity::Warning, code, message)
    }

    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(Severity::Error, code, message)
    }

    fn new(severity: Severity, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            severity,
            message: message.into(),
            layer: None,
            field: None,
        }
    }

    #[must_use]
    pub fn at_layer(mut self, layer: usize) -> Self {
        self.layer = Some(layer);
        self
    }

    #[must_use]
    pub fn at_field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }

    /// True only for a built-in checksum verification failure.
    #[must_use]
    pub fn is_checksum_failure(&self) -> bool {
        CHECKSUM_FAILURE_CODES.contains(&self.code.as_str())
    }
}

/// Appends `diagnostic` unless one with the same code is already present.
pub fn push_once(diagnostics: &mut Vec<Diagnostic>, diagnostic: Diagnostic) {
    if !diagnostics
        .iter()
        .any(|existing| existing.code == diagnostic.code)
    {
        diagnostics.push(diagnostic);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_text_matches_its_serde_spelling_and_orders_by_weight() {
        for severity in [Severity::Info, Severity::Warning, Severity::Error] {
            let serialized =
                serde_json::to_string(&severity).expect("severity serializes as a string");
            assert_eq!(serialized, format!("\"{}\"", severity.as_str()));
            assert_eq!(severity.to_string(), severity.as_str());
        }
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
    }

    #[test]
    fn unrelated_diagnostic_codes_never_classify_as_integrity_failures() {
        for code in [
            "decode.tcp_checksum_hint",
            "tcp.checksum",
            "vendor.checksum_mismatch",
            "decode.udp_length",
        ] {
            assert!(!Diagnostic::info(code, "unrelated").is_checksum_failure());
            assert!(!Diagnostic::warning(code, "unrelated").is_checksum_failure());
            assert!(!Diagnostic::error(code, "unrelated").is_checksum_failure());
        }
    }
}
