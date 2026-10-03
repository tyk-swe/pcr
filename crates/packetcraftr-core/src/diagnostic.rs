// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::{Deserialize, Serialize};

pub const IPV4_CHECKSUM: &str = "decode.ipv4_checksum";
pub const TCP_CHECKSUM: &str = "decode.tcp_checksum";
pub const UDP_CHECKSUM: &str = "decode.udp_checksum";
pub const SCTP_CHECKSUM: &str = "decode.sctp_checksum";
pub const ICMPV4_CHECKSUM: &str = "decode.icmpv4_checksum";
pub const ICMPV6_CHECKSUM: &str = "decode.icmpv6_checksum";
pub const IGMP_CHECKSUM: &str = "decode.igmp_checksum";
pub const VRRP_CHECKSUM: &str = "decode.vrrp_checksum";
pub const GRE_CHECKSUM: &str = "decode.gre_checksum";

pub const CHECKSUM_FAILURE_CODES: &[&str] = &[
    IPV4_CHECKSUM,
    TCP_CHECKSUM,
    UDP_CHECKSUM,
    SCTP_CHECKSUM,
    ICMPV4_CHECKSUM,
    ICMPV6_CHECKSUM,
    IGMP_CHECKSUM,
    VRRP_CHECKSUM,
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
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

display_via_as_str!(Severity);

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    pub code: &'static str,
    pub severity: Severity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<&'static str>,
}

impl Diagnostic {
    pub fn info(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(Severity::Info, code, message)
    }

    pub fn warning(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(Severity::Warning, code, message)
    }

    pub fn error(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(Severity::Error, code, message)
    }

    fn new(severity: Severity, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
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
    pub fn at_field(mut self, field: &'static str) -> Self {
        self.field = Some(field);
        self
    }

    #[must_use]
    pub fn is_checksum_failure(&self) -> bool {
        CHECKSUM_FAILURE_CODES.contains(&self.code)
    }
}

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
