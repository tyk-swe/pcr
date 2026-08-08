// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Consistent expert-finding construction and attribution.

use packetcraftr_packet::diagnostic::Severity as DiagnosticSeverity;

use super::{Finding, StreamRef};

pub(super) fn new(
    severity: DiagnosticSeverity,
    code: impl Into<String>,
    number: u64,
    stream: Option<StreamRef>,
    message: impl Into<String>,
) -> Finding {
    Finding {
        severity,
        code: code.into(),
        number,
        stream,
        message: message.into(),
    }
}
