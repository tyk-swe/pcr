// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Packet document convert output.

use serde::Serialize;

/// One failed conversion entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FailedEntry {
    pub path: String,
    pub error: String,
}

/// Aggregate result of converting packet documents to v2 format.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Result {
    pub converted: Vec<String>,
    pub unchanged: Vec<String>,
    pub failed: Vec<FailedEntry>,
}
