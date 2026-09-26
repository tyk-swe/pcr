// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use serde::Serialize;

/// The bounded number of per-field changes one rewrite report carries.
/// Changes beyond it are folded into `changes_omitted`.
pub const MAX_REPORTED_CHANGES: usize = 4096;

/// One applied field-edit byte-range change attributed to its source frame
/// and rule. `bytes` is the absolute changed range in the frame.
#[derive(Debug, Serialize)]
pub struct Change {
    pub frame: u64,
    pub rule: u64,
    #[serde(flatten)]
    pub change: packetcraftr_core::transform::FieldChange,
}

#[derive(Debug, serde::Serialize)]
pub struct Report {
    pub path: String,
    pub rule_matches: Vec<u64>,
    #[serde(flatten)]
    pub capture: packetcraftr_core::capture_file::MapReport,
    /// Present when `--dry-run` reported without publishing the destination.
    #[serde(skip_serializing_if = "is_false")]
    pub dry_run: bool,
    /// Per-field changes in application order; bounded by
    /// [`MAX_REPORTED_CHANGES`].
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<Change>,
    /// Changes withheld because the report reached [`MAX_REPORTED_CHANGES`].
    #[serde(skip_serializing_if = "super::envelope::is_zero")]
    pub changes_omitted: u64,
}

const fn is_false(value: &bool) -> bool {
    !*value
}
