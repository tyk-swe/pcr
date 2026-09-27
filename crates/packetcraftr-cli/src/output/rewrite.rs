// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use serde::Serialize;

use packetcraftr_core::{capture_file::MapReport, transform};

use super::frame::ByteRange;

/// The bounded number of per-field changes one rewrite report carries.
/// Changes beyond it are folded into `changes_omitted`.
pub const MAX_REPORTED_CHANGES: usize = 4096;

published_enum! {
    /// Whether a rule asked for a field change or a derived field followed.
    pub enum ChangeOrigin from transform::ChangeOrigin {
        Requested => "requested",
        Derived => "derived",
    }
}

/// One applied field-edit byte-range change attributed to its source frame
/// and rule. `bytes` is the absolute changed range in the frame.
#[derive(Debug, Serialize)]
pub struct Change {
    pub frame: u64,
    pub rule: u64,
    pub field: String,
    pub layer: usize,
    pub range: ByteRange,
    pub old: u64,
    pub new: u64,
    pub origin: ChangeOrigin,
}

/// A field change at a one-based source frame, made by a zero-based rule.
impl From<(u64, u64, transform::FieldChange)> for Change {
    fn from((frame, rule, change): (u64, u64, transform::FieldChange)) -> Self {
        Self {
            frame,
            rule,
            field: change.field,
            layer: change.layer,
            range: change.range.into(),
            old: change.old,
            new: change.new,
            origin: change.origin.into(),
        }
    }
}

/// What the frame mapping read and changed.
#[derive(Debug, Serialize)]
pub struct Mapping {
    pub frames_read: u64,
    pub frames_changed: u64,
    pub captured_bytes_read: u64,
    pub captured_bytes_written: u64,
    pub interfaces: usize,
    pub source_metadata_records: u64,
}

impl From<MapReport> for Mapping {
    fn from(value: MapReport) -> Self {
        Self {
            frames_read: value.frames_read,
            frames_changed: value.frames_changed,
            captured_bytes_read: value.captured_bytes_read,
            captured_bytes_written: value.captured_bytes_written,
            interfaces: value.interfaces,
            source_metadata_records: value.source_metadata_records,
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct Report {
    pub path: String,
    pub rule_matches: Vec<u64>,
    #[serde(flatten)]
    pub capture: Mapping,
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

/// The destination path, the frames each rule matched, the mapping, whether
/// it was a dry run, and the changes retained and withheld.
impl From<(String, Vec<u64>, MapReport, bool, Vec<Change>, u64)> for Report {
    fn from(
        (path, rule_matches, capture, dry_run, changes, changes_omitted): (
            String,
            Vec<u64>,
            MapReport,
            bool,
            Vec<Change>,
            u64,
        ),
    ) -> Self {
        Self {
            path,
            rule_matches,
            capture: capture.into(),
            dry_run,
            changes,
            changes_omitted,
        }
    }
}

const fn is_false(value: &bool) -> bool {
    !*value
}
