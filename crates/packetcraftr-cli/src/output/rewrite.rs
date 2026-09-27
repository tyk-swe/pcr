// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use serde::Serialize;

use packetcraftr_core::{capture_file::MapReport, transform};

use super::frame::ByteRange;

pub const MAX_REPORTED_CHANGES: usize = 4096;

published_enum! {
    pub enum ChangeOrigin from transform::ChangeOrigin {
        Requested => "requested",
        Derived => "derived",
    }
}

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
    #[serde(skip_serializing_if = "is_false")]
    pub dry_run: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<Change>,
    #[serde(skip_serializing_if = "super::envelope::is_zero")]
    pub changes_omitted: u64,
}

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
