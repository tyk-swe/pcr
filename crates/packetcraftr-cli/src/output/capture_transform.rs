// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::capture_file;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Dedup {
    pub path: String,
    #[serde(flatten)]
    pub selection: super::export::Selection,
    pub duplicates: u64,
}
impl From<(String, capture_file::DedupReport)> for Dedup {
    fn from((path, report): (String, capture_file::DedupReport)) -> Self {
        Self {
            path,
            selection: report.selection.into(),
            duplicates: report.duplicates,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Split {
    pub path: String,
    pub format: &'static str,
    pub files: usize,
    pub frames: u64,
    pub captured_bytes: u64,
    pub frames_per_file: Vec<u64>,
}
impl From<(String, capture_file::SplitReport)> for Split {
    fn from((path, report): (String, capture_file::SplitReport)) -> Self {
        Self {
            path,
            format: report.format.as_str(),
            files: report.files,
            frames: report.frames,
            captured_bytes: report.captured_bytes,
            frames_per_file: report.frames_per_file,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Shift {
    pub path: String,
    pub format: &'static str,
    pub frames: u64,
    pub captured_bytes: u64,
    pub shifted_packets: u64,
    pub shifted_statistics: u64,
}
impl From<(String, capture_file::ShiftReport)> for Shift {
    fn from((path, report): (String, capture_file::ShiftReport)) -> Self {
        Self {
            path,
            format: report.format.as_str(),
            frames: report.frames,
            captured_bytes: report.captured_bytes,
            shifted_packets: report.shifted_packets,
            shifted_statistics: report.shifted_statistics,
        }
    }
}
