// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use packetcraftr_core::capture_file::MergeReport;

#[derive(Debug, Serialize)]
pub struct Interface {
    pub source: usize,
    pub source_name: String,
    pub section: Option<u64>,
    pub local_interface: Option<u32>,
    pub global_interface: u32,
    pub output_interface: u32,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub path: String,
    pub frames: u64,
    pub captured_bytes: u64,
    pub source_frames: Vec<u64>,
    pub interfaces: Vec<Interface>,
    pub source_metadata_records: u64,
}
/// The destination path and what the merge wrote there.
impl From<(String, MergeReport)> for Report {
    fn from((path, report): (String, MergeReport)) -> Self {
        Self {
            path,
            frames: report.frames,
            captured_bytes: report.captured_bytes,
            source_frames: report.source_frames,
            source_metadata_records: report.source_metadata_records,
            interfaces: report
                .interfaces
                .into_iter()
                .map(|i| Interface {
                    source: i.source,
                    source_name: i.source_name,
                    section: i.section,
                    local_interface: i.local_interface,
                    global_interface: i.global_interface,
                    output_interface: i.output_interface,
                })
                .collect(),
        }
    }
}
