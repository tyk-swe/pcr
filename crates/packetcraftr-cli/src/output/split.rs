// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The `split` result: detected container, per-part fixed names, and the
//! source/decoded/encoded byte accounting of one bounded split.

use serde::Serialize;

use packetcraftr_core::capture_file::split;

use super::contract::Error;

/// One generated capture part: its fixed basename, source frame range, and
/// captured/decoded/encoded byte counts.
#[derive(Debug, Serialize)]
pub struct Part {
    pub index: u64,
    pub file: String,
    pub first_frame: Option<u64>,
    pub last_frame: Option<u64>,
    pub frames: u64,
    pub captured_bytes: u64,
    pub decoded_bytes: u64,
    pub encoded_bytes: u64,
}

/// The saved-file facts one sealed part produced: the fixed basename under
/// the destination directory and the exact encoded length the closed file
/// measured.
#[derive(Debug)]
pub struct File {
    /// The one-based part index this file holds; conversion refuses files
    /// whose index sequence does not match the plan's parts.
    pub index: u64,
    pub name: String,
    pub encoded_bytes: u64,
}

/// The complete split result published by every output format.
#[derive(Debug, Serialize)]
pub struct Report {
    pub format: &'static str,
    pub compression: &'static str,
    pub directory: String,
    pub frames_per_file: u64,
    pub frames_read: u64,
    pub captured_bytes_read: u64,
    pub metadata_records: u64,
    pub metadata_bytes: u64,
    pub decoded_bytes_written: u64,
    pub encoded_bytes_written: u64,
    pub files: Vec<Part>,
}

/// The destination directory, compression, and core report; `files[i]` is the
/// sealed saved file holding `report.parts[i]`.
impl TryFrom<(String, &'static str, split::Report, Vec<File>)> for Report {
    type Error = Error;

    fn try_from(
        (directory, compression, report, files): (String, &'static str, split::Report, Vec<File>),
    ) -> Result<Self, Error> {
        if files.is_empty() || files.len() != report.parts.len() {
            return Err(Error::Unpublished {
                value: "split part file list",
            });
        }
        let mut encoded_bytes_written = 0_u64;
        let mut parts = Vec::with_capacity(report.parts.len());
        for (part, file) in report.parts.iter().zip(files) {
            if file.index != part.index {
                return Err(Error::Unpublished {
                    value: "split part index",
                });
            }
            encoded_bytes_written = encoded_bytes_written
                .checked_add(file.encoded_bytes)
                .ok_or(Error::Unpublished {
                    value: "split encoded-byte total",
                })?;
            parts.push(Part {
                index: part.index,
                file: file.name,
                first_frame: part.first_frame,
                last_frame: part.last_frame,
                frames: part.frames,
                captured_bytes: part.captured_bytes,
                decoded_bytes: part.decoded_bytes,
                encoded_bytes: file.encoded_bytes,
            });
        }
        Ok(Self {
            format: report.format.as_str(),
            compression,
            directory,
            frames_per_file: report.frames_per_file,
            frames_read: report.frames_read,
            captured_bytes_read: report.captured_bytes_read,
            metadata_records: report.metadata_records,
            metadata_bytes: report.metadata_bytes,
            decoded_bytes_written: report.decoded_bytes_written,
            encoded_bytes_written,
            files: parts,
        })
    }
}
