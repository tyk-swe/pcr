// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Read, Write};

use super::error::Error;
use super::model::{Limits, RecordKind, RewriteReport};
use super::reader::Reader;

/// Rewrites a capture without changing its format or dropping source records.
///
/// The reader validates every bounded record before its original bytes are
/// written. Format conversion and packet filtering are intentionally outside
/// this contract because they cannot represent all source structure.
pub fn rewrite<R: Read, W: Write>(
    reader: &mut Reader<R>,
    mut output: W,
    limits: Limits,
) -> Result<(W, RewriteReport), Error> {
    let format = reader.format();
    output.write_all(reader.header().raw())?;

    let mut frames = 0_u64;
    let mut captured_bytes = 0_u64;
    let mut metadata_records = 0_u64;
    while let Some(record) = reader.next_record()? {
        if let Some(frame) = record.frame() {
            (frames, captured_bytes) =
                limits.advance(frames, captured_bytes, frame.captured_length())?;
        } else if matches!(record.kind, RecordKind::Metadata(_)) {
            metadata_records = metadata_records.saturating_add(1);
        }
        output.write_all(record.raw_bytes())?;
    }
    output.flush()?;
    Ok((
        output,
        RewriteReport {
            format,
            frames,
            captured_bytes,
            interfaces: reader.interfaces().len(),
            metadata_records,
        },
    ))
}
