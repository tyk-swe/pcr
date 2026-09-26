// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Read, Write};

use super::{
    Error, Limits, MetadataBlockKind, Reader, RecordKind, RewriteReport, SelectionError,
    SelectionReport,
};
use crate::{error::BoundaryError, frame::Frame};

/// Rewrites a capture without changing its format or dropping source records.
/// Every validated source record, including section lengths, is copied verbatim.
pub fn rewrite<R: Read, W: Write>(
    reader: &mut Reader<R>,
    output: W,
    limits: Limits,
) -> Result<(W, RewriteReport), Error> {
    let (output, report) =
        copy_records(reader, output, limits, false, |_, _| Ok::<_, Error>(true))?;
    Ok((
        output,
        RewriteReport {
            format: report.format,
            frames: report.frames_read,
            captured_bytes: report.captured_bytes_read,
            interfaces: report.interfaces,
            metadata_records: report.metadata_records,
        },
    ))
}

/// Copies selected packet records and all metadata in the source format.
///
/// The predicate receives the original one-based frame number. Every input
/// packet consumes the limits, even when rejected. Selected packets and metadata
/// are copied verbatim except PCAPNG section lengths, which become unknown.
/// Retained interface statistics describe the source capture, not the selection.
/// No related packets or fragments are automatically included.
///
/// An empty selection succeeds. Errors may leave a partial capture in `output`;
/// input validation continues through EOF and the output is flushed on success.
pub fn select<R: Read, W: Write, F>(
    reader: &mut Reader<R>,
    output: W,
    limits: Limits,
    mut predicate: F,
) -> Result<(W, SelectionReport), SelectionError>
where
    F: FnMut(u64, &Frame) -> Result<bool, BoundaryError>,
{
    copy_records(reader, output, limits, true, |number, frame| {
        predicate(number, frame).map_err(|source| SelectionError::Predicate { number, source })
    })
}

fn copy_records<R: Read, W: Write, E: From<Error>>(
    reader: &mut Reader<R>,
    mut output: W,
    limits: Limits,
    selecting: bool,
    mut predicate: impl FnMut(u64, &Frame) -> Result<bool, E>,
) -> Result<(W, SelectionReport), E> {
    let mut report = SelectionReport {
        format: reader.format(),
        frames_read: 0,
        frames_selected: 0,
        captured_bytes_read: 0,
        captured_bytes_selected: 0,
        interfaces: 0,
        metadata_records: 0,
    };
    if selecting && reader.format() == super::Format::PcapNg {
        super::pcapng::write_selected_section(&mut output, reader.header().raw())?;
    } else {
        output
            .write_all(reader.header().raw())
            .map_err(Error::from)?;
    }
    while let Some(record) = reader.next_record()? {
        if let Some(frame) = record.frame.as_ref() {
            (report.frames_read, report.captured_bytes_read) = limits.advance(
                report.frames_read,
                report.captured_bytes_read,
                frame.captured_length(),
            )?;
            if !predicate(report.frames_read, frame)? {
                continue;
            }
            // Selected totals cannot exceed the already checked input totals.
            report.frames_selected = report.frames_selected.saturating_add(1);
            report.captured_bytes_selected = report
                .captured_bytes_selected
                .saturating_add(u64::from(frame.captured_length()));
        } else {
            report.metadata_records = report.metadata_records.saturating_add(1);
        }
        if selecting
            && matches!(
                record.kind,
                RecordKind::Metadata(MetadataBlockKind::Section(_))
            )
        {
            super::pcapng::write_selected_section(&mut output, record.raw_bytes())?;
        } else {
            output.write_all(record.raw_bytes()).map_err(Error::from)?;
        }
    }
    output.flush().map_err(Error::from)?;
    report.interfaces = reader.interfaces().len();
    Ok((output, report))
}
