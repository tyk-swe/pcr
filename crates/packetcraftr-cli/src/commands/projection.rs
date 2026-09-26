// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded selected-field output shared by read, dissect, and capture.

use crate::{
    errors::CliError,
    rendering::{StreamEncoder, bounded_json_len, emit_aggregate, write_raw},
};
use packetcraftr_cli::output::{
    self,
    contract::{Command, Format},
    projection::{Cell, Row},
};
use packetcraftr_core::{self as core, filter::Projection};
use std::io::{self, Write};

pub(super) struct Projector {
    pub(super) projection: Projection,
    command: Command,
    format: Format,
    remaining: usize,
    maximum: usize,
    rows: Vec<Row>,
    count: u64,
    header_written: bool,
}
impl Projector {
    pub(super) fn prepare(
        columns: &[String],
        maximum: usize,
        registry: &core::registry::Registry,
        command: Command,
        format: Format,
    ) -> Result<Option<Self>, CliError> {
        if columns.is_empty() {
            return Ok(None);
        }
        if !matches!(
            format,
            Format::Text | Format::Json | Format::Ndjson | Format::Csv | Format::Tsv
        ) {
            return Err(CliError::new(
                core::error::Kind::Usage,
                "--field requires text, JSON, NDJSON, CSV, or TSV output",
            ));
        }
        let projection = Projection::compile(columns.iter().map(String::as_str), registry)
            .map_err(CliError::classified)?;
        if command == Command::Capture && projection.requirements().stream_index {
            return Err(CliError::new(
                core::error::Kind::Usage,
                "capture --field cannot select stream indices; save the capture and use read --field",
            ));
        }
        Ok(Some(Self {
            projection,
            command,
            format,
            remaining: maximum,
            maximum,
            rows: Vec::new(),
            count: 0,
            header_written: false,
        }))
    }
    pub(super) fn remaining(&self) -> usize {
        self.remaining
    }
    fn limit(&self) -> CliError {
        CliError::classified(core::filter::ProjectionError::Limit {
            field: "projection_bytes",
            limit: self.maximum,
        })
    }
    fn charge(&mut self, bytes: usize) -> Result<(), CliError> {
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or_else(|| self.limit())?;
        Ok(())
    }
    fn header(&mut self) -> Result<(), CliError> {
        if self.header_written || !matches!(self.format, Format::Csv | Format::Tsv | Format::Text) {
            return Ok(());
        }
        let separator = if self.format == Format::Csv {
            b','
        } else {
            b'\t'
        };
        let mut buffer = BoundedBuffer::new(self.remaining);
        for (index, column) in self.projection.columns().iter().enumerate() {
            if index != 0 {
                buffer.write_all(&[separator]).map_err(|_| self.limit())?;
            }
            quoted(&mut buffer, column.as_bytes()).map_err(|_| self.limit())?;
        }
        buffer.write_all(b"\n").map_err(|_| self.limit())?;
        self.charge(buffer.bytes.len())?;
        write_raw(&buffer.bytes)?;
        self.header_written = true;
        Ok(())
    }
    pub(super) fn emit(
        &mut self,
        source_frame: u64,
        values: Vec<Option<core::field::FieldValue>>,
        stream: &StreamEncoder,
    ) -> Result<(), CliError> {
        let row = Row {
            source_frame: source_frame.try_into().map_err(CliError::classified)?,
            values,
        };
        self.header()?;
        if matches!(self.format, Format::Csv | Format::Tsv | Format::Text) {
            let separator = if self.format == Format::Csv {
                b','
            } else {
                b'\t'
            };
            let mut buffer = BoundedBuffer::new(self.remaining);
            for (index, value) in row.values.iter().enumerate() {
                if index != 0 {
                    buffer.write_all(&[separator]).map_err(|_| self.limit())?;
                }
                let mut cell =
                    BoundedBuffer::new(self.remaining.saturating_sub(buffer.bytes.len()));
                serde_json::to_writer(&mut cell, &value.as_ref().map(Cell))
                    .map_err(|_| self.limit())?;
                if self.format == Format::Text {
                    buffer.write_all(&cell.bytes).map_err(|_| self.limit())?;
                } else {
                    quoted(&mut buffer, &cell.bytes).map_err(|_| self.limit())?;
                }
            }
            buffer.write_all(b"\n").map_err(|_| self.limit())?;
            self.charge(buffer.bytes.len())?;
            write_raw(&buffer.bytes)?;
        } else if self.format == Format::Ndjson {
            let event = output::projection::RowEvent {
                columns: self.projection.columns(),
                row: &row,
            };
            let bytes = bounded_json_len(&event, self.remaining)
                .map_err(|error| error.into_cli_error(|| self.limit()))?;
            self.charge(bytes)?;
            stream.emit_data(
                output::projection::RowEvent {
                    columns: self.projection.columns(),
                    row: &row,
                },
                Vec::new(),
            )?;
        } else {
            let bytes = bounded_json_len(&row, self.remaining)
                .map_err(|error| error.into_cli_error(|| self.limit()))?;
            self.charge(bytes)?;
            self.rows.push(row);
        }
        self.count = self.count.checked_add(1).ok_or_else(|| self.limit())?;
        Ok(())
    }
    pub(super) fn finish(
        mut self,
        frames_read: u64,
        captured_bytes_read: u64,
        stream: &StreamEncoder,
    ) -> Result<(), CliError> {
        self.header()?;
        let summary = output::projection::Complete {
            columns: self.projection.columns().to_vec(),
            rows_written: self.count,
            frames_read,
            captured_bytes_read,
        };
        match self.format {
            Format::Json => emit_aggregate(
                self.command,
                output::projection::Report {
                    summary,
                    rows: self.rows,
                },
                Vec::new(),
            ),
            Format::Ndjson => stream.complete(summary, Vec::new()).map_err(Into::into),
            _ => Ok(()),
        }
    }
}

struct BoundedBuffer {
    bytes: Vec<u8>,
    remaining: usize,
}
impl BoundedBuffer {
    fn new(remaining: usize) -> Self {
        Self {
            bytes: Vec::new(),
            remaining,
        }
    }
}
impl Write for BoundedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("projection output limit"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn quoted(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    writer.write_all(b"\"")?;
    for part in bytes.split_inclusive(|byte| *byte == b'"') {
        writer.write_all(part)?;
        if part.last() == Some(&b'"') {
            writer.write_all(b"\"")?;
        }
    }
    writer.write_all(b"\"")
}

/// The one rejection for a command output format that requires `--field`
/// selections; each command applies it to the formats it declared projected.
pub(super) fn missing_fields_error() -> CliError {
    CliError::new(
        core::error::Kind::Usage,
        "this output format requires --field selections",
    )
}

pub(super) fn read(
    args: super::read::arguments::Args,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    crate::input::validate_capture_stream_limits(args.limits)?;
    let bounds = args.epoch.resolve()?;
    let registry = args.decode.registry()?;
    let mut projector = Projector::prepare(
        &args.fields,
        args.max_projection_bytes,
        &registry,
        Command::Read,
        format,
    )?
    .expect("field selection dispatch");
    let filter = args
        .filter
        .as_deref()
        .map(|source| {
            crate::filtering::compile(
                source,
                &registry,
                crate::filtering::Capabilities::stream_capable(),
            )
        })
        .transpose()?;
    let mut reader = crate::input::open_capture(&args.path, args.limits.reader)?;
    let mut frames = 0u64;
    let mut bytes = 0u64;
    if projector.projection.requirements().stream_index
        || filter
            .as_ref()
            .is_some_and(|filter| filter.requirements().stream_index)
    {
        let summary = core::analysis::run(
            &mut reader,
            registry,
            &core::analysis::Options {
                time_bounds: bounds,
                cancellation: Some(crate::cancellation::signal().clone()),
                limits: core::analysis::Limits {
                    max_frames: args.limits.max_frames,
                    max_bytes: args.limits.max_bytes,
                    max_frame_bytes: args.limits.reader.max_frame_bytes,
                    ..Default::default()
                },
                ..Default::default()
            },
            |record| {
                let kept = filter
                    .as_ref()
                    .map(|filter| record.matches(filter))
                    .transpose()
                    .map_err(|source| CliError::classified(source).into_boundary_error())?
                    .unwrap_or(true);
                if kept {
                    let values = record
                        .project(&projector.projection, projector.remaining())
                        .map_err(|source| CliError::classified(source).into_boundary_error())?;
                    projector
                        .emit(record.number, values, stream)
                        .map_err(CliError::into_boundary_error)?;
                }
                Ok(())
            },
        )
        .map_err(CliError::classified)?;
        frames = summary.frames_read;
        bytes = summary.bytes_read;
    } else {
        // The stream-capable filter takes the analysis branch above, so the
        // frame-at-a-time seam applies here.
        let decoder = crate::filtering::FrameDecoder::new(
            registry,
            filter,
            args.limits.reader.max_frame_bytes,
        );
        while let Some(frame) = reader.next_frame().map_err(CliError::classified)? {
            (frames, bytes) = core::analysis::pcap::Limits {
                max_frames: args.limits.max_frames,
                max_bytes: args.limits.max_bytes,
            }
            .advance(frames, bytes, frame.captured_length())
            .map_err(CliError::classified)?;
            if bounds.is_some_and(|bounds| !bounds.contains(frame.timestamp)) {
                continue;
            }
            let Some(decoded) = decoder.decode_selected(frames, &frame)? else {
                continue;
            };
            let context = core::filter::Context {
                decoded: &decoded,
                derived: &[],
                number: frames,
                tcp_stream: None,
                udp_stream: None,
            };
            let values = projector
                .projection
                .values(&context, projector.remaining())
                .map_err(CliError::classified)?;
            projector.emit(frames, values, stream)?;
        }
    }
    projector.finish(frames, bytes, stream)
}
