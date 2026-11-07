// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output::envelope::Published;
use crate::output::{
    self,
    contract::{Command, Format},
    projection::{Cell, Row},
};
use crate::{
    errors::CliError,
    invocation::StreamEncoder,
    rendering::{bounded_json_len, emit_published, write_raw},
};
use packetcraftr_core::{
    self as core,
    filter::{Context, Projection, Requirements},
};
use std::io::{self, Write};

pub(crate) struct Projector {
    projection: Projection,
    command: Command,
    format: Format,
    remaining: usize,
    maximum: usize,
    rows: Vec<Row>,
    count: u64,
    header_written: bool,
}
impl Projector {
    pub(crate) fn prepare(
        columns: &[String],
        maximum: usize,
        registry: &core::registry::Registry,
        command: Command,
        format: Format,
    ) -> Result<Option<Self>, CliError> {
        if columns.is_empty() {
            return Ok(None);
        }
        if !matches!(format, Format::Text | Format::Json | Format::Ndjson) {
            return Err(CliError::new(
                core::error::Kind::Usage,
                "--field requires text, JSON, or NDJSON output",
            ));
        }
        let projection = Projection::compile(columns.iter().map(String::as_str), registry)
            .map_err(CliError::classified)?;
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
    pub(crate) fn requirements(&self) -> Requirements {
        self.projection.requirements()
    }
    fn limit(&self) -> CliError {
        CliError::classified(core::filter::Error::ProjectionLimit {
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
        if self.header_written || self.format != Format::Text {
            return Ok(());
        }
        let mut buffer = BoundedBuffer::new(self.remaining);
        for (index, column) in self.projection.columns().iter().enumerate() {
            if index != 0 {
                buffer.write_all(b"\t").map_err(|_| self.limit())?;
            }
            buffer
                .write_all(column.as_bytes())
                .map_err(|_| self.limit())?;
        }
        buffer.write_all(b"\n").map_err(|_| self.limit())?;
        self.charge(buffer.bytes.len())?;
        write_raw(&buffer.bytes)?;
        self.header_written = true;
        Ok(())
    }
    pub(crate) fn emit(
        &mut self,
        source_frame: u64,
        context: &Context<'_>,
        stream: &StreamEncoder,
    ) -> Result<(), CliError> {
        let values = self
            .projection
            .values(context, self.remaining)
            .map_err(CliError::classified)?;
        let row = Row::try_from((source_frame, values)).map_err(CliError::classified)?;
        self.header()?;
        if self.format == Format::Text {
            let mut buffer = BoundedBuffer::new(self.remaining);
            for (index, value) in row.values.iter().enumerate() {
                if index != 0 {
                    buffer.write_all(b"\t").map_err(|_| self.limit())?;
                }
                let mut cell =
                    BoundedBuffer::new(self.remaining.saturating_sub(buffer.bytes.len()));
                serde_json::to_writer(&mut cell, &value.as_ref().map(Cell))
                    .map_err(|_| self.limit())?;
                buffer.write_all(&cell.bytes).map_err(|_| self.limit())?;
            }
            buffer.write_all(b"\n").map_err(|_| self.limit())?;
            self.charge(buffer.bytes.len())?;
            write_raw(&buffer.bytes)?;
        } else if self.format == Format::Ndjson {
            let event = output::projection::RowEvent::from((&self.projection, &row));
            stream
                .emit_data_counted(event, Vec::new(), &mut self.remaining)
                .map_err(|error| match error {
                    output::stream::MeteredError::Limit => self.limit(),
                    output::stream::MeteredError::Encode(
                        error @ output::stream::EncodeError::RecordLimit { .. },
                    ) => {
                        // Preserve projection-limit precedence when both byte ceilings are exceeded
                        let event = output::projection::RowEvent::from((&self.projection, &row));
                        match bounded_json_len(
                            &event,
                            self.remaining,
                            serde_json::ser::CompactFormatter,
                        ) {
                            Ok(_) => CliError::from(error),
                            Err(error) => error.into_cli_error(|| self.limit()),
                        }
                    }
                    output::stream::MeteredError::Encode(error) => CliError::from(error),
                    output::stream::MeteredError::Serialize(error) => {
                        super::serialization_error(error)
                    }
                })?;
        } else {
            let bytes = bounded_json_len(&row, self.remaining, serde_json::ser::CompactFormatter)
                .map_err(|error| error.into_cli_error(|| self.limit()))?;
            self.charge(bytes)?;
            self.rows.push(row);
        }
        self.count = self.count.checked_add(1).ok_or_else(|| self.limit())?;
        Ok(())
    }
    pub(crate) fn finish(
        mut self,
        invocation: &crate::invocation::Invocation,
        frames_read: u64,
        captured_bytes_read: u64,
        stream: &StreamEncoder,
    ) -> Result<(), CliError> {
        self.header()?;
        let summary = output::projection::Complete::from((
            &self.projection,
            self.count,
            frames_read,
            captured_bytes_read,
        ));
        match self.format {
            Format::Json => emit_published(
                invocation,
                self.command,
                Published::new(
                    output::projection::Report::from((summary, self.rows)),
                    Vec::new(),
                ),
            ),
            Format::Ndjson => stream
                .complete_published(Published::new(summary, Vec::new()))
                .map_err(Into::into),
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

pub(crate) fn missing_fields_error() -> CliError {
    CliError::new(
        core::error::Kind::Usage,
        "this output format requires --field selections",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_limit_precedes_record_limit_only_when_the_payload_exceeds_both() {
        let record_limit = output::stream::MAX_RECORD_BYTES;
        let registry = core::protocol::builtin::registry();
        let frame = core::frame::Frame::new(
            None,
            core::frame::LinkType(147),
            vec![0; record_limit / 2 - 1],
        )
        .unwrap();
        let decoder =
            core::filter::FrameDecoder::new(registry.clone(), None, record_limit).unwrap();
        let decoded = decoder.decode(&frame).unwrap();
        let context = Context::frame(&decoded, 1);
        for (maximum, expected) in [
            (record_limit, core::error::Code::PolicyProjectionLimit),
            (record_limit * 2, core::error::Code::IoOutputRecordLimit),
        ] {
            let mut projector = Projector::prepare(
                &["raw.bytes".to_owned()],
                maximum,
                &registry,
                Command::Dissect,
                Format::Ndjson,
            )
            .unwrap()
            .unwrap();
            let stream = StreamEncoder::new(Command::Dissect, io::sink());
            let error = projector.emit(1, &context, &stream).unwrap_err();
            assert_eq!(error.classification.code, expected);
        }
    }
}
