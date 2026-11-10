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
    publication::{BoundedJsonError, Limited, bounded_json_len, emit_published, write_raw},
};
use packetcraftr_core::{
    self as core,
    filter::{Context, Projection, Requirements},
};

pub(crate) struct Projector {
    projection: Projection,
    command: Command,
    sink: Sink,
    budget: Budget,
    count: u64,
}

enum Sink {
    Text { header_written: bool },
    Json { rows: Vec<Row> },
    Ndjson,
}

struct Budget {
    remaining: usize,
    maximum: usize,
}

impl Budget {
    fn limit(&self) -> CliError {
        CliError::classified(core::filter::Error::ProjectionLimit {
            field: "projection_bytes",
            limit: self.maximum,
        })
    }

    fn error(&self, error: BoundedJsonError) -> CliError {
        error.into_cli_error(|| self.limit())
    }

    fn write_line<C>(
        &mut self,
        cells: impl IntoIterator<Item = C>,
        push: impl Fn(&mut Limited<Vec<u8>>, C) -> Result<(), BoundedJsonError>,
    ) -> Result<(), CliError> {
        let mut line = Limited::buffer(self.remaining);
        cells
            .into_iter()
            .enumerate()
            .try_for_each(|(index, cell)| {
                if index != 0 {
                    line.push(b"\t")?;
                }
                push(&mut line, cell)
            })
            .and_then(|()| line.push(b"\n"))
            .map_err(|error| self.error(error))?;
        let (bytes, remaining) = line.finish();
        self.remaining = remaining;
        write_raw(&bytes)
    }

    fn write_header(
        &mut self,
        header_written: &mut bool,
        projection: &Projection,
    ) -> Result<(), CliError> {
        if *header_written {
            return Ok(());
        }
        self.write_line(projection.columns(), |line, column| {
            line.push(column.as_bytes())
        })?;
        *header_written = true;
        Ok(())
    }
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
        let sink = match format {
            Format::Text => Sink::Text {
                header_written: false,
            },
            Format::Json => Sink::Json { rows: Vec::new() },
            Format::Ndjson => Sink::Ndjson,
            Format::Csv | Format::Hex | Format::Raw | Format::Pcap | Format::PcapNg => {
                return Err(CliError::new(
                    core::error::Kind::Usage,
                    "--field requires text, JSON, or NDJSON output",
                ));
            }
        };
        let projection = Projection::compile(columns.iter().map(String::as_str), registry)
            .map_err(CliError::classified)?;
        Ok(Some(Self {
            projection,
            command,
            sink,
            budget: Budget {
                remaining: maximum,
                maximum,
            },
            count: 0,
        }))
    }

    pub(crate) fn requirements(&self) -> Requirements {
        self.projection.requirements()
    }

    pub(crate) fn emit(
        &mut self,
        source_frame: u64,
        context: &Context<'_>,
        stream: &StreamEncoder,
    ) -> Result<(), CliError> {
        let values = self
            .projection
            .values(context, self.budget.remaining)
            .map_err(CliError::classified)?;
        let row = Row::try_from((source_frame, values)).map_err(CliError::classified)?;
        match &mut self.sink {
            Sink::Text { header_written } => {
                self.budget.write_header(header_written, &self.projection)?;
                self.budget.write_line(&row.values, |line, value| {
                    line.push_json(&value.as_ref().map(Cell))
                })?;
            }
            Sink::Json { rows } => {
                let bytes = bounded_json_len(
                    &row,
                    self.budget.remaining,
                    serde_json::ser::CompactFormatter,
                )
                .map_err(|error| self.budget.error(error))?;
                self.budget.remaining -= bytes;
                rows.push(row);
            }
            Sink::Ndjson => {
                let event = || output::projection::RowEvent::from((&self.projection, &row));
                stream
                    .emit_data_counted(event(), Vec::new(), &mut self.budget.remaining)
                    .map_err(|error| match error {
                        output::stream::MeteredError::Limit => self.budget.limit(),
                        output::stream::MeteredError::Encode(
                            error @ output::stream::EncodeError::RecordLimit { .. },
                        ) => {
                            // Preserve projection-limit precedence when both byte ceilings are exceeded
                            match bounded_json_len(
                                &event(),
                                self.budget.remaining,
                                serde_json::ser::CompactFormatter,
                            ) {
                                Ok(_) => CliError::from(error),
                                Err(error) => self.budget.error(error),
                            }
                        }
                        output::stream::MeteredError::Encode(error) => CliError::from(error),
                        output::stream::MeteredError::Serialize(error) => {
                            crate::publication::serialization_error(error)
                        }
                    })?;
            }
        }
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| self.budget.limit())?;
        Ok(())
    }

    pub(crate) fn finish(
        mut self,
        invocation: &crate::invocation::Invocation,
        frames_read: u64,
        captured_bytes_read: u64,
        stream: &StreamEncoder,
    ) -> Result<(), CliError> {
        let summary = output::projection::Complete::from((
            &self.projection,
            self.count,
            frames_read,
            captured_bytes_read,
        ));
        match self.sink {
            Sink::Text { mut header_written } => self
                .budget
                .write_header(&mut header_written, &self.projection),
            Sink::Json { rows } => emit_published(
                invocation,
                self.command,
                Published::new(
                    output::projection::Report::from((summary, rows)),
                    Vec::new(),
                ),
            ),
            Sink::Ndjson => stream
                .complete_published(Published::new(summary, Vec::new()))
                .map_err(Into::into),
        }
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
    use std::io;

    #[test]
    fn formats_without_a_row_shape_are_refused_before_any_frame_is_read() {
        let registry = core::protocol::builtin::registry();
        let prepare = |columns: &[String], format| {
            Projector::prepare(columns, 1024, &registry, Command::Dissect, format)
        };
        let columns = ["raw.bytes".to_owned()];
        for format in [Format::Text, Format::Json, Format::Ndjson] {
            assert!(prepare(&columns, format).unwrap().is_some());
        }
        for format in [
            Format::Csv,
            Format::Hex,
            Format::Raw,
            Format::Pcap,
            Format::PcapNg,
        ] {
            let error = prepare(&columns, format).err().unwrap();
            assert_eq!(error.classification.kind, core::error::Kind::Usage);
            assert!(prepare(&[], format).unwrap().is_none());
        }
    }

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
