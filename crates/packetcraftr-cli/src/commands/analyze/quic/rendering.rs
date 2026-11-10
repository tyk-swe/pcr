use super::{
    arguments::Args,
    output::{Connection, Event, Range, Stream, StreamData},
    write::Exporter,
};
use crate::{
    errors::CliError,
    invocation::{Invocation, StreamEncoder},
    output::{contract::Format, envelope::Published, hex::compact_hex},
    publication::bounded_json_len,
    terminal::write_stdout_line,
};
use packetcraftr_core::{analysis::quic, error::Kind};

pub(super) struct State {
    pub retained: Vec<Connection>,
    pub selected: u64,
    pub omitted: u64,
    pub output_bytes: u64,
    remaining: usize,
    exporter: Option<Exporter>,
}
impl State {
    pub(super) fn new(args: &Args, invocation: &Invocation) -> Result<Self, CliError> {
        Ok(Self {
            retained: Vec::new(),
            selected: 0,
            omitted: 0,
            output_bytes: 0,
            remaining: args.max_application_output_bytes,
            exporter: args
                .write
                .as_deref()
                .map(|path| Exporter::new(invocation, path, args.max_output_connections))
                .transpose()?,
        })
    }
    pub(super) fn mark_capture_incomplete(&mut self) {
        for connection in &mut self.retained {
            connection.incomplete = true;
        }
        if let Some(exporter) = &mut self.exporter {
            exporter.mark_capture_incomplete();
        }
    }
    fn charge(&mut self, bytes: usize) -> Result<(), CliError> {
        self.remaining = self.remaining.checked_sub(bytes).ok_or_else(|| {
            CliError::new(Kind::Policy, "QUIC application output byte limit exceeded")
        })?;
        self.output_bytes = self.output_bytes.saturating_add(bytes as u64);
        Ok(())
    }
    pub(super) fn event(
        &mut self,
        event: quic::Event,
        args: &Args,
        invocation: &Invocation,
        encoder: &StreamEncoder,
    ) -> Result<(), CliError> {
        let quic::Event::Connection { connection } = event;
        if args
            .connection
            .is_some_and(|id| id != connection.connection)
        {
            return Ok(());
        }
        if args.stream.is_some_and(|id| {
            !connection
                .streams
                .iter()
                .any(|s| s.id == id && args.direction.includes(s.direction))
        }) {
            return Ok(());
        }
        self.selected += 1;
        if invocation.format == Format::Json
            && self.retained.len() >= args.max_output_connections
            && self.exporter.is_none()
        {
            self.omitted += 1;
            return Ok(());
        }
        let mut streams = Vec::new();
        for stream in &connection.streams {
            if args.stream.is_some_and(|id| stream.id != id)
                || !args.direction.includes(stream.direction)
            {
                continue;
            }
            let mut ranges = Vec::new();
            for range in &stream.ranges {
                let file = self.exporter.as_ref().map(|_| {
                    format!(
                        "quic-{}-{}-{}-{}-{}.bin",
                        connection.connection,
                        stream.id,
                        stream.direction.as_str(),
                        if stream.early_data {
                            "early"
                        } else {
                            "accepted"
                        },
                        range.offset
                    )
                });
                if args.include_data || self.exporter.is_some() {
                    self.charge(range.data.len())?;
                }
                if let (Some(exporter), Some(name)) = (&mut self.exporter, &file) {
                    exporter.range(name, &range.data)?;
                }
                if args.include_data && invocation.format != Format::Json {
                    for (index, chunk) in range.data.chunks(64 * 1024).enumerate() {
                        let data = StreamData {
                            connection: connection.connection,
                            stream: stream.id,
                            direction: stream.direction.into(),
                            offset: range.offset + (index * 64 * 1024) as u64,
                            data_hex: compact_hex(chunk),
                            early_data: stream.early_data,
                        };
                        if invocation.format == Format::Ndjson {
                            encoder.emit_published(Published::new(
                                Event::StreamData { stream_data: data },
                                Vec::new(),
                            ))?;
                        } else {
                            write_stdout_line(
                                invocation,
                                format_args!(
                                    "data connection={} stream={} direction={} offset={} early_data={} hex={}",
                                    connection.connection,
                                    stream.id,
                                    stream.direction.as_str(),
                                    data.offset,
                                    data.early_data,
                                    data.data_hex
                                ),
                            )?;
                        }
                    }
                }
                ranges.push(Range {
                    offset: range.offset,
                    length: range.data.len() as u64,
                    data_hex: (args.include_data && invocation.format == Format::Json)
                        .then(|| compact_hex(&range.data)),
                    file,
                });
            }
            streams.push(Stream {
                id: stream.id,
                direction: stream.direction.into(),
                ranges,
                final_size: stream.final_size,
                reset_error: stream.reset_error,
                complete: stream.complete,
                conflicting_overlap: stream.conflicting_overlap,
                final_size_error: stream.final_size_error,
                omitted_bytes: stream.omitted_bytes,
                early_data: stream.early_data,
            });
        }
        if let Some(exporter) = &mut self.exporter {
            let length = exporter.connection(
                connection.connection,
                connection.early_data.into(),
                connection.incomplete,
                &streams,
                self.remaining,
            )?;
            self.charge(length)?;
        }
        let report = Connection::from_core(*connection, streams).map_err(CliError::classified)?;
        match invocation.format {
            Format::Text => {
                write_stdout_line(
                    invocation,
                    format_args!(
                        "connection={} version=0x{:08x} client={} server={} sni={} alpn={} packets={} decrypted={} incomplete={}",
                        report.connection,
                        report.version,
                        report.client_endpoint,
                        report.server_endpoint,
                        report.sni.as_deref().unwrap_or("unknown"),
                        report.negotiated_alpn.as_deref().unwrap_or("unknown"),
                        report.metrics.packets,
                        report.metrics.decrypted_packets,
                        report.incomplete
                    ),
                )?;
                for stream in &report.streams {
                    write_stdout_line(
                        invocation,
                        format_args!(
                            "stream={} direction={} ranges={} final_size={} complete={} early_data={}",
                            stream.id,
                            stream.direction,
                            stream.ranges.len(),
                            stream
                                .final_size
                                .map_or_else(|| "unknown".to_owned(), |n| n.to_string()),
                            stream.complete,
                            stream.early_data
                        ),
                    )?;
                }
                for d in &report.diagnostics {
                    write_stdout_line(
                        invocation,
                        format_args!("frame={} {} {}", d.frame, d.code, d.message),
                    )?;
                }
            }
            Format::Ndjson => {
                encoder.emit_published(Published::new(
                    Event::Connection {
                        connection: Box::new(report),
                    },
                    Vec::new(),
                ))?;
            }
            Format::Json => {
                if self.retained.len() >= args.max_output_connections {
                    self.omitted += 1;
                    return Ok(());
                }
                let length =
                    bounded_json_len(&report, self.remaining, serde_json::ser::CompactFormatter)
                        .map_err(|_| {
                            CliError::new(Kind::Policy, "QUIC aggregate report byte limit exceeded")
                        })?;
                self.charge(length)?;
                self.retained.push(report);
            }
            other => other.unreachable(),
        }
        Ok(())
    }
    pub(super) fn publish(&mut self) -> Result<(), CliError> {
        if let Some(exporter) = self.exporter.take() {
            exporter.finish()?;
        }
        Ok(())
    }
}
