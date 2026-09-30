// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    command_options::{DecodeArgs, OfflineLimitsArgs, Selector, validate_output_bytes},
    errors::CliError,
    output::{
        contract::{Command, ToolFormat},
        websocket as wire,
    },
    rendering::{StreamEncoder, emit_aggregate, write_stdout_line, write_summary_line},
};
use packetcraftr_core::{
    analysis::{
        StreamRef, StreamTransport,
        websocket::{Collector, Limits},
    },
    error::Kind,
};
use std::path::PathBuf;

pub(crate) const AFTER_LONG_HELP: &str = "WebSocket messages are assembled offline from one TCP conversation. HTTP GET/101 upgrade headers enable frame parsing. Use --decode-as websocket for a capture starting after the upgrade. Continuations assemble under a 16 MiB message ceiling; control frames remain separate. Negotiated compression is unsupported.\n\nExamples:\n  packetcraftr websocket capture.pcapng --stream tcp:2\n  packetcraftr --output ndjson websocket capture.pcapng --stream tcp:0 --decode-as websocket";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Source PCAP/PCAPNG capture; - reads stdin.
    pub(crate) path: PathBuf,
    /// Select one complete TCP conversation.
    #[arg(long, value_name = "tcp:INDEX", value_parser = crate::command_options::stream_selector)]
    pub(crate) stream: Selector<StreamRef>,
    /// Explicit WebSocket framing for streams whose HTTP upgrade was not captured.
    #[arg(long, value_parser = ["websocket"])]
    pub(crate) decode_as: Option<String>,
    /// Maximum assembled WebSocket message bytes, at most 16 MiB.
    #[arg(long, default_value_t = 16 * 1024 * 1024, value_parser = clap::value_parser!(u64).range(1..=16 * 1024 * 1024))]
    pub(crate) max_websocket_message_bytes: u64,
    /// Maximum buffered WebSocket bytes across both directions.
    #[arg(long, default_value_t = 32 * 1024 * 1024)]
    pub(crate) max_websocket_buffer_bytes: usize,
    /// Maximum data messages and control frames across the selected stream.
    #[arg(long, default_value_t = Limits::default().max_messages)]
    pub(crate) max_application_messages: usize,
    /// Maximum bytes buffered across both directions, including partial messages.
    #[arg(long, default_value_t = 16 * 1024 * 1024 + 14)]
    pub(crate) max_application_buffer_bytes: usize,
    /// Cumulative bytes charged for retained and emitted WebSocket evidence.
    #[arg(long, default_value_t = Limits::default().max_retained_bytes)]
    pub(crate) max_application_retained_bytes: usize,
    /// Maximum serialized message, control, and issue bytes in every format.
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    pub(crate) max_application_output_bytes: usize,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
}

impl super::Spec for Args {
    type Format = ToolFormat;
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;
    fn run_time(&self) -> Option<&dyn crate::command_options::Bounded> {
        Some(&self.limits)
    }
    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [max_websocket_message_bytes: Bytes @ ActiveState, max_websocket_buffer_bytes: Bytes @ ActiveState]);
        crate::resources::declare!(settings, self, [
            max_application_messages: Count @ ActiveState preset(256, 4096),
            max_application_buffer_bytes: Bytes @ ActiveState preset(2097152, 16777230),
            max_application_retained_bytes: Bytes @ ActiveState preset(8388608, 67108864),
            max_application_output_bytes: Bytes @ ResultRetention preset(8388608, 67108864),
        ]);
        self.limits.resources(
            settings,
            crate::command_options::AnalysisStages::with_tcp(true),
        );
    }
    fn run(
        self,
        format: ToolFormat,
        stream: &StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        validate_output_bytes(self.max_application_output_bytes)?;
        // Validate each supplied limit before combining the two buffer ceilings.
        packetcraftr_core::analysis::application::Limits {
            max_messages: self.max_application_messages,
            max_buffer_bytes: self.max_application_buffer_bytes,
            max_retained_bytes: self.max_application_retained_bytes,
            ..Default::default()
        }
        .validate()
        .map_err(CliError::classified)?;
        if self.max_websocket_buffer_bytes == 0
            || self.max_websocket_buffer_bytes > 32 * 1024 * 1024
        {
            return Err(CliError::new(
                Kind::Usage,
                "--max-websocket-buffer-bytes must be in 1..=33554432",
            ));
        }
        let selected = self.stream.get()?;
        if selected.transport != StreamTransport::Tcp {
            return Err(CliError::new(
                Kind::Usage,
                "WebSocket requires --stream tcp:INDEX",
            ));
        }
        let collector = Collector::new(
            selected,
            Limits {
                max_message_bytes: self.max_websocket_message_bytes as usize,
                max_buffered_bytes: self
                    .max_websocket_buffer_bytes
                    .min(self.max_application_buffer_bytes),
                max_messages: self.max_application_messages,
                max_retained_bytes: self.max_application_retained_bytes,
            },
            self.decode_as.is_some(),
        )
        .map_err(CliError::classified)?;
        let mut events = Vec::new();
        let decode = DecodeArgs::default();
        let outcome = super::offline_analysis::inspect(
            super::offline_analysis::Inspection {
                path: &self.path,
                limits: self.limits,
                decode: &decode,
                output_bytes: self.max_application_output_bytes,
                selector: Some(selected),
            },
            collector,
            format,
            stream,
            |output, event| output.emit(wire::Event::from(event), &mut events, render_event),
        )?;
        let complete = wire::Complete::try_from((&outcome.run, outcome.summary, outcome.scopes))
            .map_err(CliError::classified)?;
        match format {
            ToolFormat::Json => emit_aggregate(
                Command::Websocket,
                wire::Report {
                    stream: selected.index,
                    events,
                    complete,
                },
                Vec::new(),
            )?,
            ToolFormat::Ndjson => stream.complete(complete, Vec::new())?,
            ToolFormat::Text => write_summary_line(format_args!(
                "{} WebSocket messages, {} control frames, {} incomplete messages, {} malformed frames",
                complete.summary.messages,
                complete.summary.control_frames,
                complete.summary.incomplete_messages,
                complete.summary.malformed_frames
            ))?,
        }
        Ok(super::CommandExit::SUCCESS)
    }
}

fn render_event(event: &wire::Event) -> Result<(), CliError> {
    match event {
        wire::Event::Message {
            frame,
            index,
            opcode,
            bytes_hex,
            ..
        } => write_stdout_line(format_args!(
            "WebSocket message={index} frame={frame} opcode={opcode} payload={bytes_hex}"
        )),
        wire::Event::Control {
            frame,
            opcode,
            bytes_hex,
            ..
        } => write_stdout_line(format_args!(
            "WebSocket control frame={frame} opcode={opcode} payload={bytes_hex}"
        )),
        wire::Event::Issue { frame, reason, .. } => {
            write_stdout_line(format_args!("WebSocket frame={frame}: {reason}"))
        }
    }
}
