// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{analysis, output};

use crate::errors::CliError;
use crate::rendering::{
    emit, emit_aggregate, emit_next, emit_stderr_message, write_raw, write_stdout_line,
};

use analysis::expert::StreamTransport;
use analysis::follow::{Chunk, Selector, Summary};

#[derive(Default)]
pub(super) struct State {
    pub(super) sequence: u64,
    retained: Vec<output::follow::Chunk>,
}

pub(super) fn render_record(
    format: output::contract::Format,
    chunk: Chunk,
    state: &mut State,
) -> Result<(), CliError> {
    match format {
        output::contract::Format::Text => write_stdout_line(format_args!(
            "{} #{} {}",
            direction_marker(&chunk),
            chunk.number,
            chunk.bytes.escape_ascii()
        )),
        output::contract::Format::Hex => {
            let rendered = output::follow::Chunk::from(chunk.clone());
            write_stdout_line(format_args!(
                "{} #{} {}",
                direction_marker(&chunk),
                rendered.frame,
                rendered.bytes_hex
            ))
        }
        output::contract::Format::Raw => write_raw(&chunk.bytes),
        output::contract::Format::Json => {
            state.retained.push(chunk.into());
            Ok(())
        }
        output::contract::Format::Ndjson => emit_next(
            output::contract::Command::Follow,
            &mut state.sequence,
            output::follow::Chunk::from(chunk),
        ),
        _ => unreachable!("the format contract admits only text, json, ndjson, hex, and raw"),
    }
}

pub(super) fn render_text(selector: Selector, summary: &Summary) -> Result<(), CliError> {
    let transport = transport_name(selector.transport);
    match &summary.client_flow {
        Some(flow) => write_stdout_line(format_args!(
            "followed {transport} stream {}: client {}:{} sent {} byte(s), \
             server {}:{} sent {} byte(s), {} byte(s) undelivered in {} frame(s)",
            selector.index,
            flow.source,
            flow.source_port,
            summary.client_bytes,
            flow.destination,
            flow.destination_port,
            summary.server_bytes,
            summary.undelivered_bytes,
            summary.frames,
        )),
        None => write_stdout_line(format_args!(
            "followed {transport} stream {}: no frames",
            selector.index
        )),
    }
}

pub(super) fn render_aggregate(
    selector: Selector,
    summary: Summary,
    state: State,
) -> Result<(), CliError> {
    emit_aggregate(
        output::contract::Command::Follow,
        output::follow::Result::from_summary(
            selector.transport.into(),
            selector.index,
            summary,
            state.retained,
        ),
        Vec::new(),
    )
}

pub(super) fn render_stream(
    selector: Selector,
    summary: Summary,
    state: State,
) -> Result<(), CliError> {
    emit(
        output::contract::Command::Follow,
        state.sequence,
        output::follow::Result::from_summary(
            selector.transport.into(),
            selector.index,
            summary,
            Vec::new(),
        ),
        Vec::new(),
    )
}

pub(super) fn render_payload_warning(summary: &Summary) -> Result<(), CliError> {
    if summary.undelivered_bytes == 0 {
        return Ok(());
    }
    emit_stderr_message(&format!(
        "warning: {} byte(s) were captured but stranded behind missing segments and are not part of this output",
        summary.undelivered_bytes
    ))
}

fn direction_marker(chunk: &Chunk) -> &'static str {
    match chunk.direction {
        analysis::follow::Direction::ClientToServer => ">",
        analysis::follow::Direction::ServerToClient => "<",
    }
}

fn transport_name(transport: StreamTransport) -> &'static str {
    match transport {
        StreamTransport::Tcp => "tcp",
        StreamTransport::Udp => "udp",
    }
}
