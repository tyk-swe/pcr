// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{analysis, output};

use crate::commands::format::FollowFormat;
use crate::errors::CliError;
use crate::rendering::{
    StreamEncoder, emit_aggregate, emit_stderr_message, write_raw, write_stdout_line,
};

use analysis::follow::{Chunk, Selector, Summary};

#[derive(Default)]
pub(super) struct State {
    retained: Vec<output::follow::Chunk>,
}

pub(super) fn render_record(
    format: FollowFormat,
    chunk: Chunk,
    state: &mut State,
    stream: &mut StreamEncoder,
) -> Result<(), CliError> {
    match format {
        FollowFormat::Text => write_stdout_line(format_args!(
            "{} #{} {}",
            direction_marker(&chunk),
            chunk.number,
            chunk.bytes.escape_ascii()
        )),
        FollowFormat::Hex => {
            let rendered = output::follow::Chunk::from(chunk.clone());
            write_stdout_line(format_args!(
                "{} #{} {}",
                direction_marker(&chunk),
                rendered.frame,
                rendered.bytes_hex
            ))
        }
        FollowFormat::Raw => write_raw(&chunk.bytes),
        FollowFormat::Json => {
            state.retained.push(chunk.into());
            Ok(())
        }
        FollowFormat::Ndjson => {
            Ok(stream.emit_data(output::follow::Chunk::from(chunk), Vec::new())?)
        }
    }
}

pub(super) fn render_text(selector: Selector, summary: &Summary) -> Result<(), CliError> {
    let transport = output::expert::StreamTransport::from(selector.transport).as_str();
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
    ip_reassembly: &analysis::IpReassemblyReport,
) -> Result<(), CliError> {
    emit_aggregate(
        output::contract::Command::Follow,
        output::follow::Result::from_summary(
            selector.transport.into(),
            selector.index,
            summary,
            state.retained,
            ip_reassembly,
        ),
        Vec::new(),
    )
}

pub(super) fn render_stream(
    selector: Selector,
    summary: Summary,
    ip_reassembly: &analysis::IpReassemblyReport,
    stream: &mut StreamEncoder,
) -> Result<(), CliError> {
    Ok(stream.complete(
        output::follow::Result::from_summary(
            selector.transport.into(),
            selector.index,
            summary,
            Vec::new(),
            ip_reassembly,
        ),
        Vec::new(),
    )?)
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
