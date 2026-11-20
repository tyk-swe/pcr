// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod critical;
mod message;

use std::collections::BTreeMap;

use crate::budget::Deadline;
use crate::error::BoundaryError;
use crate::protocol::application::{qpack, quic::Reader};

use super::{quic, session};

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_qpack_history_bytes: usize,
    pub max_header_section_bytes: usize,
    pub max_exchange_bytes: usize,
    pub max_steps: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_qpack_history_bytes: 4 * 1024 * 1024,
            max_header_section_bytes: 64 * 1024,
            max_exchange_bytes: 256 * 1024,
            max_steps: 1_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    MissingControlStream,
    ClosedControlStream,
    ClosedQpackEncoderStream,
    ClosedQpackDecoderStream,
    DuplicateCriticalStream,
    MissingSettings,
    InvalidSettings,
    EncoderStreamGap,
    QpackEncoderError,
    QpackUnavailable,
    QpackAmbiguous,
    QpackInvalid,
    StreamGap,
    StreamReset,
    ConflictingStream,
    OmittedStreamBytes,
    TruncatedFrame,
    InvalidFrame,
    InvalidFramePlacement,
    InvalidHeaders,
    ContentLengthMismatch,
    UnexpectedResponseContent,
    ExtendedConnectDisabled,
    ExtendedConnectSettingsUnavailable,
    MissingInitialHeaders,
    MissingFinalResponse,
    Limit,
}

#[derive(Clone, Copy, Debug)]
pub struct Issue {
    pub code: Code,
    pub offset: Option<u64>,
}

#[derive(Debug, Default)]
pub struct CriticalStreams {
    pub control_stream: Option<u64>,
    pub encoder_stream: Option<u64>,
    pub max_table_capacity: Option<u64>,
    pub qpack_blocked_streams: Option<u64>,
    pub encoder_inserts: u64,
    pub issues: Vec<Issue>,
}

pub struct Connection<'a> {
    pub transport: &'a quic::Connection,
    pub transport_incomplete: bool,
    pub client: CriticalStreams,
    pub server: CriticalStreams,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionKind {
    Request,
    Informational,
    Response,
    Trailers,
    Unclassified,
}

#[derive(Debug)]
pub struct Field {
    pub name: bytes::Bytes,
    pub value: bytes::Bytes,
}

#[derive(Debug)]
pub struct HeaderSection {
    pub kind: SectionKind,
    pub offset: u64,
    pub encoded_bytes: u64,
    pub required_insert_count: Option<u64>,
    pub method: Option<String>,
    pub status: Option<u16>,
    pub fields: Vec<Field>,
}

#[derive(Debug, Default)]
pub struct Side {
    pub complete: bool,
    pub prefix_bytes: u64,
    pub reset_error: Option<u64>,
    pub header_sections: Vec<HeaderSection>,
    pub data_frames: u64,
    pub data_bytes: u64,
    pub first_data_offset: Option<u64>,
    pub issues: Vec<Issue>,
    pub issues_omitted: u64,
}

#[derive(Debug)]
pub struct Exchange {
    pub connection: u64,
    pub stream: u64,
    pub request: Option<Side>,
    pub response: Option<Side>,
}

pub enum Event<'a> {
    Connection(Connection<'a>),
    Exchange(Exchange),
}

/// Inspect the observed prefixes of HTTP/3 streams. A stream selector limits
/// exchange parsing, while QPACK uses the full captured encoder history.
pub fn inspect(
    connection: &quic::Connection,
    selected_stream: Option<u64>,
    limits: Limits,
    deadline: &Deadline,
    emit: &mut dyn FnMut(Event<'_>) -> Result<(), BoundaryError>,
) -> Result<(), BoundaryError> {
    session::check(deadline)?;
    if connection.negotiated_alpn.as_deref() != Some("h3") {
        return Ok(());
    }
    let mut budget = Work {
        remaining: limits.max_steps,
        deadline,
    };
    let mut transport_incomplete = !connection.closed
        || connection.pending_packets > 0
        || connection.source_frames_omitted > 0
        || connection.diagnostics_omitted > 0
        || !connection.diagnostics.is_empty();
    let mut critical = [critical::Streams::default(), critical::Streams::default()];
    let mut exchanges = BTreeMap::<u64, [Option<&quic::Stream>; 2]>::new();
    for stream in &connection.streams {
        session::check(deadline)?;
        transport_incomplete |=
            conflicting(stream) || (!stream.complete && !critical::normally_open(stream));
        // Accepted 0-RTT is already merged into the ordinary QUIC stream.
        if stream.early_data {
            transport_incomplete |= connection.early_data != quic::EarlyData::Accepted;
            continue;
        }
        let index = stream.direction.index();
        match stream.id % 4 {
            0 if selected_stream.is_none_or(|id| id == stream.id) => {
                exchanges.entry(stream.id).or_default()[index] = Some(stream);
            }
            2 | 3 => critical[index].observe(stream),
            _ => {}
        }
    }

    let [client, server] = critical;
    let mut client = client.settings(&mut budget)?;
    let mut server = server.settings(&mut budget)?;
    let client_history = client.history(server.report.max_table_capacity, limits, &mut budget)?;
    let server_history = server.history(client.report.max_table_capacity, limits, &mut budget)?;
    let connect_enabled = server.connect_enabled;
    emit(Event::Connection(Connection {
        transport: connection,
        transport_incomplete,
        client: client.report,
        server: server.report,
    }))?;
    for (stream, [request, response]) in exchanges {
        session::check(deadline)?;
        let [request, response] = message::read_pair(
            [request, response],
            [&client_history, &server_history],
            limits,
            connect_enabled,
            &mut budget,
        )?;
        emit(Event::Exchange(Exchange {
            connection: connection.connection,
            stream,
            request,
            response,
        }))?;
    }
    session::check(deadline)
}

struct Work<'a> {
    remaining: usize,
    deadline: &'a Deadline,
}

impl Work<'_> {
    fn step(&mut self, charge: usize) -> Result<(), qpack::Failure> {
        session::check(self.deadline).map_err(qpack::Failure::Interrupted)?;
        self.remaining = self
            .remaining
            .checked_sub(charge)
            .ok_or(qpack::Failure::Limit)?;
        Ok(())
    }
}

fn prefix(stream: &quic::Stream) -> &[u8] {
    stream
        .ranges
        .first()
        .filter(|range| range.offset == 0)
        .map_or(&[], |range| &range.data)
}

fn has_gap(stream: &quic::Stream, prefix: &[u8]) -> bool {
    stream.ranges.last().is_some_and(|range| range.offset != 0)
        || stream
            .final_size
            .is_some_and(|size| size > prefix.len() as u64)
}

fn conflicting(stream: &quic::Stream) -> bool {
    stream.conflicting_overlap || stream.final_size_error
}

struct Frame<'a> {
    kind: u64,
    data: &'a [u8],
}

fn frame<'a>(
    reader: &mut Reader<'a>,
) -> Result<Frame<'a>, crate::protocol::application::quic::Error> {
    let kind = reader.varint()?;
    let length = reader.length()?;
    let data = reader.take(length)?;
    Ok(Frame { kind, data })
}

#[cfg(test)]
mod tests;
