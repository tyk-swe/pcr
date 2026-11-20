// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::{analysis::http3, field::hex::CompactHex};
use serde::Serialize;

use crate::commands::offline_analysis::output::{Endpoint, Scope};
use crate::output::{contract, published_enum, stream::StreamRecord};

published_enum! { pub(super) enum Code from http3::Code {
    MissingControlStream => "missing_control_stream",
    ClosedControlStream => "closed_control_stream",
    ClosedQpackEncoderStream => "closed_qpack_encoder_stream",
    ClosedQpackDecoderStream => "closed_qpack_decoder_stream",
    DuplicateCriticalStream => "duplicate_critical_stream",
    MissingSettings => "missing_settings",
    InvalidSettings => "invalid_settings",
    EncoderStreamGap => "encoder_stream_gap",
    QpackEncoderError => "qpack_encoder_error",
    QpackUnavailable => "qpack_unavailable",
    QpackAmbiguous => "qpack_ambiguous",
    QpackInvalid => "qpack_invalid",
    StreamGap => "stream_gap",
    StreamReset => "stream_reset",
    ConflictingStream => "conflicting_stream",
    OmittedStreamBytes => "omitted_stream_bytes",
    TruncatedFrame => "truncated_frame",
    InvalidFrame => "invalid_frame",
    InvalidFramePlacement => "invalid_frame_placement",
    InvalidHeaders => "invalid_headers",
    ContentLengthMismatch => "content_length_mismatch",
    UnexpectedResponseContent => "unexpected_response_content",
    ExtendedConnectDisabled => "extended_connect_disabled",
    ExtendedConnectSettingsUnavailable => "extended_connect_settings_unavailable",
    MissingInitialHeaders => "missing_initial_headers",
    MissingFinalResponse => "missing_final_response",
    Limit => "limit",
} }

published_enum! { pub(super) enum SectionKind from http3::SectionKind {
    Request => "request",
    Informational => "informational",
    Response => "response",
    Trailers => "trailers",
    Unclassified => "unclassified",
} }

#[derive(Debug, Serialize)]
pub(super) struct Issue {
    pub code: Code,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
}

impl From<http3::Issue> for Issue {
    fn from(issue: http3::Issue) -> Self {
        Self {
            code: issue.code.into(),
            offset: issue.offset,
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct CriticalStreams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_stream: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoder_stream: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_table_capacity: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qpack_blocked_streams: Option<u64>,
    pub encoder_inserts: u64,
    pub issues: Vec<Issue>,
}

impl From<http3::CriticalStreams> for CriticalStreams {
    fn from(streams: http3::CriticalStreams) -> Self {
        Self {
            control_stream: streams.control_stream,
            encoder_stream: streams.encoder_stream,
            max_table_capacity: streams.max_table_capacity,
            qpack_blocked_streams: streams.qpack_blocked_streams,
            encoder_inserts: streams.encoder_inserts,
            issues: streams.issues.into_iter().map(Issue::from).collect(),
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct Connection {
    pub connection: u64,
    pub scope: Scope,
    pub version: u32,
    pub client_endpoint: Endpoint,
    pub server_endpoint: Endpoint,
    pub first_frame: u64,
    pub last_frame: u64,
    pub source_frames: Vec<u64>,
    pub source_frames_omitted: u64,
    pub pending_packets: u64,
    pub transport_incomplete: bool,
    pub client: CriticalStreams,
    pub server: CriticalStreams,
}

impl TryFrom<http3::Connection<'_>> for Connection {
    type Error = contract::Error;

    fn try_from(connection: http3::Connection<'_>) -> Result<Self, Self::Error> {
        let transport = connection.transport;
        Ok(Self {
            connection: transport.connection,
            scope: Scope::try_from(&transport.scope)?,
            version: transport.version,
            client_endpoint: transport.client_endpoint.into(),
            server_endpoint: transport.server_endpoint.into(),
            first_frame: transport.first_frame,
            last_frame: transport.last_frame,
            source_frames: transport.source_frames.clone(),
            source_frames_omitted: transport.source_frames_omitted,
            pending_packets: transport.pending_packets,
            transport_incomplete: connection.transport_incomplete,
            client: connection.client.into(),
            server: connection.server.into(),
        })
    }
}

#[derive(Debug, Serialize)]
pub(super) struct Field {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_hex: Option<String>,
}

impl Field {
    fn new(field: http3::Field, include_values: bool) -> Self {
        let name = std::str::from_utf8(&field.name).map_or_else(
            |_| format!("[hex:{}]", CompactHex(&field.name)),
            str::to_owned,
        );
        let (value, value_hex) = if include_values {
            match std::str::from_utf8(&field.value) {
                Ok(value) => (Some(value.to_owned()), None),
                Err(_) => (None, Some(CompactHex(&field.value).to_string())),
            }
        } else {
            (None, None)
        };
        Self {
            name,
            value,
            value_hex,
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct HeaderSection {
    pub kind: SectionKind,
    pub offset: u64,
    pub encoded_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_insert_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub fields: Vec<Field>,
}

impl HeaderSection {
    fn new(section: http3::HeaderSection, include_values: bool) -> Self {
        Self {
            kind: section.kind.into(),
            offset: section.offset,
            encoded_bytes: section.encoded_bytes,
            required_insert_count: section.required_insert_count,
            method: section.method,
            status: section.status,
            fields: section
                .fields
                .into_iter()
                .map(|f| Field::new(f, include_values))
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct Side {
    pub complete: bool,
    pub prefix_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reset_error: Option<u64>,
    pub header_sections: Vec<HeaderSection>,
    pub data_frames: u64,
    pub data_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_data_offset: Option<u64>,
    pub issues: Vec<Issue>,
    pub issues_omitted: u64,
}

impl Side {
    fn new(side: http3::Side, include_values: bool) -> Self {
        Self {
            complete: side.complete,
            prefix_bytes: side.prefix_bytes,
            reset_error: side.reset_error,
            header_sections: side
                .header_sections
                .into_iter()
                .map(|section| HeaderSection::new(section, include_values))
                .collect(),
            data_frames: side.data_frames,
            data_bytes: side.data_bytes,
            first_data_offset: side.first_data_offset,
            issues: side.issues.into_iter().map(Issue::from).collect(),
            issues_omitted: side.issues_omitted,
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct Exchange {
    pub connection: u64,
    pub stream: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<Side>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<Side>,
}

impl Exchange {
    pub(super) fn new(exchange: http3::Exchange, include_values: bool) -> Self {
        Self {
            connection: exchange.connection,
            stream: exchange.stream,
            request: exchange.request.map(|side| Side::new(side, include_values)),
            response: exchange
                .response
                .map(|side| Side::new(side, include_values)),
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub(super) struct Summary {
    pub frames_read: u64,
    pub input_incomplete: bool,
    pub connections: u64,
    pub exchanges: u64,
    pub unknown_alpn: u64,
    pub skipped_alpn: u64,
    pub quic_limit_hits: u64,
    pub quic_evictions: u64,
    pub quic_unassociated_packets: u64,
    pub keylog_records_rejected: u64,
}

#[derive(Serialize)]
pub(super) struct Terminal {
    pub summary: Summary,
}

#[derive(Serialize)]
pub(super) struct Report {
    pub connections: Vec<Connection>,
    pub exchanges: Vec<Exchange>,
    pub summary: Summary,
}

#[derive(Serialize)]
#[serde(untagged)]
pub(super) enum Event {
    Connection { connection: Box<Connection> },
    Exchange { exchange: Box<Exchange> },
}

impl StreamRecord for Event {
    fn event_name(&self) -> &'static str {
        match self {
            Self::Connection { .. } => "http3_connection",
            Self::Exchange { .. } => "http3_exchange",
        }
    }
}
