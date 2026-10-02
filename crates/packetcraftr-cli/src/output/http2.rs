// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub mod frame;

pub use frame::{Control, Frame, Priority, Setting};

use super::{
    analysis::{ScopedFlowKey, analysis_complete},
    contract::Error,
    hex::compact_hex,
    http as http1,
    provenance::Source,
    stream::StreamRecord,
};
use packetcraftr_core::analysis::http2 as analysis;
use serde::Serialize;

published_enum! {
    pub enum Status from analysis::Status {
        Complete => "complete",
        Incomplete => "incomplete",
        Malformed => "malformed",
        Limit => "limit",
        Gap => "gap",
        Conflict => "conflict",
        Reset => "reset",
        Evicted => "evicted",
        Unprocessed => "unprocessed",
        Unsupported => "unsupported",
    }
}

published_enum! {
    pub enum Startup from analysis::Startup {
        PriorKnowledge => "prior_knowledge",
        H2c => "h2c",
        Unknown => "unknown",
    }
}

published_enum! {
    pub enum MessageKind from analysis::MessageKind {
        Request => "request",
        Response => "response",
        Informational => "informational",
        PushPromise => "push_promise",
    }
}

published_enum! {
    pub enum Certainty from analysis::Certainty {
        Confirmed => "confirmed",
        ObservedOrder => "observed_order",
        Indeterminate => "indeterminate",
    }
}

published_enum! {
    pub enum IssueScope from analysis::IssueScope {
        Connection => "connection",
        Stream => "stream",
        Compression => "compression",
        Capture => "capture",
    }
}

#[derive(Debug, Serialize)]
pub struct Header {
    pub name: String,
    pub name_hex: String,
    pub value: String,
    pub value_hex: String,
    pub never_indexed: bool,
}
impl From<analysis::Header> for Header {
    fn from(value: analysis::Header) -> Self {
        Self {
            name: String::from_utf8_lossy(&value.name).into_owned(),
            name_hex: compact_hex(&value.name),
            value: String::from_utf8_lossy(&value.value).into_owned(),
            value_hex: compact_hex(&value.value),
            never_indexed: value.never_indexed,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct UpgradeHead {
    pub start: http1::StartLine,
    pub headers: Vec<http1::Header>,
    pub wire_hex: String,
}
impl From<packetcraftr_core::protocol::application::http::Head> for UpgradeHead {
    fn from(value: packetcraftr_core::protocol::application::http::Head) -> Self {
        let wire_hex = compact_hex(value.wire());
        Self {
            start: value.start.into(),
            headers: value.headers.into_iter().map(Into::into).collect(),
            wire_hex,
        }
    }
}

fn sources(set: &packetcraftr_core::analysis::provenance::SourceSet) -> Result<Vec<Source>, Error> {
    set.frames()
        .iter()
        .map(Source::try_from)
        .collect::<Result<_, _>>()
}
fn optional_sources(
    set: Option<&packetcraftr_core::analysis::provenance::SourceSet>,
) -> Result<Vec<Source>, Error> {
    match set {
        Some(set) => sources(set),
        None => Ok(Vec::new()),
    }
}

#[derive(Debug, Serialize)]
pub struct Message {
    pub index: u64,
    pub stream: u64,
    pub generation: u64,
    pub http2_stream_id: u32,
    pub flow: ScopedFlowKey,
    pub kind: MessageKind,
    pub request: Option<u64>,
    pub promised_by: Option<u32>,
    pub status: Status,
    pub headers: Vec<Header>,
    pub trailers: Vec<Header>,
    pub header_blocks_hex: Vec<String>,
    pub upgrade_head: Option<UpgradeHead>,
    pub body_bytes: u64,
    pub sources: Vec<Source>,
    pub compression_sources: Vec<Source>,
}
impl TryFrom<analysis::Message> for Message {
    type Error = Error;
    fn try_from(value: analysis::Message) -> Result<Self, Error> {
        Ok(Self {
            index: value.index,
            stream: value.stream,
            generation: value.generation,
            http2_stream_id: value.http2_stream_id,
            flow: value.flow.into(),
            kind: value.kind.into(),
            request: value.request,
            promised_by: value.promised_by,
            status: value.status.into(),
            headers: value.headers.into_iter().map(Into::into).collect(),
            trailers: value.trailers.into_iter().map(Into::into).collect(),
            header_blocks_hex: value
                .header_blocks
                .iter()
                .map(|block| compact_hex(block))
                .collect(),
            upgrade_head: value.upgrade_head.map(Into::into),
            body_bytes: value.body_bytes,
            sources: sources(&value.sources)?,
            compression_sources: optional_sources(value.compression_sources.as_ref())?,
        })
    }
}
impl StreamRecord for Message {
    fn event_name(&self) -> &'static str {
        "http2_message"
    }
}

#[derive(Debug, Serialize)]
pub struct Issue {
    pub number: u64,
    pub stream: u64,
    pub generation: u64,
    pub http2_stream_id: Option<u32>,
    pub flow: ScopedFlowKey,
    pub code: String,
    pub scope: IssueScope,
    pub certainty: Certainty,
    pub status: Status,
    pub detail: String,
    pub wire_hex: String,
    pub sources: Vec<Source>,
}
impl TryFrom<analysis::Issue> for Issue {
    type Error = Error;
    fn try_from(value: analysis::Issue) -> Result<Self, Error> {
        Ok(Self {
            number: value.number,
            stream: value.stream,
            generation: value.generation,
            http2_stream_id: value.http2_stream_id,
            flow: value.flow.into(),
            code: value.code.to_owned(),
            scope: value.scope.into(),
            certainty: value.certainty.into(),
            status: value.status.into(),
            detail: value.detail,
            wire_hex: compact_hex(&value.wire),
            sources: optional_sources(value.sources.as_ref())?,
        })
    }
}
impl StreamRecord for Issue {
    fn event_name(&self) -> &'static str {
        "http2_issue"
    }
}

#[derive(Debug, Serialize)]
pub struct PeerSettings {
    pub header_table_size: u32,
    pub enable_push: bool,
    pub max_concurrent_streams: Option<u32>,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: Option<u32>,
}
impl From<analysis::PeerSettings> for PeerSettings {
    fn from(value: analysis::PeerSettings) -> Self {
        Self {
            header_table_size: value.header_table_size,
            enable_push: value.enable_push,
            max_concurrent_streams: value.max_concurrent_streams,
            initial_window_size: value.initial_window_size,
            max_frame_size: value.max_frame_size,
            max_header_list_size: value.max_header_list_size,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Connection {
    pub stream: u64,
    pub generation: u64,
    pub flow: ScopedFlowKey,
    pub startup: Startup,
    pub status: Status,
    pub client_settings: PeerSettings,
    pub server_settings: PeerSettings,
    pub client_window: i64,
    pub server_window: i64,
    pub streams: u64,
    pub frames: u64,
    pub issues: u64,
    pub pending_settings: u64,
    pub pending_pings: u64,
    pub upgrade_response: Option<UpgradeHead>,
    pub upgrade_sources: Vec<Source>,
}
impl TryFrom<analysis::Connection> for Connection {
    type Error = Error;
    fn try_from(value: analysis::Connection) -> Result<Self, Error> {
        Ok(Self {
            stream: value.stream,
            generation: value.generation,
            flow: value.flow.into(),
            startup: value.startup.into(),
            status: value.status.into(),
            client_settings: value.client_settings.into(),
            server_settings: value.server_settings.into(),
            client_window: value.client_window,
            server_window: value.server_window,
            streams: value.streams,
            frames: value.frames,
            issues: value.issues,
            pending_settings: value.pending_settings,
            pending_pings: value.pending_pings,
            upgrade_response: value.upgrade_response.map(Into::into),
            upgrade_sources: optional_sources(value.upgrade_sources.as_ref())?,
        })
    }
}
impl StreamRecord for Connection {
    fn event_name(&self) -> &'static str {
        "http2_connection"
    }
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub connections: u64,
    pub prior_knowledge_connections: u64,
    pub upgraded_connections: u64,
    pub unsupported_connections: u64,
    pub frames: u64,
    pub streams: u64,
    pub messages: u64,
    pub complete_messages: u64,
    pub incomplete_messages: u64,
    pub malformed_messages: u64,
    pub limited_messages: u64,
    pub issues: u64,
}
impl From<analysis::Summary> for Summary {
    fn from(value: analysis::Summary) -> Self {
        Self {
            connections: value.connections,
            prior_knowledge_connections: value.prior_knowledge_connections,
            upgraded_connections: value.upgraded_connections,
            unsupported_connections: value.unsupported_connections,
            frames: value.frames,
            streams: value.streams,
            messages: value.messages,
            complete_messages: value.complete_messages,
            incomplete_messages: value.incomplete_messages,
            malformed_messages: value.malformed_messages,
            limited_messages: value.limited_messages,
            issues: value.issues,
        }
    }
}
analysis_complete!(analysis::Summary);
#[derive(Debug, Serialize)]
pub struct Report {
    pub frames: Vec<Frame>,
    pub messages: Vec<Message>,
    pub issues: Vec<Issue>,
    pub connections: Vec<Connection>,
    #[serde(flatten)]
    pub complete: Complete,
}
impl
    From<(
        Vec<Frame>,
        Vec<Message>,
        Vec<Issue>,
        Vec<Connection>,
        Complete,
    )> for Report
{
    fn from(
        (frames, messages, issues, connections, complete): (
            Vec<Frame>,
            Vec<Message>,
            Vec<Issue>,
            Vec<Connection>,
            Complete,
        ),
    ) -> Self {
        Self {
            frames,
            messages,
            issues,
            connections,
            complete,
        }
    }
}
