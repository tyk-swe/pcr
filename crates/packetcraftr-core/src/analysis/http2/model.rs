// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::analysis::provenance::SourceSet;
use crate::analysis::reassembly::tcp::ScopedFlowKey;
use crate::protocol::application::http;
use crate::protocol::application::http2 as wire;
use bytes::Bytes;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Complete,
    Incomplete,
    Malformed,
    Limit,
    Gap,
    Conflict,
    Reset,
    Evicted,
    Unprocessed,
    Unsupported,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Startup {
    PriorKnowledge,
    H2c,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageKind {
    Request,
    Response,
    Informational,
    PushPromise,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Certainty {
    Confirmed,
    ObservedOrder,
    Indeterminate,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssueScope {
    Connection,
    Stream,
    Compression,
    Capture,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub name: Bytes,
    pub value: Bytes,
    pub never_indexed: bool,
}
#[derive(Clone, Debug)]
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
    pub header_blocks: Vec<Bytes>,
    pub upgrade_head: Option<http::Head>,
    pub body_bytes: u64,
    pub sources: SourceSet,
    pub compression_sources: Option<SourceSet>,
}
#[derive(Clone, Debug)]
pub struct Frame {
    pub index: u64,
    pub stream: u64,
    pub generation: u64,
    pub flow: ScopedFlowKey,
    pub header: wire::FrameHeader,
    pub header_wire: [u8; 9],
    pub control: Option<wire::Payload>,
    pub payload_wire: Option<Bytes>,
    pub data_bytes: u64,
    pub padding_bytes: usize,
    pub sources: SourceSet,
}
#[derive(Clone, Debug)]
pub struct Issue {
    pub number: u64,
    pub stream: u64,
    pub generation: u64,
    pub http2_stream_id: Option<u32>,
    pub flow: ScopedFlowKey,
    pub code: &'static str,
    pub scope: IssueScope,
    pub certainty: Certainty,
    pub status: Status,
    pub detail: String,
    pub wire: Bytes,
    pub sources: Option<SourceSet>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerSettings {
    pub header_table_size: u32,
    pub enable_push: bool,
    pub max_concurrent_streams: Option<u32>,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: Option<u32>,
}
impl Default for PeerSettings {
    fn default() -> Self {
        Self {
            header_table_size: 4096,
            enable_push: true,
            max_concurrent_streams: None,
            initial_window_size: 65_535,
            max_frame_size: 16_384,
            max_header_list_size: None,
        }
    }
}
#[derive(Clone, Debug)]
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
    pub upgrade_response: Option<http::Head>,
    pub upgrade_sources: Option<SourceSet>,
}
#[derive(Clone, Debug, Default)]
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
#[derive(Clone, Debug)]
pub enum Event {
    Frame(Box<Frame>),
    Message(Box<Message>),
    Issue(Issue),
    Connection(Box<Connection>),
}
