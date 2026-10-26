// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Stream lifecycle and in-progress request and response message state.

use super::model::{Header, MessageKind};
use crate::analysis::http2::side::{PerSide, Side};
use crate::analysis::provenance::SourceSet;
use bytes::Bytes;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Reserved,
    Open,
    Closed,
}

pub(crate) struct MessageBuilder {
    pub index: u64,
    pub stream_id: u32,
    pub kind: MessageKind,
    pub request: Option<u64>,
    pub promised_by: Option<u32>,
    pub headers: Vec<Header>,
    pub trailers: Vec<Header>,
    pub header_blocks: Vec<Bytes>,
    pub upgrade_head: Option<crate::protocol::application::http::Head>,
    pub body_bytes: u64,
    pub sets: Vec<SourceSet>,
    pub compression: Vec<SourceSet>,
    pub failure: Option<crate::analysis::http2::Status>,
    pub saw_body: bool,
    pub trailers_seen: bool,
    pub content_length: Option<u64>,
    pub status_code: Option<u16>,
    pub charged: usize,
    pub charged_spans: usize,
}

impl MessageBuilder {
    pub(crate) fn new(index: u64, stream_id: u32, kind: MessageKind) -> Self {
        Self {
            index,
            stream_id,
            kind,
            request: None,
            promised_by: None,
            headers: Vec::new(),
            trailers: Vec::new(),
            header_blocks: Vec::new(),
            upgrade_head: None,
            body_bytes: 0,
            sets: Vec::new(),
            compression: Vec::new(),
            failure: None,
            saw_body: false,
            trailers_seen: false,
            content_length: None,
            status_code: None,
            charged: 0,
            charged_spans: 0,
        }
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct EarlyResponse {
    pub final_seen: bool,
    pub forbids_trailers: bool,
    /// The final status cannot carry content, so later DATA is a violation.
    pub bodyless: bool,
    pub ended: bool,
}

pub(crate) struct StreamState {
    pub phase: Phase,
    pub initiator: Side,
    pub promised_by: Option<u32>,
    pub ended: PerSide<bool>,
    pub request: Option<u64>,
    pub msgs: PerSide<Option<MessageBuilder>>,
    pub send_window: PerSide<i64>,
    pub credit_exceeded: PerSide<bool>,
    pub window_granted: PerSide<i64>,
    pub early_response: Option<EarlyResponse>,
    pub method: Option<Bytes>,
    pub response_bodyless: bool,
    pub unprocessed: bool,
}

impl StreamState {
    pub(crate) fn open(initiator: Side, windows: PerSide<i64>) -> Self {
        Self {
            phase: Phase::Open,
            initiator,
            promised_by: None,
            ended: PerSide::default(),
            request: None,
            msgs: PerSide::new(None, None),
            send_window: windows,
            credit_exceeded: PerSide::new(false, false),
            window_granted: PerSide::new(0, 0),
            early_response: None,
            method: None,
            response_bodyless: false,
            unprocessed: false,
        }
    }
    pub(crate) fn reserved(promised_by: u32, windows: PerSide<i64>) -> Self {
        let mut stream = Self::open(Side::Server, windows);
        stream.phase = Phase::Reserved;
        stream.promised_by = Some(promised_by);
        stream.ended = PerSide::new(true, false);
        stream
    }
}
