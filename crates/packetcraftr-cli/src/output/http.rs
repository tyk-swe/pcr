// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    contract::Error,
    hex::compact_hex,
    provenance::{Source, from_source_set},
    stream::StreamRecord,
};
use packetcraftr_core::{
    analysis::{http as analysis, reassembly::tcp::ScopedFlowKey, scope::Definition},
    protocol::application::http,
};
use serde::Serialize;
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StartLine {
    Request {
        method: String,
        target: String,
        target_hex: String,
        version: String,
    },
    Response {
        version: String,
        status: u16,
        reason: String,
        reason_hex: String,
    },
}
impl From<http::StartLine> for StartLine {
    fn from(value: http::StartLine) -> Self {
        match value {
            http::StartLine::Request {
                method,
                target,
                version,
            } => Self::Request {
                method,
                target: String::from_utf8_lossy(&target).into_owned(),
                target_hex: compact_hex(&target),
                version,
            },
            http::StartLine::Response {
                version,
                status,
                reason,
            } => Self::Response {
                version,
                status,
                reason: String::from_utf8_lossy(&reason).into_owned(),
                reason_hex: compact_hex(&reason),
            },
        }
    }
}
#[derive(Debug, Serialize)]
pub struct Header {
    pub name: String,
    pub value: String,
    pub value_hex: String,
}
impl From<http::Header> for Header {
    fn from(value: http::Header) -> Self {
        Self {
            name: value.name,
            value: String::from_utf8_lossy(&value.value).into_owned(),
            value_hex: compact_hex(&value.value),
        }
    }
}
#[derive(Debug, Serialize)]
pub struct Message {
    pub index: u64,
    pub stream: u64,
    pub generation: u64,
    pub flow: ScopedFlowKey,
    pub request: Option<u64>,
    pub status: analysis::Status,
    pub start: Option<StartLine>,
    pub headers: Vec<Header>,
    pub header_wire_hex: String,
    pub framing: Option<http::Body>,
    pub body_bytes: u64,
    pub trailers: Vec<Header>,
    pub error: Option<String>,
    pub sources: Vec<Source>,
}
impl TryFrom<analysis::Message> for Message {
    type Error = Error;
    fn try_from(value: analysis::Message) -> Result<Self, Error> {
        let (start, headers) = value.head.map_or((None, Vec::new()), |head| {
            (
                Some(head.start.into()),
                head.headers.into_iter().map(Into::into).collect(),
            )
        });
        Ok(Self {
            index: value.index,
            stream: value.stream,
            generation: value.generation,
            flow: value.flow,
            request: value.request,
            status: value.status,
            start,
            headers,
            header_wire_hex: compact_hex(&value.header_wire),
            framing: value.framing,
            body_bytes: value.body_bytes,
            trailers: value.trailers.into_iter().map(Into::into).collect(),
            error: value.error.map(|error| error.to_string()),
            sources: from_source_set(&value.sources)?,
        })
    }
}
impl StreamRecord for Message {
    fn event_name(&self) -> &'static str {
        "http_message"
    }
}
#[derive(Debug, Serialize)]
#[serde(transparent)]
pub struct Issue(pub analysis::Issue);
impl StreamRecord for Issue {
    fn event_name(&self) -> &'static str {
        "http_stream_issue"
    }
}
#[derive(Debug, Serialize)]
pub struct Complete {
    pub frames_read: u64,
    pub frames_matched: u64,
    pub summary: analysis::Summary,
    pub scopes: Vec<Definition>,
    pub incomplete_datagrams: usize,
    pub source_outcomes_omitted: u64,
    pub ip_reassembly: super::reassembly::Report,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub messages: Vec<Message>,
    pub issues: Vec<Issue>,
    #[serde(flatten)]
    pub complete: Complete,
}
