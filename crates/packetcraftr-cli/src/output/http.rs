// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    analysis::{Scope, ScopedFlowKey},
    contract::Error,
    hex::compact_hex,
    provenance::Source,
    stream::StreamRecord,
};
use packetcraftr_core::{
    analysis::{self as library, http as analysis, scope::Definition},
    protocol::application::http,
};
use serde::Serialize;

published_enum! {
    /// Where an HTTP message, or a stream issue, ended up.
    pub enum Status from analysis::Status {
        Complete => "complete",
        Incomplete => "incomplete",
        Malformed => "malformed",
        Limit => "limit",
        Gap => "gap",
        Conflict => "conflict",
        Reset => "reset",
        Evicted => "evicted",
        Upgrade => "upgrade",
    }
}

/// How a message delimits its body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", content = "length")]
pub enum Body {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "length")]
    Length(u64),
    #[serde(rename = "chunked")]
    Chunked,
    #[serde(rename = "close")]
    Close,
    #[serde(rename = "tunnel")]
    Tunnel,
}

impl From<http::Body> for Body {
    fn from(value: http::Body) -> Self {
        match value {
            http::Body::None => Self::None,
            http::Body::Length(length) => Self::Length(length),
            http::Body::Chunked => Self::Chunked,
            http::Body::Close => Self::Close,
            http::Body::Tunnel => Self::Tunnel,
        }
    }
}

/// The HTTP request line or status line of a message.
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

/// One HTTP header field with its text form and raw wire bytes.
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

/// One HTTP message on a stream, with head, body progress, and outcome.
#[derive(Debug, Serialize)]
pub struct Message {
    pub index: u64,
    pub stream: u64,
    pub generation: u64,
    pub flow: ScopedFlowKey,
    pub request: Option<u64>,
    pub status: Status,
    pub start: Option<StartLine>,
    pub headers: Vec<Header>,
    pub header_wire_hex: String,
    pub framing: Option<Body>,
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
            flow: value.flow.into(),
            request: value.request,
            status: value.status.into(),
            start,
            headers,
            header_wire_hex: compact_hex(&value.header_wire),
            framing: value.framing.map(Into::into),
            body_bytes: value.body_bytes,
            trailers: value.trailers.into_iter().map(Into::into).collect(),
            error: value.error.map(|error| error.to_string()),
            sources: value
                .sources
                .frames()
                .iter()
                .map(Source::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}
impl StreamRecord for Message {
    fn event_name(&self) -> &'static str {
        "http_message"
    }
}
/// A stream-level condition that invalidated pending messages.
#[derive(Debug, Serialize)]
pub struct Issue {
    pub number: u64,
    pub flow: ScopedFlowKey,
    pub stream: u64,
    pub status: Status,
}
impl From<analysis::Issue> for Issue {
    fn from(value: analysis::Issue) -> Self {
        Self {
            number: value.number,
            flow: value.flow.into(),
            stream: value.stream,
            status: value.status.into(),
        }
    }
}
impl StreamRecord for Issue {
    fn event_name(&self) -> &'static str {
        "http_stream_issue"
    }
}
/// Cumulative counts over every message the collector framed.
#[derive(Debug, Serialize)]
pub struct Summary {
    pub messages: u64,
    pub complete_messages: u64,
    pub incomplete_messages: u64,
    pub malformed_messages: u64,
    pub upgraded_connections: u64,
    pub responses_without_request: u64,
    pub requests_without_final_response: u64,
}
impl From<analysis::Summary> for Summary {
    fn from(value: analysis::Summary) -> Self {
        Self {
            messages: value.messages,
            complete_messages: value.complete_messages,
            incomplete_messages: value.incomplete_messages,
            malformed_messages: value.malformed_messages,
            upgraded_connections: value.upgraded_connections,
            responses_without_request: value.responses_without_request,
            requests_without_final_response: value.requests_without_final_response,
        }
    }
}
#[derive(Debug, Serialize)]
pub struct Complete {
    pub frames_read: u64,
    pub frames_matched: u64,
    pub summary: Summary,
    pub scopes: Vec<Scope>,
    pub incomplete_datagrams: usize,
    pub source_outcomes_omitted: u64,
    pub ip_reassembly: super::reassembly::Report,
}
/// The run's counters, the collector's summary, and the scopes it exposed.
impl TryFrom<(&library::Summary, analysis::Summary, Vec<Definition>)> for Complete {
    type Error = Error;
    fn try_from(
        (run, summary, scopes): (&library::Summary, analysis::Summary, Vec<Definition>),
    ) -> Result<Self, Error> {
        Ok(Self {
            frames_read: run.frames_read,
            frames_matched: run.frames_matched,
            summary: summary.into(),
            scopes: scopes
                .into_iter()
                .map(Scope::try_from)
                .collect::<Result<_, _>>()?,
            incomplete_datagrams: run.incomplete_sources.len(),
            source_outcomes_omitted: run.source_outcomes_omitted,
            ip_reassembly: (&run.ip_reassembly).into(),
        })
    }
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub messages: Vec<Message>,
    pub issues: Vec<Issue>,
    #[serde(flatten)]
    pub complete: Complete,
}
/// The messages and issues retained for the document, and the terminal
/// counters.
impl From<(Vec<Message>, Vec<Issue>, Complete)> for Report {
    fn from((messages, issues, complete): (Vec<Message>, Vec<Issue>, Complete)) -> Self {
        Self {
            messages,
            issues,
            complete,
        }
    }
}
