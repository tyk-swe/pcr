// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

use super::{
    analysis::{Scope, ScopedFlowKey},
    contract::Error,
    frame::Timestamp,
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

/// How a settled request/response header association ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum TransactionOutcome {
    /// A parsed response head consumed a pending request.
    #[serde(rename = "paired")]
    Paired,
    /// A request saw no consuming response before retirement.
    #[serde(rename = "unanswered")]
    Unanswered,
    /// A response head had no pending request to consume.
    #[serde(rename = "orphan_response")]
    OrphanResponse,
}

impl TransactionOutcome {
    /// The published name, for text output that must agree with JSON.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Paired => "paired",
            Self::Unanswered => "unanswered",
            Self::OrphanResponse => "orphan_response",
        }
    }
}

impl fmt::Display for TransactionOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
impl From<analysis::TransactionOutcome> for TransactionOutcome {
    fn from(value: analysis::TransactionOutcome) -> Self {
        match value {
            analysis::TransactionOutcome::Paired => Self::Paired,
            analysis::TransactionOutcome::Unanswered => Self::Unanswered,
            analysis::TransactionOutcome::OrphanResponse => Self::OrphanResponse,
        }
    }
}

/// The physical frame that made header bytes available to the parser, and its
/// capture timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Availability {
    pub frame: u64,
    pub timestamp: Timestamp,
}
impl TryFrom<analysis::Availability> for Availability {
    type Error = Error;
    fn try_from(value: analysis::Availability) -> Result<Self, Error> {
        Ok(Self {
            frame: value.frame,
            timestamp: Timestamp::try_from(value.timestamp)?,
        })
    }
}

/// A signed capture-observed interval between two availability markers.
/// Negative intervals stay visible; zero is never negative.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Interval {
    pub nanoseconds: u128,
    pub negative: bool,
}
impl From<analysis::Interval> for Interval {
    fn from(value: analysis::Interval) -> Self {
        Self {
            nanoseconds: value.nanoseconds,
            negative: value.negative,
        }
    }
}

/// One settled header transaction: request/response association plus the
/// availability markers and signed intervals the capture observed.
#[derive(Debug, Serialize)]
pub struct Transaction {
    pub index: u64,
    pub stream: u64,
    pub generation: u64,
    pub flow: ScopedFlowKey,
    pub outcome: TransactionOutcome,
    pub request: Option<u64>,
    pub response: Option<u64>,
    pub response_status: Option<u16>,
    pub informational: Vec<u64>,
    pub request_headers_available: Option<Availability>,
    pub response_started: Option<Availability>,
    pub response_headers_available: Option<Availability>,
    pub response_header_wait: Option<Interval>,
    pub response_header_span: Option<Interval>,
}
impl TryFrom<analysis::Transaction> for Transaction {
    type Error = Error;
    fn try_from(value: analysis::Transaction) -> Result<Self, Error> {
        Ok(Self {
            index: value.index,
            stream: value.stream,
            generation: value.generation,
            flow: value.flow.into(),
            outcome: value.outcome.into(),
            request: value.request,
            response: value.response,
            response_status: value.response_status,
            informational: value.informational,
            request_headers_available: value
                .request_headers_available
                .map(TryInto::try_into)
                .transpose()?,
            response_started: value.response_started.map(TryInto::try_into).transpose()?,
            response_headers_available: value
                .response_headers_available
                .map(TryInto::try_into)
                .transpose()?,
            response_header_wait: value.response_header_wait.map(Into::into),
            response_header_span: value.response_header_span.map(Into::into),
        })
    }
}
impl StreamRecord for Transaction {
    fn event_name(&self) -> &'static str {
        "http_transaction"
    }
}

/// Outcome totals across every transaction a run emitted.
#[derive(Debug, Serialize)]
pub struct TransactionSummary {
    pub transactions: u64,
    pub paired: u64,
    pub unanswered: u64,
    pub orphan_responses: u64,
    pub negative_header_waits: u64,
    pub negative_header_spans: u64,
}
impl From<analysis::TransactionSummary> for TransactionSummary {
    fn from(value: analysis::TransactionSummary) -> Self {
        Self {
            transactions: value.transactions,
            paired: value.paired,
            unanswered: value.unanswered,
            orphan_responses: value.orphan_responses,
            negative_header_waits: value.negative_header_waits,
            negative_header_spans: value.negative_header_spans,
        }
    }
}

/// The byte domain an exported body artifact preserves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Representation {
    /// Entity bytes after chunk removal, with content encodings unchanged.
    #[serde(rename = "http_body_after_dechunking")]
    HttpBodyAfterDechunking,
}

impl Representation {
    /// The published name, for text output that must agree with JSON.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HttpBodyAfterDechunking => "http_body_after_dechunking",
        }
    }
}

impl fmt::Display for Representation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The caller-named artifact one completed message body was published as.
/// Body bytes are never embedded in machine output.
#[derive(Debug, Serialize)]
pub struct BodyExport {
    pub message: u64,
    pub stream: u64,
    pub generation: u64,
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub representation: Representation,
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
    pub transaction_summary: Option<TransactionSummary>,
    pub body_export: Option<BodyExport>,
}
/// The run's counters, the collector's summary, and the scopes it exposed.
impl TryFrom<(&library::Summary, analysis::Summary, Vec<Definition>)> for Complete {
    type Error = Error;
    fn try_from(
        (run, summary, scopes): (&library::Summary, analysis::Summary, Vec<Definition>),
    ) -> Result<Self, Error> {
        let transaction_summary = summary.transaction_summary.clone().map(Into::into);
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
            transaction_summary,
            body_export: None,
        })
    }
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub messages: Vec<Message>,
    pub transactions: Vec<Transaction>,
    pub issues: Vec<Issue>,
    #[serde(flatten)]
    pub complete: Complete,
}
/// The messages, transactions, and issues retained for the document, and the
/// terminal counters.
impl From<(Vec<Message>, Vec<Transaction>, Vec<Issue>, Complete)> for Report {
    fn from(
        (messages, transactions, issues, complete): (
            Vec<Message>,
            Vec<Transaction>,
            Vec<Issue>,
            Complete,
        ),
    ) -> Self {
        Self {
            messages,
            transactions,
            issues,
            complete,
        }
    }
}
