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
    analysis::{self as library, dns, provenance::SourceSet, scope::Definition},
    field::FieldValue,
    layer::Layer,
};
use serde::Serialize;
use std::collections::BTreeMap;

published_enum! {
    /// The transport a DNS message was framed from.
    pub enum Transport from dns::Transport {
        Udp => "udp",
        Tcp => "tcp",
    }
}

published_enum! {
    /// Where a framed DNS message, or a stream issue, ended up.
    pub enum Status from dns::Status {
        Complete => "complete",
        Malformed => "malformed",
        Incomplete => "incomplete",
        Gap => "gap",
        Conflict => "conflict",
        Reset => "reset",
        Evicted => "evicted",
    }
}

published_enum! {
    /// How a query/response transaction settled.
    pub enum TransactionStatus from dns::TransactionStatus {
        Matched => "matched",
        Unanswered => "unanswered",
        OrphanResponse => "orphan_response",
        DuplicateResponse => "duplicate_response",
    }
}

/// The interval between a query's last captured byte and its response's
/// first; negative intervals stay visible.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Latency {
    pub nanoseconds: u128,
    pub negative: bool,
}

impl From<dns::Latency> for Latency {
    fn from(value: dns::Latency) -> Self {
        Self {
            nanoseconds: value.nanoseconds,
            negative: value.negative,
        }
    }
}

fn sources(value: &SourceSet) -> Result<Vec<Source>, Error> {
    value.frames().iter().map(Source::try_from).collect()
}

#[derive(Debug, Serialize)]
pub struct Message {
    pub index: u64,
    pub transport: Transport,
    pub stream: u64,
    pub generation: u64,
    pub flow: ScopedFlowKey,
    pub status: Status,
    pub wire_hex: String,
    pub framing_hex: String,
    pub declared_length: Option<u16>,
    pub fields: Option<BTreeMap<String, FieldValue>>,
    pub error: Option<String>,
    pub sources: Vec<Source>,
}
impl TryFrom<dns::Message> for Message {
    type Error = Error;
    fn try_from(message: dns::Message) -> Result<Self, Error> {
        Ok(Self {
            index: message.index,
            transport: message.transport.into(),
            stream: message.stream,
            generation: message.generation,
            flow: message.flow.into(),
            status: message.status.into(),
            wire_hex: compact_hex(&message.wire),
            framing_hex: compact_hex(&message.framing_bytes),
            declared_length: message.declared_length,
            fields: message.dns.as_ref().map(|dns| {
                dns.schema()
                    .fields
                    .iter()
                    .filter(|field| field.name != "wire")
                    .filter_map(|field| {
                        dns.field(field.name)
                            .map(|value| (field.name.to_owned(), value))
                    })
                    .collect()
            }),
            error: message.error.map(|error| error.to_string()),
            sources: sources(&message.sources)?,
        })
    }
}
impl StreamRecord for Message {
    fn event_name(&self) -> &'static str {
        "dns_message"
    }
}
#[derive(Debug, Serialize)]
pub struct Transaction {
    pub status: TransactionStatus,
    pub transport: Transport,
    pub stream: u64,
    pub generation: u64,
    pub flow: ScopedFlowKey,
    pub dns_id: u16,
    pub queries: Vec<u64>,
    pub response: Option<u64>,
    pub original_response: Option<u64>,
    pub first_query_latency: Option<Latency>,
    pub latest_query_latency: Option<Latency>,
    pub sources: Vec<Source>,
}
impl TryFrom<dns::Transaction> for Transaction {
    type Error = Error;
    fn try_from(value: dns::Transaction) -> Result<Self, Error> {
        Ok(Self {
            status: value.status.into(),
            transport: value.transport.into(),
            stream: value.stream,
            generation: value.generation,
            flow: value.flow.into(),
            dns_id: value.dns_id,
            queries: value.queries,
            response: value.response,
            original_response: value.original_response,
            first_query_latency: value.first_query_latency.map(Into::into),
            latest_query_latency: value.latest_query_latency.map(Into::into),
            sources: sources(&value.sources)?,
        })
    }
}
impl StreamRecord for Transaction {
    fn event_name(&self) -> &'static str {
        "dns_transaction"
    }
}
/// A stream-level condition attributed to one direction of a flow.
#[derive(Debug, Serialize)]
pub struct Issue {
    pub number: u64,
    pub flow: ScopedFlowKey,
    pub stream: u64,
    pub status: Status,
}
impl From<dns::StreamIssue> for Issue {
    fn from(value: dns::StreamIssue) -> Self {
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
        "dns_stream_issue"
    }
}
/// Cumulative counts over every record the collector processed.
#[derive(Debug, Serialize)]
pub struct Summary {
    pub messages: u64,
    pub complete_messages: u64,
    pub transactions: u64,
    pub matched_transactions: u64,
    pub unanswered_transactions: u64,
    pub orphan_responses: u64,
    pub duplicate_responses: u64,
}
impl From<dns::Summary> for Summary {
    fn from(value: dns::Summary) -> Self {
        Self {
            messages: value.messages,
            complete_messages: value.complete_messages,
            transactions: value.transactions,
            matched_transactions: value.matched_transactions,
            unanswered_transactions: value.unanswered_transactions,
            orphan_responses: value.orphan_responses,
            duplicate_responses: value.duplicate_responses,
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
impl TryFrom<(&library::Summary, dns::Summary, Vec<Definition>)> for Complete {
    type Error = Error;
    fn try_from(
        (run, summary, scopes): (&library::Summary, dns::Summary, Vec<Definition>),
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
