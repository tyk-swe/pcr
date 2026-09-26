// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{contract::Error, hex::compact_hex, stream::StreamRecord};
use packetcraftr_core::{
    analysis::{dns, reassembly::tcp::ScopedFlowKey, scope::Definition},
    field::FieldValue,
    layer::Layer,
};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Serialize)]
pub struct Message {
    pub index: u64,
    pub transport: dns::Transport,
    pub stream: u64,
    pub generation: u64,
    pub flow: ScopedFlowKey,
    pub status: dns::Status,
    pub wire_hex: String,
    pub framing_hex: String,
    pub declared_length: Option<u16>,
    pub fields: Option<BTreeMap<String, FieldValue>>,
    pub error: Option<String>,
    pub sources: Vec<super::provenance::Source>,
}
impl TryFrom<dns::Message> for Message {
    type Error = Error;
    fn try_from(message: dns::Message) -> Result<Self, Error> {
        Ok(Self {
            index: message.index,
            transport: message.transport,
            stream: message.stream,
            generation: message.generation,
            flow: message.flow,
            status: message.status,
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
            sources: super::provenance::from_source_set(&message.sources)?,
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
    pub status: dns::TransactionStatus,
    pub transport: dns::Transport,
    pub stream: u64,
    pub generation: u64,
    pub flow: ScopedFlowKey,
    pub dns_id: u16,
    pub queries: Vec<u64>,
    pub response: Option<u64>,
    pub original_response: Option<u64>,
    pub first_query_latency: Option<dns::Latency>,
    pub latest_query_latency: Option<dns::Latency>,
    pub sources: Vec<super::provenance::Source>,
}
impl TryFrom<dns::Transaction> for Transaction {
    type Error = Error;
    fn try_from(value: dns::Transaction) -> Result<Self, Error> {
        Ok(Self {
            status: value.status,
            transport: value.transport,
            stream: value.stream,
            generation: value.generation,
            flow: value.flow,
            dns_id: value.dns_id,
            queries: value.queries,
            response: value.response,
            original_response: value.original_response,
            first_query_latency: value.first_query_latency,
            latest_query_latency: value.latest_query_latency,
            sources: super::provenance::from_source_set(&value.sources)?,
        })
    }
}
impl StreamRecord for Transaction {
    fn event_name(&self) -> &'static str {
        "dns_transaction"
    }
}
#[derive(Debug, Serialize)]
#[serde(transparent)]
pub struct Issue(pub dns::StreamIssue);
impl StreamRecord for Issue {
    fn event_name(&self) -> &'static str {
        "dns_stream_issue"
    }
}
#[derive(Debug, Serialize)]
pub struct Complete {
    pub frames_read: u64,
    pub frames_matched: u64,
    pub summary: dns::Summary,
    pub scopes: Vec<Definition>,
    pub incomplete_datagrams: usize,
    pub source_outcomes_omitted: u64,
    pub ip_reassembly: super::reassembly::Report,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub messages: Vec<Message>,
    pub transactions: Vec<Transaction>,
    pub issues: Vec<Issue>,
    #[serde(flatten)]
    pub complete: Complete,
}
