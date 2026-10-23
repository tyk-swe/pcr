// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    analysis::{ScopedFlowKey, analysis_complete},
    contract::Error,
    hex::compact_hex,
    provenance::Source,
    stream::StreamRecord,
};
use packetcraftr_core::analysis::messages as core;
use serde::Serialize;

pub use core::Status;
#[derive(Debug, Serialize)]
pub struct Message {
    pub index: u64,
    pub protocol: String,
    pub stream: u64,
    pub generation: u64,
    pub flow: ScopedFlowKey,
    pub status: Status,
    pub wire_hex: String,
    pub packet: Option<packetcraftr_core::document::Packet>,
    pub error: Option<String>,
    pub sources: Vec<Source>,
}
impl TryFrom<core::Message> for Message {
    type Error = Error;
    fn try_from(v: core::Message) -> Result<Self, Error> {
        Ok(Self {
            index: v.index,
            protocol: v.protocol.as_str().to_owned(),
            stream: v.stream,
            generation: v.generation,
            flow: v.flow.into(),
            status: v.status,
            wire_hex: compact_hex(&v.wire),
            packet: v
                .packet
                .as_ref()
                .map(packetcraftr_core::document::Packet::from_packet),
            error: v.error,
            sources: v
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
        "protocol_message"
    }
}
#[derive(Debug, Serialize)]
pub struct Issue {
    pub number: u64,
    pub flow: ScopedFlowKey,
    pub stream: u64,
    pub status: Status,
}
impl From<core::Issue> for Issue {
    fn from(v: core::Issue) -> Self {
        Self {
            number: v.number,
            flow: v.flow.into(),
            stream: v.stream,
            status: v.status,
        }
    }
}
impl StreamRecord for Issue {
    fn event_name(&self) -> &'static str {
        "protocol_issue"
    }
}
pub type Summary = core::Summary;
analysis_complete!(core::Summary);
#[derive(Debug, Serialize)]
pub struct Report {
    pub messages: Vec<Message>,
    pub issues: Vec<Issue>,
    #[serde(flatten)]
    pub complete: Complete,
}
