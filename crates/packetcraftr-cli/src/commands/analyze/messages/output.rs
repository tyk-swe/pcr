// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::commands::offline_analysis::output::{ScopedFlowKey, analysis_complete};

use crate::output::contract::Error;

use crate::output::hex::compact_hex;

use crate::output::frame::Source;

use crate::output::published_enum;
use crate::output::stream::StreamRecord;
use packetcraftr_core::analysis::messages as core;
use serde::Serialize;

published_enum! {
    pub(crate) enum Status from core::Status {
        Complete => "complete",
        Incomplete => "incomplete",
        Malformed => "malformed",
        Unsupported => "unsupported",
        Gap => "gap",
        Conflict => "conflict",
        Reset => "reset",
        Evicted => "evicted",
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct Message {
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
            status: v.status.into(),
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
pub(crate) struct Issue {
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
            status: v.status.into(),
        }
    }
}
impl StreamRecord for Issue {
    fn event_name(&self) -> &'static str {
        "protocol_issue"
    }
}
#[derive(Debug, Serialize)]
pub(crate) struct Summary {
    pub(crate) messages: u64,
    pub(crate) complete_messages: u64,
    pub(crate) incomplete_messages: u64,
    pub(crate) malformed_messages: u64,
    pub(crate) unsupported_messages: u64,
    pub(crate) by_protocol: std::collections::BTreeMap<String, u64>,
}

impl From<core::Summary> for Summary {
    fn from(value: core::Summary) -> Self {
        Self {
            messages: value.messages,
            complete_messages: value.complete_messages,
            incomplete_messages: value.incomplete_messages,
            malformed_messages: value.malformed_messages,
            unsupported_messages: value.unsupported_messages,
            by_protocol: value.by_protocol,
        }
    }
}

analysis_complete!(core::Summary);
#[derive(Debug, Serialize)]
pub(crate) struct Report {
    pub messages: Vec<Message>,
    pub issues: Vec<Issue>,
    #[serde(flatten)]
    pub complete: Complete,
}
