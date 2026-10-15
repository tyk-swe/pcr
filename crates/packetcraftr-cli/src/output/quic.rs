// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Published `analyze quic` rows: header-form evidence without decryption.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use packetcraftr_core::analysis::quic as library;

use super::analysis::{Clock, Scope};
use super::contract::Error;
use super::frame::Timestamp;
use super::hex::compact_hex;

/// QUIC packets counted per conversation by header form.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PacketCounts {
    pub initial: u64,
    pub zero_rtt: u64,
    pub handshake: u64,
    pub retry: u64,
    pub version_negotiation: u64,
    pub one_rtt: u64,
    pub malformed: u64,
}

impl PacketCounts {
    /// Total packets, malformed included.
    pub fn total(&self) -> u64 {
        self.initial
            .saturating_add(self.zero_rtt)
            .saturating_add(self.handshake)
            .saturating_add(self.retry)
            .saturating_add(self.version_negotiation)
            .saturating_add(self.one_rtt)
            .saturating_add(self.malformed)
    }
}

impl From<library::PacketCounts> for PacketCounts {
    fn from(value: library::PacketCounts) -> Self {
        Self {
            initial: value.initial,
            zero_rtt: value.zero_rtt,
            handshake: value.handshake,
            retry: value.retry,
            version_negotiation: value.version_negotiation,
            one_rtt: value.one_rtt,
            malformed: value.malformed,
        }
    }
}

/// One UDP conversation's retained QUIC evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Conversation {
    /// Capture-global `udp.stream` index; filters and selectors share it.
    pub stream: u64,
    pub scope: Scope,
    pub address_a: IpAddr,
    pub port_a: u16,
    pub address_b: IpAddr,
    pub port_b: u16,
    pub packets: PacketCounts,
    pub versions: Vec<u32>,
    pub versions_omitted: u64,
    pub negotiated: Vec<u32>,
    pub negotiated_omitted: u64,
    /// Lowercase hex of the first Initial's destination connection ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_dcid_hex: Option<String>,
    /// Lowercase hex of the first Initial's source connection ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_scid_hex: Option<String>,
    pub first_timestamp: Timestamp,
    pub last_timestamp: Timestamp,
    pub duration: Duration,
}

impl TryFrom<library::Conversation> for Conversation {
    type Error = Error;

    fn try_from(value: library::Conversation) -> Result<Self, Error> {
        let duration = value.duration();
        Ok(Self {
            stream: value.stream,
            scope: value.scope.try_into()?,
            address_a: value.address_a,
            port_a: value.port_a,
            address_b: value.address_b,
            port_b: value.port_b,
            packets: value.packets.into(),
            versions: value.versions,
            versions_omitted: value.versions_omitted,
            negotiated: value.negotiated,
            negotiated_omitted: value.negotiated_omitted,
            initial_dcid_hex: value.initial_dcid.map(|bytes| compact_hex(&bytes)),
            initial_scid_hex: value.initial_scid.map(|bytes| compact_hex(&bytes)),
            first_timestamp: value.first_timestamp.try_into()?,
            last_timestamp: value.last_timestamp.try_into()?,
            duration,
        })
    }
}

/// Run totals across every conversation on the analyzed service ports.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub clock: Clock,
    pub frames_read: u64,
    pub frames_matched: u64,
    /// UDP conversations observed on the analyzed service ports, QUIC or not.
    pub conversations: u64,
    /// Conversations with at least one retained QUIC packet.
    pub quic_conversations: u64,
    pub packets: u64,
    pub malformed: u64,
    /// Service-port datagrams that never claimed the QUIC fixed bit.
    pub non_quic_datagrams: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_malformed: Option<&'static str>,
}

impl From<(library::Summary, &packetcraftr_core::analysis::Summary)> for Summary {
    fn from((summary, run): (library::Summary, &packetcraftr_core::analysis::Summary)) -> Self {
        Self {
            clock: run.clock.clone().into(),
            frames_read: run.frames_read,
            frames_matched: run.frames_matched,
            conversations: summary.conversations,
            quic_conversations: summary.quic_conversations,
            packets: summary.packets,
            malformed: summary.malformed,
            non_quic_datagrams: summary.non_quic_datagrams,
            first_malformed: summary.first_malformed,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Report {
    pub conversations: Vec<Conversation>,
    pub summary: Summary,
}

impl From<(Vec<Conversation>, Summary)> for Report {
    fn from((conversations, summary): (Vec<Conversation>, Summary)) -> Self {
        Self {
            conversations,
            summary,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Event {
    Conversation {
        #[serde(flatten)]
        conversation: Box<Conversation>,
    },
    Complete {
        #[serde(flatten)]
        summary: Box<Summary>,
    },
}

impl From<Conversation> for Event {
    fn from(conversation: Conversation) -> Self {
        Self::Conversation {
            conversation: Box::new(conversation),
        }
    }
}

impl From<Summary> for Event {
    fn from(summary: Summary) -> Self {
        Self::Complete {
            summary: Box::new(summary),
        }
    }
}

impl crate::output::stream::StreamRecord for Event {
    fn event_name(&self) -> &'static str {
        match self {
            Self::Conversation { .. } => "conversation",
            Self::Complete { .. } => "complete",
        }
    }
}

impl crate::output::stream::StreamRecord for Conversation {
    fn event_name(&self) -> &'static str {
        "conversation"
    }
}
