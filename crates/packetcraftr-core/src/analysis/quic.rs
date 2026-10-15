// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded per-conversation QUIC packet analysis without decryption.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use serde::Serialize;

use super::application;
use super::conversation_index::CanonicalFlow;
use super::pipeline::{FrameRecord, Summary as RunSummary};
use super::reassembly::tcp::ScopedFlowKey;
use super::scope::Definition;
use super::session;
use crate::error::{Classification, Classified, Kind};
use crate::protocol::application::quic::{self, PacketType, Parsed};

/// UDP port always analyzed: QUIC's registered service port.
pub const DEFAULT_SERVICE_PORT: u16 = 443;

/// Distinct long-header versions retained per conversation before later ones
/// are only counted.
pub const MAX_CONVERSATION_VERSIONS: usize = 8;

/// Version-negotiation offers retained per conversation before later ones are
/// only counted.
pub const MAX_NEGOTIATED_VERSIONS: usize = 16;

/// Retention ceilings for one QUIC analysis pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Distinct UDP conversations the collector retains over the whole run.
    pub max_conversations: usize,
    /// Parsed QUIC packets charged across all conversations.
    pub max_packets: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_conversations: 4096,
            max_packets: 100_000,
        }
    }
}

impl Limits {
    /// Rejects a zero ceiling, which would refuse every conversation.
    pub fn validate(&self) -> Result<(), Error> {
        if self.max_conversations == 0 {
            return Err(Error::Limit {
                field: "max_conversations",
                limit: 0,
            });
        }
        if self.max_packets == 0 {
            return Err(Error::Limit {
                field: "max_packets",
                limit: 0,
            });
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Analysis(#[from] super::Error),
    #[error(transparent)]
    Ports(#[from] application::Error),
    #[error("quic analysis exceeds {field}={limit}")]
    Limit { field: &'static str, limit: u64 },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Analysis(source) => source.classification(),
            Self::Ports(source) => source.classification(),
            Self::Limit { .. } => Classification::new(
                "policy.quic_limit",
                Kind::Policy,
                Some("raise a finite quic analysis limit or narrow the capture"),
            ),
        }
    }
}

/// QUIC packets counted per conversation by header form.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PacketCounts {
    pub initial: u64,
    pub zero_rtt: u64,
    pub handshake: u64,
    pub retry: u64,
    pub version_negotiation: u64,
    pub one_rtt: u64,
    /// Datagrams that claimed the QUIC fixed bit but broke a wire rule.
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

/// One UDP conversation's retained QUIC evidence, ending at capture end.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Conversation {
    /// Capture-global `udp.stream` index; filters and selectors share it.
    pub stream: u64,
    pub scope: Definition,
    pub address_a: IpAddr,
    pub port_a: u16,
    pub address_b: IpAddr,
    pub port_b: u16,
    pub packets: PacketCounts,
    /// Distinct long-header versions in first-seen order, minus omissions.
    pub versions: Vec<u32>,
    pub versions_omitted: u64,
    /// Supported versions offered by version negotiation, in first-seen order.
    pub negotiated: Vec<u32>,
    pub negotiated_omitted: u64,
    /// The first Initial's destination connection ID, verbatim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_dcid: Option<Bytes>,
    /// The first Initial's source connection ID, verbatim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_scid: Option<Bytes>,
    pub first_timestamp: SystemTime,
    pub last_timestamp: SystemTime,
}

impl Conversation {
    pub fn duration(&self) -> Duration {
        self.last_timestamp
            .duration_since(self.first_timestamp)
            .unwrap_or(Duration::ZERO)
    }
}

/// Run totals across every conversation on the analyzed service ports.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
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

struct ConversationState {
    flow: CanonicalFlow,
    scope: Definition,
    packets: PacketCounts,
    versions: Vec<u32>,
    versions_omitted: u64,
    negotiated: Vec<u32>,
    negotiated_omitted: u64,
    initial_dcid: Option<Bytes>,
    initial_scid: Option<Bytes>,
    first_timestamp: SystemTime,
    last_timestamp: SystemTime,
}

/// Counts one parsed QUIC packet per UDP conversation.
pub struct Collector {
    ports: Vec<u16>,
    limits: Limits,
    conversations: BTreeMap<u64, ConversationState>,
    seen_streams: BTreeSet<u64>,
    packets: u64,
    malformed: u64,
    non_quic_datagrams: u64,
    first_malformed: Option<&'static str>,
}

impl Collector {
    /// `ports` always includes [`DEFAULT_SERVICE_PORT`].
    pub fn new(ports: Vec<u16>, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        let mut ports = ports;
        ports.push(DEFAULT_SERVICE_PORT);
        let ports = application::normalize_ports(ports, "quic_ports")?;
        Ok(Self {
            ports,
            limits,
            conversations: BTreeMap::new(),
            seen_streams: BTreeSet::new(),
            packets: 0,
            malformed: 0,
            non_quic_datagrams: 0,
            first_malformed: None,
        })
    }

    pub fn ports(&self) -> &[u16] {
        &self.ports
    }

    /// One matched frame. Events are retained and streamed at [`Collector::finish`],
    /// because a conversation stays open until the capture ends.
    pub fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Conversation>, Error> {
        let Some(view) = record.udp else {
            return Ok(Vec::new());
        };
        let Some(conversation) = view.conversation else {
            return Ok(Vec::new());
        };
        let flow = conversation.flow;
        if !self.ports.contains(&flow.flow.source_port)
            && !self.ports.contains(&flow.flow.destination_port)
        {
            return Ok(Vec::new());
        }
        self.seen_streams.insert(conversation.index);
        let payload = super::adapter::transport_payload(view.decoded, view.layer);
        if payload.is_empty() {
            self.non_quic_datagrams += 1;
            return Ok(Vec::new());
        }
        // Coalesced packets share one datagram: after each parsed packet the
        // covered length delimits the next one. A short header ends the walk,
        // because its connection ID length is connection state, not bytes.
        let mut rest = payload;
        let mut parsed_any = false;
        loop {
            match quic::parse(&rest) {
                Parsed::Packet(packet, covered) => {
                    if self.packets >= self.limits.max_packets {
                        return Err(Error::Limit {
                            field: "max_packets",
                            limit: self.limits.max_packets,
                        });
                    }
                    self.packets += 1;
                    self.record_packet(conversation.index, flow, record, &packet)?;
                    parsed_any = true;
                    if covered >= rest.len() {
                        break;
                    }
                    rest = rest.slice(covered..);
                }
                Parsed::NotQuic => {
                    if !parsed_any {
                        self.non_quic_datagrams += 1;
                    }
                    break;
                }
                Parsed::Malformed(reason) => {
                    self.malformed += 1;
                    self.first_malformed.get_or_insert(reason);
                    self.record_malformed(conversation.index, flow, record)?;
                    break;
                }
            }
        }
        Ok(Vec::new())
    }

    pub fn finish(self, _run: &RunSummary) -> Result<(Vec<Conversation>, Summary), Error> {
        let quic_conversations = self.conversations.len() as u64;
        let conversations = self
            .conversations
            .into_iter()
            .map(|(stream, state)| Conversation {
                stream,
                scope: state.scope,
                address_a: state.flow.first.0,
                port_a: state.flow.first.1,
                address_b: state.flow.second.0,
                port_b: state.flow.second.1,
                packets: state.packets,
                versions: state.versions,
                versions_omitted: state.versions_omitted,
                negotiated: state.negotiated,
                negotiated_omitted: state.negotiated_omitted,
                initial_dcid: state.initial_dcid,
                initial_scid: state.initial_scid,
                first_timestamp: state.first_timestamp,
                last_timestamp: state.last_timestamp,
            })
            .collect();
        let summary = Summary {
            conversations: self.seen_streams.len() as u64,
            quic_conversations,
            packets: self.packets,
            malformed: self.malformed,
            non_quic_datagrams: self.non_quic_datagrams,
            first_malformed: self.first_malformed,
        };
        Ok((conversations, summary))
    }

    fn state(
        &mut self,
        stream: u64,
        flow: &ScopedFlowKey,
        record: &FrameRecord<'_>,
    ) -> Result<&mut ConversationState, Error> {
        if !self.conversations.contains_key(&stream)
            && self.conversations.len() >= self.limits.max_conversations
        {
            return Err(Error::Limit {
                field: "max_conversations",
                limit: self.limits.max_conversations as u64,
            });
        }
        let timestamp = record.timestamp;
        Ok(self
            .conversations
            .entry(stream)
            .or_insert_with(|| ConversationState {
                flow: CanonicalFlow::from_flow(flow),
                scope: record
                    .scope_definition(flow.scope)
                    .expect("indexed scope exists")
                    .clone(),
                packets: PacketCounts::default(),
                versions: Vec::new(),
                versions_omitted: 0,
                negotiated: Vec::new(),
                negotiated_omitted: 0,
                initial_dcid: None,
                initial_scid: None,
                first_timestamp: timestamp,
                last_timestamp: timestamp,
            }))
    }

    fn record_packet(
        &mut self,
        stream: u64,
        flow: &ScopedFlowKey,
        record: &FrameRecord<'_>,
        packet: &quic::Quic,
    ) -> Result<(), Error> {
        let state = self.state(stream, flow, record)?;
        state.last_timestamp = record.timestamp;
        match packet.packet_type {
            PacketType::Initial => state.packets.initial += 1,
            PacketType::ZeroRtt => state.packets.zero_rtt += 1,
            PacketType::Handshake => state.packets.handshake += 1,
            PacketType::Retry => state.packets.retry += 1,
            PacketType::VersionNegotiation => state.packets.version_negotiation += 1,
            PacketType::OneRtt => state.packets.one_rtt += 1,
        }
        if packet.packet_type == PacketType::OneRtt {
            return Ok(());
        }
        if packet.version != 0 {
            push_bounded(
                &mut state.versions,
                &mut state.versions_omitted,
                packet.version,
                MAX_CONVERSATION_VERSIONS,
            );
        }
        for version in &packet.supported_versions {
            push_bounded(
                &mut state.negotiated,
                &mut state.negotiated_omitted,
                *version,
                MAX_NEGOTIATED_VERSIONS,
            );
        }
        if packet.packet_type == PacketType::Initial {
            state
                .initial_dcid
                .get_or_insert_with(|| packet.dcid.clone());
            state
                .initial_scid
                .get_or_insert_with(|| packet.scid.clone());
        }
        Ok(())
    }

    fn record_malformed(
        &mut self,
        stream: u64,
        flow: &ScopedFlowKey,
        record: &FrameRecord<'_>,
    ) -> Result<(), Error> {
        let state = self.state(stream, flow, record)?;
        state.last_timestamp = record.timestamp;
        state.packets.malformed += 1;
        Ok(())
    }
}

/// Retains `value` once, in first-seen order, up to `limit`; later distinct
/// values only raise the omission counter.
fn push_bounded(list: &mut Vec<u32>, omitted: &mut u64, value: u32, limit: usize) {
    if list.contains(&value) {
        return;
    }
    if list.len() >= limit {
        *omitted += 1;
    } else {
        list.push(value);
    }
}

impl session::Collector for Collector {
    type Event = Conversation;
    type Summary = Summary;

    fn needs(&self) -> session::CollectorNeeds {
        session::CollectorNeeds {
            udp_stream: true,
            ..session::CollectorNeeds::default()
        }
    }

    fn observe(
        &mut self,
        record: &FrameRecord<'_>,
    ) -> Result<Vec<Conversation>, crate::error::BoundaryError> {
        Self::observe(self, record).map_err(crate::error::BoundaryError::from_error)
    }

    fn finish(
        self,
        run: &RunSummary,
    ) -> Result<(Vec<Conversation>, Summary), crate::error::BoundaryError> {
        Self::finish(self, run).map_err(crate::error::BoundaryError::from_error)
    }
}
