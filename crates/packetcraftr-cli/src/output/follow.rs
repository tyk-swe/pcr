// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use packetcraftr_core::analysis::{self as library, follow};

use super::analysis::{Clock, Endpoint, Scope, StreamTransport};
use super::contract::Error;
use super::hex::compact_hex;

/// Which peer of a conversation sent a run of payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum PeerDirection {
    #[serde(rename = "client")]
    ClientToServer,
    #[serde(rename = "server")]
    ServerToClient,
}

impl From<follow::PeerDirection> for PeerDirection {
    fn from(value: follow::PeerDirection) -> Self {
        match value {
            follow::PeerDirection::ClientToServer => Self::ClientToServer,
            follow::PeerDirection::ServerToClient => Self::ServerToClient,
        }
    }
}

/// One run of conversation payload, in delivery order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Chunk {
    pub direction: PeerDirection,
    pub direction_generation: u64,
    /// Frame whose arrival delivered these bytes.
    pub frame: u64,
    pub bytes_hex: String,
}

impl From<follow::Chunk> for Chunk {
    fn from(value: follow::Chunk) -> Self {
        Self {
            direction: value.direction.into(),
            direction_generation: value.direction_generation,
            frame: value.number,
            bytes_hex: compact_hex(&value.bytes),
        }
    }
}

/// One direction payload file `follow --write` published.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WrittenFile {
    pub direction: PeerDirection,
    pub path: String,
    pub bytes: u64,
}

/// A published direction file: its direction, path, and byte count.
impl From<(follow::PeerDirection, String, u64)> for WrittenFile {
    fn from((direction, path, bytes): (follow::PeerDirection, String, u64)) -> Self {
        Self {
            direction: direction.into(),
            path,
            bytes,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub clock: Clock,
    pub transport: StreamTransport,
    pub stream: u64,
    pub scope: Option<Scope>,
    /// Absent when the capture holds no frame of the conversation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<Endpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<Endpoint>,
    pub frames: u64,
    pub client_bytes: u64,
    pub server_bytes: u64,
    /// TCP bytes captured but stranded behind missing segments.
    pub undelivered_bytes: u64,
    pub chunks: Vec<Chunk>,
    /// Files `--write` published, in deterministic publish order.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub written: Vec<WrittenFile>,
    pub ip_reassembly: super::reassembly::Report,
}

/// One followed conversation: its selector, summary, the chunks retained for
/// the document, the capture's IP reassembly, and the files `--write`
/// published.
impl
    TryFrom<(
        library::StreamRef,
        follow::Summary,
        Vec<Chunk>,
        &library::IpReassemblyReport,
        Vec<WrittenFile>,
    )> for Report
{
    type Error = Error;

    fn try_from(
        (selector, summary, chunks, ip_reassembly, written): (
            library::StreamRef,
            follow::Summary,
            Vec<Chunk>,
            &library::IpReassemblyReport,
            Vec<WrittenFile>,
        ),
    ) -> Result<Self, Error> {
        let endpoint = |address, port| Endpoint { address, port };
        let (client, server) = match &summary.client_flow {
            Some(flow) => (
                Some(endpoint(flow.source, flow.source_port)),
                Some(endpoint(flow.destination, flow.destination_port)),
            ),
            None => (None, None),
        };
        Ok(Self {
            clock: summary.clock.into(),
            transport: selector.transport.into(),
            stream: selector.index,
            client,
            server,
            scope: summary.scope.map(Scope::try_from).transpose()?,
            frames: summary.frames,
            client_bytes: summary.client_bytes,
            server_bytes: summary.server_bytes,
            undelivered_bytes: summary.undelivered_bytes,
            chunks,
            written,
            ip_reassembly: ip_reassembly.into(),
        })
    }
}

impl crate::output::stream::StreamRecord for Chunk {
    fn event_name(&self) -> &'static str {
        "chunk"
    }
}
