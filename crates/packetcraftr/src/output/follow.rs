// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured conversation-following output.

use std::net::IpAddr;

use serde::Serialize;

use packetcraftr_core::analysis::follow::{Chunk as AnalysisChunk, Direction as AnalysisDirection};

use super::expert::StreamTransport;
use super::hex::compact_hex;

mirror_enum! {
    /// Who sent a chunk: the conversation's first captured sender is the
    /// client, its peer the server.
    #[serde(rename_all = "snake_case")]
    pub enum Direction from AnalysisDirection {
        Client = ClientToServer,
        Server = ServerToClient,
    }
}

pub use super::network::Endpoint;

/// One run of conversation payload, in delivery order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Chunk {
    pub direction: Direction,
    /// Frame whose arrival delivered these bytes.
    pub frame: u64,
    pub bytes_hex: String,
}

impl From<AnalysisChunk> for Chunk {
    fn from(value: AnalysisChunk) -> Self {
        Self {
            direction: value.direction.into(),
            frame: value.number,
            bytes_hex: compact_hex(&value.bytes),
        }
    }
}

/// Aggregate result of `follow`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub transport: StreamTransport,
    pub stream: u64,
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
    pub ip_reassembly: super::reassembly::Report,
}

impl Report {
    #[must_use]
    pub fn from_summary(
        transport: StreamTransport,
        stream: u64,
        summary: packetcraftr_core::analysis::follow::Summary,
        chunks: Vec<Chunk>,
        ip_reassembly: &packetcraftr_core::analysis::IpReassemblyReport,
    ) -> Self {
        let endpoint = |address: IpAddr, port: u16| Endpoint { address, port };
        let (client, server) = match &summary.client_flow {
            Some(flow) => (
                Some(endpoint(flow.source, flow.source_port)),
                Some(endpoint(flow.destination, flow.destination_port)),
            ),
            None => (None, None),
        };
        Self {
            transport,
            stream,
            client,
            server,
            frames: summary.frames,
            client_bytes: summary.client_bytes,
            server_bytes: summary.server_bytes,
            undelivered_bytes: summary.undelivered_bytes,
            chunks,
            ip_reassembly: super::reassembly::Report::from_analysis(ip_reassembly),
        }
    }
}
