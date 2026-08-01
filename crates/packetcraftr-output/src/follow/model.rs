// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use serde::Serialize;

use packetcraftr_analysis::follow::{Chunk, Direction, FollowSummary};

use super::super::common::compact_hex;
use super::super::expert::StreamTransport;

/// Who sent a chunk: the conversation's first captured sender is the
/// client, its peer the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FollowDirection {
    Client,
    Server,
}

impl From<Direction> for FollowDirection {
    fn from(value: Direction) -> Self {
        match value {
            Direction::ClientToServer => Self::Client,
            Direction::ServerToClient => Self::Server,
        }
    }
}

/// One conversation endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FollowEndpoint {
    pub address: IpAddr,
    pub port: u16,
}

/// One run of conversation payload, in delivery order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FollowChunk {
    pub direction: FollowDirection,
    /// Frame whose arrival delivered these bytes.
    pub frame: u64,
    pub bytes_hex: String,
}

impl From<Chunk> for FollowChunk {
    fn from(value: Chunk) -> Self {
        Self {
            direction: value.direction.into(),
            frame: value.number,
            bytes_hex: compact_hex(&value.bytes),
        }
    }
}

/// Aggregate result of `follow`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FollowCommandResult {
    pub transport: StreamTransport,
    pub stream: u64,
    /// Absent when the capture holds no frame of the conversation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<FollowEndpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<FollowEndpoint>,
    pub frames: u64,
    pub client_bytes: u64,
    pub server_bytes: u64,
    /// TCP bytes captured but stranded behind missing segments.
    pub undelivered_bytes: u64,
    pub chunks: Vec<FollowChunk>,
}

impl FollowCommandResult {
    pub fn from_summary(
        transport: StreamTransport,
        stream: u64,
        summary: FollowSummary,
        chunks: Vec<FollowChunk>,
    ) -> Self {
        let endpoint = |address: IpAddr, port: u16| FollowEndpoint { address, port };
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
        }
    }
}
