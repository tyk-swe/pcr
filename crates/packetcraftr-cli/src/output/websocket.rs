// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    analysis::analysis_complete, follow::PeerDirection, hex::compact_hex, stream::StreamRecord,
};
use packetcraftr_core::analysis::websocket as library;
use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Message {
        frame: u64,
        direction: PeerDirection,
        index: u64,
        opcode: u8,
        bytes_hex: String,
    },
    Control {
        frame: u64,
        direction: PeerDirection,
        opcode: u8,
        bytes_hex: String,
    },
    Issue {
        frame: u64,
        direction: PeerDirection,
        reason: String,
    },
}
impl From<library::Event> for Event {
    fn from(event: library::Event) -> Self {
        match event {
            library::Event::Message {
                number,
                direction,
                index,
                opcode,
                bytes,
            } => Self::Message {
                frame: number,
                direction: direction.into(),
                index,
                opcode,
                bytes_hex: compact_hex(&bytes),
            },
            library::Event::Control {
                number,
                direction,
                opcode,
                bytes,
            } => Self::Control {
                frame: number,
                direction: direction.into(),
                opcode,
                bytes_hex: compact_hex(&bytes),
            },
            library::Event::Issue {
                number,
                direction,
                reason,
            } => Self::Issue {
                frame: number,
                direction: direction.into(),
                reason,
            },
        }
    }
}
impl StreamRecord for Event {
    fn event_name(&self) -> &'static str {
        match self {
            Self::Message { .. } => "websocket_message",
            Self::Control { .. } => "websocket_control",
            Self::Issue { .. } => "websocket_issue",
        }
    }
}
#[derive(Debug, Serialize)]
pub struct Summary {
    pub messages: u64,
    pub control_frames: u64,
    pub incomplete_messages: u64,
    pub malformed_frames: u64,
    pub client_bytes: u64,
    pub server_bytes: u64,
    pub undelivered_bytes: u64,
}
impl From<library::Summary> for Summary {
    fn from(value: library::Summary) -> Self {
        Self {
            messages: value.messages,
            control_frames: value.control_frames,
            incomplete_messages: value.incomplete_messages,
            malformed_frames: value.malformed_frames,
            client_bytes: value.follow.client_bytes,
            server_bytes: value.follow.server_bytes,
            undelivered_bytes: value.follow.undelivered_bytes,
        }
    }
}
analysis_complete!(library::Summary);

#[derive(Debug, Serialize)]
pub struct Report {
    pub stream: u64,
    pub events: Vec<Event>,
    #[serde(flatten)]
    pub complete: Complete,
}
