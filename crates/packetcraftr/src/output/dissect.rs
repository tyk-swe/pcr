// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured `dissect` output.

use bytes::Bytes;
use serde::Serialize;

use packetcraftr_core::{
    decode::DecodedPacket, diagnostic::Diagnostic, document::v2::Document, layout::PacketLayout,
};

use super::hex::compact_hex;

/// Structured result of `dissect`.
#[derive(Clone, Debug, Serialize)]
pub struct Result {
    #[serde(skip)]
    bytes: Bytes,
    pub bytes_hex: String,
    pub length: u64,
    pub link_type: u32,
    pub packet: Document,
    pub layout: PacketLayout,
}

impl Result {
    pub fn from_decoded(decoded: DecodedPacket) -> (Self, Vec<Diagnostic>) {
        let DecodedPacket {
            packet,
            original,
            frame,
            layout,
            diagnostics,
        } = decoded;
        (
            Self {
                bytes_hex: compact_hex(&original),
                length: u64::try_from(original.len()).unwrap_or(u64::MAX),
                link_type: frame.link_type.0,
                packet: Document::from_packet(&packet),
                layout,
                bytes: original,
            },
            diagnostics,
        )
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AggregateResult {
    matched: bool,
    dissection: Option<Result>,
}

impl AggregateResult {
    pub fn from_filter(matched: bool, dissection: Result) -> Self {
        Self {
            matched,
            dissection: matched.then_some(dissection),
        }
    }
}
