//! Structured `build` output.

use bytes::Bytes;
use serde::Serialize;

use crate::packet::{
    build::BuiltPacket, diagnostic::Diagnostic, document::PacketDocument, layout::PacketLayout,
};

use super::common::compact_hex;

/// Structured result of `build`.
#[derive(Clone, Debug, Serialize)]
pub struct Result {
    #[serde(skip)]
    bytes: Bytes,
    pub bytes_hex: String,
    pub length: u64,
    pub packet: PacketDocument,
    pub layout: PacketLayout,
    pub requires_live_opt_in: bool,
}

impl Result {
    pub fn from_built(built: BuiltPacket) -> (Self, Vec<Diagnostic>) {
        let BuiltPacket {
            bytes,
            packet,
            layout,
            diagnostics,
            requires_live_opt_in,
        } = built;
        (
            Self {
                bytes_hex: compact_hex(&bytes),
                length: bytes.len() as u64,
                packet: PacketDocument::from_packet(&packet),
                layout,
                requires_live_opt_in,
                bytes,
            },
            diagnostics,
        )
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
