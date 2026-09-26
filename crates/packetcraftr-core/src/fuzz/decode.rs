// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::request::Limits;
use crate::frame::{Frame, LinkType};
use crate::{
    build::BuiltPacket,
    decode::{DecodedPacket, Dissector},
    diagnostic::Diagnostic,
    packet::Packet,
    protocol::BuiltinProtocol,
};

pub fn dissect_built(
    dissector: &Dissector,
    built: &BuiltPacket,
    limits: Limits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<DecodedPacket> {
    let Some(link_type) = packet_link_type(&built.packet) else {
        diagnostics.push(Diagnostic::info(
            "fuzz.decode_unavailable",
            "built root has no registered capture-link representation; exact bytes are retained",
        ));
        return None;
    };
    let frame = match Frame::new(std::time::UNIX_EPOCH, link_type, built.bytes.clone()) {
        Ok(frame) => frame,
        Err(source) => {
            diagnostics.push(Diagnostic::warning(
                "fuzz.decode_frame",
                format!(
                    "could not form bounded decode evidence: {}",
                    crate::error::render(&source)
                ),
            ));
            return None;
        }
    };
    match dissector.decode(
        frame,
        crate::decode::Options {
            max_packet_size: limits.max_packet_bytes,
            ..crate::decode::Options::default()
        },
    ) {
        Ok(decoded) => {
            diagnostics.extend_from_slice(&decoded.diagnostics);
            Some(decoded)
        }
        Err(source) => {
            diagnostics.push(Diagnostic::warning(
                "fuzz.decode_rejected",
                format!(
                    "bounded dissection rejected the built case: {}",
                    crate::error::render(&source)
                ),
            ));
            None
        }
    }
}

/// The link type recorded for a built packet, from its outermost layer.
pub fn packet_link_type(packet: &Packet) -> Option<LinkType> {
    LinkType::for_root_protocol(BuiltinProtocol::of(packet.layer(0)?)?)
}
