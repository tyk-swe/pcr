// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded decode evidence and capture-link helpers.

use crate::frame::{Frame, LinkType};
use crate::{
    Packet,
    build::BuiltPacket,
    decode::{DecodedPacket, Dissector},
    diagnostic::Diagnostic,
    semantics::BuiltinProtocol,
};

pub(in crate::fuzz) fn dissect_built(
    dissector: &Dissector,
    built: &BuiltPacket,
    limits: super::super::request::Limits,
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
                format!("could not form bounded decode evidence: {source}"),
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
                format!("bounded dissection rejected the built case: {source}"),
            ));
            None
        }
    }
}

fn packet_link_type(packet: &Packet) -> Option<LinkType> {
    Some(match BuiltinProtocol::of(packet.layer(0)?)? {
        BuiltinProtocol::Ethernet => LinkType::ETHERNET,
        BuiltinProtocol::BsdNull => LinkType::NULL,
        BuiltinProtocol::BsdLoop => LinkType::LOOP,
        BuiltinProtocol::LinuxSll => LinkType::LINUX_SLL,
        BuiltinProtocol::LinuxSll2 => LinkType::LINUX_SLL2,
        BuiltinProtocol::Ipv4 => LinkType::IPV4,
        BuiltinProtocol::Ipv6 => LinkType::IPV6,
        BuiltinProtocol::RawIp => LinkType::RAW,
        _ => return None,
    })
}
