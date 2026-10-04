// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

mod common;

use common::packets::{ROOT_LINK_TYPE, rooted_registry};
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::layer::{Malformed, Raw};
use packetcraftr_core::protocol::link::{Eapol, Ethernet};
use packetcraftr_core::registry::Registry;
use packetcraftr_core::{build, codec, decode, field::WireValue, packet::Packet};

const STP_MULTICAST: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x00];
const LLDP_MULTICAST: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e];
const PAE_MULTICAST: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x03];
const SOURCE: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

/// Configuration BPDU: root and sending bridge priority 32768, path cost 4.
const CONFIG_BPDU: [u8; 35] = [
    0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x81, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x80, 0x80, 0x02, 0x00, 0x00, 0x14, 0x00, 0x02,
    0x00, 0x0f, 0x00,
];

const CHASSIS: [u8; 9] = [0x02, 0x07, 0x04, 0x02, 0, 0, 0, 0, 1];
const PORT: [u8; 4] = [0x04, 0x02, 0x07, b'1'];
const TTL: [u8; 4] = [0x06, 0x02, 0x00, 0x78];
const SYSTEM_NAME: [u8; 6] = [0x0a, 0x04, b'l', b'a', b'b', b'1'];
const ORG_SPECIFIC: [u8; 8] = [0xfe, 0x06, 0x12, 0x34, 0x56, 0x01, 0xaa, 0xbb];
const END: [u8; 2] = [0, 0];

fn frame(destination: [u8; 6], ether_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&destination);
    bytes.extend_from_slice(&SOURCE);
    bytes.extend_from_slice(&ether_type.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn pad_to_minimum_frame(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.len() < 60 {
        bytes.resize(60, 0);
    }
    bytes
}

fn dissect(registry: &Arc<Registry>, bytes: &[u8]) -> decode::DecodedPacket {
    let frame = Frame::new(
        SystemTime::UNIX_EPOCH,
        ROOT_LINK_TYPE,
        Bytes::copy_from_slice(bytes),
    )
    .expect("frame");
    decode::Dissector::new(Arc::clone(registry))
        .decode(frame, decode::Options::default())
        .expect("dissection preserves any bytes")
}

fn rebuild(
    registry: &Arc<Registry>,
    packet: Packet,
    mode: codec::Mode,
) -> Result<build::BuiltPacket, build::Error> {
    build::Builder::new(Arc::clone(registry)).build(
        packet,
        codec::Context::default(),
        build::Options {
            mode,
            ..build::Options::default()
        },
    )
}

fn layer_names(decoded: &decode::DecodedPacket) -> Vec<&str> {
    decoded
        .packet
        .iter()
        .map(|layer| layer.protocol_id().as_str())
        .collect()
}

fn diagnostic_codes(decoded: &decode::DecodedPacket) -> Vec<&'static str> {
    decoded
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code)
        .collect()
}

/// The bytes dissect, rebuild strictly to the same bytes, and report no
/// problems beyond the information-level padding note.
fn assert_exact_strict_round_trip(registry: &Arc<Registry>, bytes: &[u8]) -> decode::DecodedPacket {
    let decoded = dissect(registry, bytes);
    let rebuilt = rebuild(registry, decoded.packet.clone(), codec::Mode::Strict)
        .expect("a well-formed frame rebuilds strictly");
    assert_eq!(rebuilt.bytes.as_ref(), bytes);
    decoded
}

fn llc_frame(bpdu: &[u8]) -> Vec<u8> {
    let mut payload = vec![0x42, 0x42, 0x03];
    payload.extend_from_slice(bpdu);
    let length = u16::try_from(payload.len()).expect("802.3 length");
    pad_to_minimum_frame(frame(STP_MULTICAST, length, &payload))
}

#[test]
fn stp_truncated_bpdu_becomes_malformed_with_its_bytes() {
    let registry = rooted_registry("ethernet");
    let bytes = llc_frame(&CONFIG_BPDU[..34]);
    let decoded = dissect(&registry, &bytes);
    assert_eq!(
        layer_names(&decoded),
        ["ethernet", "llc", "malformed", "padding"]
    );
    let malformed = decoded.packet.get::<Malformed>().expect("malformed layer");
    assert_eq!(malformed.intended_protocol.as_deref(), Some("stp"));
    assert_eq!(malformed.bytes.as_ref(), &CONFIG_BPDU[..34]);
    assert!(diagnostic_codes(&decoded).contains(&"decode.malformed_layer"));
}

fn eap_identity_request() -> Vec<u8> {
    // EAP code 1 (Request), id 1, length 5, type 1 (Identity)
    vec![0x01, 0x01, 0x00, 0x05, 0x01]
}

#[test]
fn eapol_overrun_malformed_exact_length_strict() {
    let registry = rooted_registry("ethernet");
    let bytes = frame(PAE_MULTICAST, 0x888e, &[0x02, 0x00, 0x00, 0x20, 0x01, 0x01]);
    let decoded = dissect(&registry, &bytes);
    assert_eq!(layer_names(&decoded), ["ethernet", "malformed"]);
    let malformed = decoded.packet.get::<Malformed>().expect("malformed EAPOL");
    assert_eq!(malformed.intended_protocol.as_deref(), Some("eapol"));
    assert_eq!(
        malformed.bytes.as_ref(),
        [0x02, 0x00, 0x00, 0x20, 0x01, 0x01]
    );
    assert!(diagnostic_codes(&decoded).contains(&"decode.malformed_layer"));
    // Dissection has no strict mode: like PPPoE, the over-long frame is kept as a
    // malformed layer, and the rebuilt packet reports it so the live policy gate
    // (which refuses `contains_malformed()` packets) never transmits it.
    let rebuilt = rebuild(&registry, decoded.packet, codec::Mode::Strict).expect("bytes survive");
    assert_eq!(rebuilt.bytes.as_ref(), bytes);
    assert!(rebuilt.contains_malformed());

    let mut wrong = Packet::new();
    wrong.push(Ethernet {
        destination: PAE_MULTICAST,
        source: SOURCE,
        ..Ethernet::default()
    });
    wrong.push(Eapol {
        packet_type: 0,
        length: WireValue::Exact(9),
        ..Eapol::default()
    });
    wrong.push(Raw::new(eap_identity_request()));
    assert!(rebuild(&registry, wrong.clone(), codec::Mode::Strict).is_err());
    let permissive = rebuild(&registry, wrong, codec::Mode::Permissive)
        .expect("an exact wrong length builds permissively");
    assert_eq!(permissive.bytes[16..18], [0x00, 0x09]);
    assert!(
        permissive
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.field == Some("length"))
    );
}
