// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::packets::{ROOT_LINK_TYPE, rooted_registry};
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::layer::{Malformed, Padding, Raw};
use packetcraftr_core::protocol::capture::{LinuxSll, LinuxSll2};
use packetcraftr_core::protocol::link::{Eapol, Ethernet, Llc, Lldp, Snap, Stp, Vlan, Vlan8021ad};
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
fn stp_config_bpdu_decodes_typed_and_keeps_ethernet_padding_outside_it() {
    let registry = rooted_registry("ethernet");
    let bytes = llc_frame(&CONFIG_BPDU);
    assert_eq!(bytes.len(), 60);

    let decoded = assert_exact_strict_round_trip(&registry, &bytes);
    assert_eq!(layer_names(&decoded), ["ethernet", "llc", "stp", "padding"]);
    assert!(
        decoded
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.code == "decode.trailing_padding")
    );
    let stp = decoded.packet.get::<Stp>().expect("typed BPDU");
    assert_eq!((stp.root_priority, stp.root_extension), (8, 2));
    assert_eq!(stp.root_mac, [0, 0, 0, 0, 0x01, 0]);
    assert_eq!((stp.bridge_priority, stp.bridge_extension), (8, 0x102));
    assert_eq!(stp.bridge_mac, [0, 0, 0, 0, 0x02, 0x80]);
    assert_eq!(stp.root_path_cost, 4);
    assert_eq!(stp.port_id, 0x8002);
    assert_eq!(
        (stp.max_age, stp.hello_time, stp.forward_delay),
        (0x1400, 0x0200, 0x0f00)
    );
    assert!(stp.topology_change && !stp.topology_change_ack);
    let padding = decoded
        .packet
        .get::<Padding>()
        .expect("minimum-frame bytes");
    assert_eq!((padding.bytes.len(), padding.outside_layer), (8, Some(0)));
}

#[test]
fn stp_bpdus_built_from_layers_match_the_wire_image() {
    let registry = rooted_registry("ethernet");
    let mut packet = Packet::new();
    packet.push(Ethernet {
        destination: STP_MULTICAST,
        source: SOURCE,
        ..Ethernet::default()
    });
    packet.push(Llc {
        dsap: 0x42,
        ssap: 0x42,
        ..Llc::default()
    });
    packet.push(Stp {
        topology_change: true,
        root_extension: 2,
        root_mac: [0, 0, 0, 0, 0x01, 0],
        root_path_cost: 4,
        bridge_extension: 0x102,
        bridge_mac: [0, 0, 0, 0, 0x02, 0x80],
        port_id: 0x8002,
        ..Stp::default()
    });
    let built = rebuild(&registry, packet, codec::Mode::Strict).expect("BPDU builds strictly");
    assert_eq!(built.bytes.as_ref(), llc_frame(&CONFIG_BPDU)[..52].to_vec());
    assert!(built.diagnostics.is_empty(), "{:?}", built.diagnostics);
}

#[test]
fn stp_tcn_and_rst_bpdus_round_trip_byte_for_byte() {
    let registry = rooted_registry("ethernet");

    let tcn = llc_frame(&[0, 0, 0, 0x80]);
    let decoded = assert_exact_strict_round_trip(&registry, &tcn);
    assert_eq!(layer_names(&decoded), ["ethernet", "llc", "stp", "padding"]);
    assert_eq!(
        decoded.packet.get::<Stp>().map(|stp| stp.bpdu_type),
        Some(0x80)
    );

    let mut rst = CONFIG_BPDU.to_vec();
    rst[2] = 2;
    rst[3] = 2;
    rst[4] = 0x7e;
    rst.push(0);
    let bytes = llc_frame(&rst);
    let decoded = assert_exact_strict_round_trip(&registry, &bytes);
    assert_eq!(layer_names(&decoded), ["ethernet", "llc", "stp", "padding"]);
    let stp = decoded.packet.get::<Stp>().expect("typed RST BPDU");
    assert_eq!(stp.port_role, 3);
    assert!(stp.proposal && stp.learning && stp.forwarding);
    assert!(
        decoded
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.code == "decode.trailing_padding")
    );
}

#[test]
fn stp_bytes_after_the_bpdu_inside_the_llc_length_stay_padding() {
    let registry = rooted_registry("ethernet");
    let mut bpdu = CONFIG_BPDU.to_vec();
    bpdu.extend_from_slice(&[0xab; 3]);
    let bytes = llc_frame(&bpdu);
    let decoded = assert_exact_strict_round_trip(&registry, &bytes);
    let paddings: Vec<_> = decoded
        .packet
        .iter()
        .filter_map(|layer| layer.downcast_ref::<Padding>())
        .map(|padding| (padding.outside_layer, padding.bytes.len()))
        .collect();
    assert_eq!(paddings, [(Some(2), 3), (Some(0), 5)]);
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

#[test]
fn stp_rst_with_version_zero_and_reserved_bits_fails_a_strict_build_only() {
    let registry = rooted_registry("ethernet");
    let mut rst = CONFIG_BPDU.to_vec();
    rst[3] = 2;
    rst[4] = 0x02;
    rst.push(0);
    let bytes = llc_frame(&rst);
    let decoded = dissect(&registry, &bytes);
    let codes = diagnostic_codes(&decoded);
    assert!(codes.contains(&"decode.stp_version"), "{codes:?}");
    assert!(codes.contains(&"decode.stp_reserved"), "{codes:?}");

    assert!(rebuild(&registry, decoded.packet.clone(), codec::Mode::Strict).is_err());
    let permissive = rebuild(&registry, decoded.packet, codec::Mode::Permissive)
        .expect("permissive builds keep noncanonical fields");
    assert_eq!(permissive.bytes.as_ref(), bytes);
    let build_codes: Vec<_> = permissive
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code)
        .filter(|code| code.starts_with("build.stp_"))
        .collect();
    assert_eq!(build_codes, ["build.stp_version", "build.stp_reserved"]);
}

#[test]
fn stp_under_a_vlan_tag_builds_and_dissects() {
    let registry = rooted_registry("ethernet");
    let mut packet = Packet::new();
    packet.push(Ethernet {
        destination: STP_MULTICAST,
        source: SOURCE,
        ..Ethernet::default()
    });
    packet.push(Vlan {
        vlan_id: 100,
        ..Vlan::default()
    });
    packet.push(Llc {
        dsap: 0x42,
        ssap: 0x42,
        ..Llc::default()
    });
    packet.push(Stp::default());
    let built = rebuild(&registry, packet, codec::Mode::Strict).expect("tagged BPDU builds");
    let decoded = assert_exact_strict_round_trip(&registry, &built.bytes);
    assert_eq!(layer_names(&decoded), ["ethernet", "vlan", "llc", "stp"]);
    assert_eq!(decoded.packet.get::<Stp>(), Some(&Stp::default()));
}

#[test]
fn stp_unknown_bpdu_type_keeps_its_bytes_and_needs_permissive_mode_to_rebuild() {
    let registry = rooted_registry("ethernet");
    let bytes = llc_frame(&[0, 0, 0, 0x7f, 0xde, 0xad]);
    let decoded = dissect(&registry, &bytes);
    assert_eq!(layer_names(&decoded)[..3], ["ethernet", "llc", "stp"]);
    assert!(diagnostic_codes(&decoded).contains(&"decode.stp_bpdu_type"));

    assert!(rebuild(&registry, decoded.packet.clone(), codec::Mode::Strict).is_err());
    let permissive = rebuild(&registry, decoded.packet, codec::Mode::Permissive)
        .expect("permissive builds keep unknown types");
    assert_eq!(permissive.bytes.as_ref(), bytes);
}

#[test]
fn lldp_frame_round_trips_verbatim_and_keeps_unknown_tlvs() {
    let registry = rooted_registry("ethernet");
    let mut payload = Vec::new();
    for tlv in [&CHASSIS[..], &PORT, &TTL, &SYSTEM_NAME, &ORG_SPECIFIC, &END] {
        payload.extend_from_slice(tlv);
    }
    let bytes = frame(LLDP_MULTICAST, 0x88cc, &payload);
    let decoded = assert_exact_strict_round_trip(&registry, &bytes);
    assert_eq!(layer_names(&decoded), ["ethernet", "lldp"]);
    assert!(decoded.diagnostics.is_empty(), "{:?}", decoded.diagnostics);
    let lldp = decoded.packet.get::<Lldp>().expect("typed LLDP");
    assert_eq!(lldp.tlvs.as_ref(), payload);
    assert!(lldp.trailing.is_empty());
    let types: Vec<_> = lldp.tlv_iter().map(|(kind, _)| kind).collect();
    assert_eq!(types, [1, 2, 3, 5, 127]);
    assert_eq!(
        lldp.tlv_iter().last().map(|(_, value)| value),
        Some(&ORG_SPECIFIC[2..])
    );
}

#[test]
fn lldp_bytes_after_the_end_tlv_are_trailing_data() {
    let registry = rooted_registry("ethernet");
    let mut payload = [&CHASSIS[..], &PORT, &TTL, &END].concat();
    let chain_len = payload.len();
    payload.extend_from_slice(&[0; 20]);
    let bytes = frame(LLDP_MULTICAST, 0x88cc, &payload);
    let decoded = assert_exact_strict_round_trip(&registry, &bytes);
    assert_eq!(layer_names(&decoded), ["ethernet", "lldp"]);
    let lldp = decoded.packet.get::<Lldp>().expect("typed LLDP");
    assert_eq!(lldp.tlvs.len(), chain_len);
    assert_eq!(lldp.trailing.as_ref(), [0; 20]);
}

#[test]
fn lldp_is_dissected_under_a_vlan_tag() {
    let registry = rooted_registry("ethernet");
    let mut packet = Packet::new();
    packet.push(Ethernet {
        destination: LLDP_MULTICAST,
        source: SOURCE,
        ..Ethernet::default()
    });
    packet.push(Vlan {
        vlan_id: 100,
        ..Vlan::default()
    });
    packet.push(Lldp::default());
    let built = rebuild(&registry, packet, codec::Mode::Strict).expect("tagged LLDP builds");
    assert_eq!(built.bytes[12..14], [0x81, 0x00]);
    assert_eq!(built.bytes[16..18], [0x88, 0xcc]);

    let decoded = assert_exact_strict_round_trip(&registry, &built.bytes);
    assert_eq!(layer_names(&decoded), ["ethernet", "vlan", "lldp"]);
}

#[test]
fn lldp_is_bound_under_every_link_parent_that_carries_ether_types() {
    type Stack = Vec<Box<dyn packetcraftr_core::layer::Layer>>;
    let ethernet = || Ethernet {
        destination: LLDP_MULTICAST,
        source: SOURCE,
        ..Ethernet::default()
    };
    let cases: [(&str, &str, Stack, &[&str]); 5] = [
        (
            "qinq",
            "ethernet",
            vec![
                Box::new(ethernet()),
                Box::new(Vlan8021ad::default()),
                Box::new(Lldp::default()),
            ],
            &["ethernet", "vlan8021ad", "lldp"],
        ),
        (
            "snap",
            "ethernet",
            vec![
                Box::new(ethernet()),
                Box::new(Llc::default()),
                Box::new(Snap {
                    protocol_id: WireValue::Exact(0x88cc),
                    ..Snap::default()
                }),
                Box::new(Lldp::default()),
            ],
            &["ethernet", "llc", "snap", "lldp"],
        ),
        (
            "linux_sll",
            "linux_sll",
            vec![Box::new(LinuxSll::default()), Box::new(Lldp::default())],
            &["linux_sll", "lldp"],
        ),
        (
            "linux_sll2",
            "linux_sll2",
            vec![Box::new(LinuxSll2::default()), Box::new(Lldp::default())],
            &["linux_sll2", "lldp"],
        ),
        (
            "vlan",
            "ethernet",
            vec![
                Box::new(ethernet()),
                Box::new(Vlan::default()),
                Box::new(Lldp::default()),
            ],
            &["ethernet", "vlan", "lldp"],
        ),
    ];
    for (name, root, layers, expected) in cases {
        let registry = rooted_registry(root);
        let mut packet = Packet::new();
        for layer in layers {
            packet.push_boxed(layer);
        }
        let built = rebuild(&registry, packet, codec::Mode::Strict).expect(name);
        let decoded = dissect(&registry, &built.bytes);
        assert_eq!(layer_names(&decoded), expected, "{name}");
        assert_eq!(
            decoded.packet.get::<Lldp>(),
            Some(&Lldp::default()),
            "{name}"
        );
    }
}

#[test]
fn lldp_structure_problems_are_diagnostics_and_never_read_past_the_slice() {
    let registry = rooted_registry("ethernet");
    let cases: [(&str, Vec<u8>, &str); 3] = [
        (
            "9-bit length overrunning the frame",
            [&CHASSIS[..], &PORT, &TTL, &[0x0d, 0xff, 1, 2, 3]].concat(),
            "lldp_truncated_tlv",
        ),
        (
            "Port ID before Chassis ID",
            [&PORT[..], &CHASSIS, &TTL, &END].concat(),
            "lldp_mandatory_order",
        ),
        (
            "no End of LLDPDU TLV",
            [&CHASSIS[..], &PORT, &TTL].concat(),
            "lldp_missing_end",
        ),
    ];
    for (name, payload, code) in cases {
        let bytes = frame(LLDP_MULTICAST, 0x88cc, &payload);
        let decoded = dissect(&registry, &bytes);
        assert_eq!(layer_names(&decoded), ["ethernet", "lldp"], "{name}");
        assert_eq!(
            decoded
                .packet
                .get::<Lldp>()
                .map(|lldp| lldp.tlvs.as_ref().to_vec()),
            Some(payload),
            "{name}"
        );
        let expected = format!("decode.{code}");
        assert!(
            decoded
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == expected),
            "{name}: {:?}",
            decoded.diagnostics
        );

        assert!(
            rebuild(&registry, decoded.packet.clone(), codec::Mode::Strict).is_err(),
            "{name}"
        );
        let permissive = rebuild(&registry, decoded.packet, codec::Mode::Permissive).expect(name);
        assert_eq!(permissive.bytes.as_ref(), bytes, "{name}");
    }
}

#[test]
fn lldp_tlv_iterator_stops_at_the_first_malformed_tlv() {
    let lldp = Lldp {
        tlvs: Bytes::from([&CHASSIS[..], &PORT, &[0x0d, 0xff, 1]].concat()),
        trailing: Bytes::new(),
    };
    assert_eq!(
        lldp.tlv_iter().map(|(kind, _)| kind).collect::<Vec<_>>(),
        [1, 2]
    );
    let empty = Lldp {
        tlvs: Bytes::new(),
        trailing: Bytes::new(),
    };
    assert_eq!(empty.tlv_iter().count(), 0);
}

fn eap_identity_request() -> Vec<u8> {
    // EAP code 1 (Request), id 1, length 5, type 1 (Identity)
    vec![0x01, 0x01, 0x00, 0x05, 0x01]
}

#[test]
fn eapol_eap_packet_decodes_with_a_raw_body_and_recomputes_auto_length() {
    let registry = rooted_registry("ethernet");
    let body = eap_identity_request();
    let mut payload = vec![0x02, 0x00, 0x00, 0x05];
    payload.extend_from_slice(&body);
    let bytes = pad_to_minimum_frame(frame(PAE_MULTICAST, 0x888e, &payload));

    let decoded = assert_exact_strict_round_trip(&registry, &bytes);
    assert_eq!(
        layer_names(&decoded),
        ["ethernet", "eapol", "raw", "padding"]
    );
    assert_eq!(
        decoded
            .packet
            .get::<Raw>()
            .map(|raw| raw.bytes.as_ref().to_vec()),
        Some(body)
    );

    let mut edited = decoded.packet;
    edited.get_mut::<Eapol>().expect("typed EAPOL").length = WireValue::Auto;
    edited.get_mut::<Raw>().expect("body").bytes = Bytes::from_static(&[1, 2, 0, 6, 1, b'x']);
    let rebuilt = rebuild(&registry, edited, codec::Mode::Strict).expect("edited body builds");
    assert_eq!(rebuilt.bytes[14..18], [0x02, 0x00, 0x00, 0x06]);
    assert_eq!(rebuilt.bytes[18..24], [1, 2, 0, 6, 1, b'x']);
}

#[test]
fn eapol_start_keeps_ethernet_padding_out_of_the_body() {
    let registry = rooted_registry("ethernet");
    let mut bytes = frame(PAE_MULTICAST, 0x888e, &[0x02, 0x01, 0x00, 0x00]);
    bytes.extend_from_slice(&[0; 42]);
    assert_eq!(bytes.len(), 60);

    let decoded = assert_exact_strict_round_trip(&registry, &bytes);
    assert_eq!(layer_names(&decoded), ["ethernet", "eapol", "padding"]);
    let padding = decoded.packet.get::<Padding>().expect("padding");
    assert_eq!((padding.bytes.len(), padding.outside_layer), (42, Some(1)));
    assert_eq!(
        decoded
            .packet
            .get::<Eapol>()
            .map(|eapol| eapol.length.clone()),
        Some(WireValue::Exact(0))
    );
}

#[test]
fn eapol_length_past_the_frame_is_malformed_and_exact_lengths_need_strict_agreement() {
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
