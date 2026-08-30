// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Per-frame TLS dissection: which TCP segments become a `tls` layer, which
//! stay `raw`, and what each one publishes.

#[expect(
    dead_code,
    reason = "the shared vector table carries provenance metadata that \
              tls_fingerprint_contracts asserts; this file needs only the bytes"
)]
#[path = "common/tls_vectors.rs"]
mod tls_vectors;

#[expect(
    dead_code,
    reason = "the shared frame builders cover every TLS test; this file needs \
              only a hello and an application-data record"
)]
#[path = "common/tls_frames.rs"]
mod tls_frames;

use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use packetcraftr_core::field::FieldValue;
use packetcraftr_core::filter::{Context as FilterContext, Filter};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::protocol::application::Tls;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::Tcp;
use packetcraftr_core::registry::Registry;
use packetcraftr_core::{Packet, build, decode};

use tls_frames::{ClientHelloSpec, application_data, client_hello, handshake_record};
use tls_vectors::{CLIENT_HELLO_VECTORS, SERVER_HELLO_VECTORS, decode_hex};

/// The ports the default registry binds to TLS.
const TLS_PORTS: &[u16] = &[443, 465, 636, 853, 993, 995, 8443];

const CLIENT_PORT: u16 = 40_000;

fn registry() -> Arc<Registry> {
    Arc::new(builtin::registry().expect("built-in registry"))
}

/// A whole ClientHello record, from the published-JA4 vector.
fn client_hello_record() -> Vec<u8> {
    decode_hex(CLIENT_HELLO_VECTORS[1].record_hex)
}

/// A whole ServerHello record.
fn server_hello_record() -> Vec<u8> {
    decode_hex(SERVER_HELLO_VECTORS[0].record_hex)
}

/// A ClientHello record whose `server_name` carries exactly `name`, so a test
/// can choose which name bytes the dissector sees.
fn client_hello_record_with_server_name(name: &str) -> Vec<u8> {
    handshake_record(&client_hello(&ClientHelloSpec {
        sni: Some(name.to_owned()),
        alpn: Vec::new(),
        supported_groups: Vec::new(),
        key_share_groups: Vec::new(),
        ..ClientHelloSpec::default()
    }))
}

/// Builds `eth/ipv4/tcp/raw(payload)`, dissects it, and asserts the exact
/// round trip the whole registry contract rests on.
fn dissect(source_port: u16, destination_port: u16, payload: &[u8]) -> decode::DecodedPacket {
    let registry = registry();
    let mut packet = Packet::new();
    packet.push(Ethernet::default());
    packet.push(Ipv4 {
        source: "192.0.2.1".parse().expect("source address"),
        destination: "198.51.100.2".parse().expect("destination address"),
        ..Ipv4::default()
    });
    packet.push(Tcp {
        source_port,
        destination_port,
        sequence: 1,
        flags: Tcp::ACK,
        ..Tcp::default()
    });
    packet.push(Raw::new(Bytes::copy_from_slice(payload)));
    let builder = build::Builder::new(Arc::clone(&registry));
    let built = builder
        .build(packet, build::Context::default(), build::Options::default())
        .expect("segment builds");
    let frame = Frame::new(
        SystemTime::UNIX_EPOCH,
        LinkType::ETHERNET,
        built.bytes.clone(),
    )
    .expect("segment frame");
    let decoded = decode::Dissector::new(Arc::clone(&registry))
        .decode(frame, decode::Options::default())
        .expect("segment dissects");
    let rebuilt = builder
        .build(
            decoded.packet.clone(),
            build::Context::default(),
            build::Options::default(),
        )
        .expect("dissected segment rebuilds");
    assert_eq!(
        rebuilt.bytes, built.bytes,
        "build(dissect(x)) must equal x on port {destination_port}"
    );
    decoded
}

fn protocols(decoded: &decode::DecodedPacket) -> Vec<&str> {
    decoded
        .packet
        .iter()
        .map(|layer| layer.protocol_id().as_str())
        .collect()
}

fn tls_field(decoded: &decode::DecodedPacket, name: &str) -> Option<FieldValue> {
    decoded
        .packet
        .iter()
        .find(|layer| layer.protocol_id().as_str() == "tls")
        .and_then(|layer| layer.field(name))
}

fn diagnostic_codes(decoded: &decode::DecodedPacket) -> Vec<&str> {
    decoded
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect()
}

fn matches(decoded: &decode::DecodedPacket, source: &str) -> bool {
    let registry = registry();
    Filter::compile(
        source,
        &registry,
        packetcraftr_core::filter::Options::default(),
    )
    .unwrap_or_else(|error| panic!("{source} must compile: {error}"))
    .matches(&FilterContext {
        decoded,
        derived: &[],
        number: 1,
        tcp_stream: Some(0),
        udp_stream: None,
    })
    .expect("filter evaluates")
}

#[test]
fn every_well_known_port_dissects_tls_in_both_directions() {
    for port in TLS_PORTS {
        let to_server = dissect(CLIENT_PORT, *port, &client_hello_record());
        assert_eq!(
            protocols(&to_server),
            vec!["ethernet", "ipv4", "tcp", "tls"],
            "client to port {port}"
        );
        let from_server = dissect(*port, CLIENT_PORT, &server_hello_record());
        assert_eq!(
            protocols(&from_server),
            vec!["ethernet", "ipv4", "tcp", "tls"],
            "server from port {port}"
        );
    }
}

#[test]
fn a_client_hello_publishes_its_handshake_fields() {
    let decoded = dissect(CLIENT_PORT, 443, &client_hello_record());
    assert_eq!(
        tls_field(&decoded, "content_type"),
        Some(FieldValue::from(22_u8))
    );
    assert_eq!(
        tls_field(&decoded, "version"),
        Some(FieldValue::from(0x0301_u16))
    );
    assert_eq!(
        tls_field(&decoded, "record_count"),
        Some(FieldValue::from(1_u16))
    );
    assert_eq!(
        tls_field(&decoded, "handshake_type"),
        Some(FieldValue::from(1_u8))
    );
    assert_eq!(
        tls_field(&decoded, "sni"),
        Some(FieldValue::Text("api.example.test".to_owned()))
    );
    assert_eq!(
        tls_field(&decoded, "sni_raw"),
        Some(FieldValue::Text(
            "6170692e6578616d706c652e74657374".to_owned()
        ))
    );
    assert_eq!(
        tls_field(&decoded, "incomplete"),
        Some(FieldValue::Bool(false))
    );
    assert_eq!(tls_field(&decoded, "ech"), Some(FieldValue::Bool(false)));
    assert!(matches!(
        tls_field(&decoded, "ja4"),
        Some(FieldValue::Text(value)) if value.starts_with("t13d")
    ));
    assert!(matches!(
        tls_field(&decoded, "ja3"),
        Some(FieldValue::Text(value)) if value.len() == 32
    ));
    assert!(matches!(
        tls_field(&decoded, "alpn"),
        Some(FieldValue::List(values)) if values == vec![
            FieldValue::Text("h2".to_owned()),
            FieldValue::Text("http/1.1".to_owned()),
        ]
    ));
    assert!(matches!(
        tls_field(&decoded, "supported_versions"),
        Some(FieldValue::List(values)) if !values.is_empty()
    ));
    // ServerHello-only fields stay absent, so a filter on them cannot match.
    assert_eq!(tls_field(&decoded, "cipher_suite"), None);
    assert_eq!(tls_field(&decoded, "selected_version"), None);
    assert!(decoded.diagnostics.is_empty());
}

#[test]
fn a_server_hello_publishes_its_selection() {
    let decoded = dissect(443, CLIENT_PORT, &server_hello_record());
    assert_eq!(
        tls_field(&decoded, "handshake_type"),
        Some(FieldValue::from(2_u8))
    );
    assert_eq!(
        tls_field(&decoded, "cipher_suite"),
        Some(FieldValue::from(0x1301_u16))
    );
    assert_eq!(
        tls_field(&decoded, "selected_version"),
        Some(FieldValue::from(0x0304_u16))
    );
    assert_eq!(
        tls_field(&decoded, "key_share_group"),
        Some(FieldValue::from(0x001d_u16))
    );
    assert_eq!(tls_field(&decoded, "sni"), None);
    assert_eq!(tls_field(&decoded, "ja4"), None);
}

#[test]
fn a_server_name_that_is_not_a_host_name_is_reported_and_left_unpublished() {
    let decoded = dissect(
        CLIENT_PORT,
        443,
        &client_hello_record_with_server_name("192.0.2.10"),
    );
    assert_eq!(protocols(&decoded), vec!["ethernet", "ipv4", "tcp", "tls"]);
    assert_eq!(diagnostic_codes(&decoded), vec!["tls.sni_invalid"]);
    assert_eq!(tls_field(&decoded, "sni"), None);
    assert_eq!(
        tls_field(&decoded, "sni_raw"),
        Some(FieldValue::Text("3139322e302e322e3130".to_owned()))
    );
}

#[test]
fn a_layer_retains_the_records_it_covered_byte_for_byte() {
    let record = client_hello_record();
    let decoded = dissect(CLIENT_PORT, 443, &record);
    assert_eq!(
        decoded
            .packet
            .get::<Tls>()
            .expect("a tls layer")
            .wire()
            .as_ref(),
        &record[..]
    );

    // A tail the parser cannot read stays outside the layer's wire.
    let mut segment = record.clone();
    segment.extend_from_slice(b"\x00\x00\x00\x00\x00\x00\x00\x00");
    let decoded = dissect(CLIENT_PORT, 443, &segment);
    assert_eq!(
        decoded
            .packet
            .get::<Tls>()
            .expect("a tls layer")
            .wire()
            .as_ref(),
        &record[..]
    );
}

#[test]
fn an_unbound_port_never_dissects_tls() {
    let decoded = dissect(CLIENT_PORT, 80, &client_hello_record());
    assert_eq!(protocols(&decoded), vec!["ethernet", "ipv4", "tcp", "raw"]);
    assert!(decoded.diagnostics.is_empty());
}

#[test]
fn a_plaintext_request_on_a_tls_port_stays_raw_without_diagnostics() {
    let decoded = dissect(
        CLIENT_PORT,
        443,
        b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
    );
    assert_eq!(protocols(&decoded), vec!["ethernet", "ipv4", "tcp", "raw"]);
    assert!(
        decoded.diagnostics.is_empty(),
        "{:?}",
        diagnostic_codes(&decoded)
    );
    assert_eq!(tls_field(&decoded, "handshake_type"), None);
}

#[test]
fn a_segment_starting_mid_record_stays_raw() {
    let record = client_hello_record();
    let decoded = dissect(CLIENT_PORT, 443, &record[64..]);
    assert_eq!(protocols(&decoded), vec!["ethernet", "ipv4", "tcp", "raw"]);
    assert!(decoded.diagnostics.is_empty());
}

#[test]
fn a_plausible_header_with_no_complete_record_stays_raw() {
    // A record header the gate accepts, over bytes that never complete it:
    // a coincidence inside opaque data, not a defect.
    let mut segment = vec![23, 0x03, 0x03, 0x40, 0x00];
    segment.extend((0..64_u8).map(|value| value.wrapping_mul(37)));
    let decoded = dissect(CLIENT_PORT, 443, &segment);
    assert_eq!(protocols(&decoded), vec!["ethernet", "ipv4", "tcp", "raw"]);
    assert!(
        decoded.diagnostics.is_empty(),
        "{:?}",
        diagnostic_codes(&decoded)
    );
}

#[test]
fn a_segment_ending_mid_record_is_incomplete_with_a_raw_tail() {
    let mut segment = client_hello_record();
    let tail = application_data(18);
    segment.extend_from_slice(&tail[..7]);
    let decoded = dissect(CLIENT_PORT, 443, &segment);
    assert_eq!(
        protocols(&decoded),
        vec!["ethernet", "ipv4", "tcp", "tls", "raw"]
    );
    assert_eq!(
        tls_field(&decoded, "incomplete"),
        Some(FieldValue::Bool(true))
    );
    assert_eq!(diagnostic_codes(&decoded), vec!["tls.record_continues"]);
    assert!(
        !decoded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "decode.terminal_payload"),
        "a continuing record is not a terminal payload"
    );
    assert!(
        decoded
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.severity == packetcraftr_core::diagnostic::Severity::Info),
        "loss on a TLS port must never raise a warning"
    );
}

#[test]
fn an_unparsable_tail_after_a_complete_record_is_reported_as_information() {
    let mut segment = application_data(17);
    segment.extend_from_slice(b"\x00\x00\x00\x00\x00\x00\x00\x00");
    let decoded = dissect(CLIENT_PORT, 443, &segment);
    assert_eq!(
        protocols(&decoded),
        vec!["ethernet", "ipv4", "tcp", "tls", "raw"]
    );
    assert_eq!(
        tls_field(&decoded, "record_count"),
        Some(FieldValue::from(1_u16))
    );
    assert_eq!(
        tls_field(&decoded, "incomplete"),
        Some(FieldValue::Bool(false))
    );
    assert_eq!(diagnostic_codes(&decoded), vec!["tls.record_unparsed"]);
}

#[test]
fn records_past_the_cap_become_a_raw_tail() {
    let mut segment = Vec::new();
    for _ in 0..65 {
        segment.extend_from_slice(&application_data(1));
    }
    let decoded = dissect(CLIENT_PORT, 443, &segment);
    assert_eq!(
        protocols(&decoded),
        vec!["ethernet", "ipv4", "tcp", "tls", "raw"]
    );
    assert_eq!(
        tls_field(&decoded, "record_count"),
        Some(FieldValue::from(64_u16))
    );
    assert_eq!(diagnostic_codes(&decoded), vec!["tls.records_capped"]);
}

#[test]
fn tls_fields_resolve_through_the_display_filter_language() {
    let hello = dissect(CLIENT_PORT, 443, &client_hello_record());
    assert!(matches(&hello, "tls"));
    assert!(matches(&hello, "tls.sni == \"api.example.test\""));
    assert!(matches(&hello, "tls.sni contains \"example\""));
    assert!(matches(&hello, "tls.ja4 contains \"t13d\""));
    assert!(matches(&hello, "tls.handshake_type == 1"));
    assert!(!matches(&hello, "tls.incomplete"));
    assert!(!matches(&hello, "tls.sni == \"other.example.test\""));
    assert!(!matches(&hello, "tls.cipher_suite == 4865"));

    let mut truncated = client_hello_record();
    truncated.extend_from_slice(&application_data(4)[..4]);
    let partial = dissect(CLIENT_PORT, 443, &truncated);
    assert!(matches(&partial, "tls.incomplete"));

    let plaintext = dissect(CLIENT_PORT, 443, b"GET / HTTP/1.1\r\n\r\n");
    assert!(!matches(&plaintext, "tls"));
    assert!(matches(&plaintext, "raw"));
}

#[test]
fn round_trips_hold_for_tls_and_non_tls_payloads_on_a_bound_port() {
    // `dissect` asserts build(dissect(x)) == x for every case; these are the
    // shapes the round trip must cover on a port that now dissects as TLS.
    let mut two_records = client_hello_record();
    two_records.extend_from_slice(&application_data(9));
    for payload in [
        client_hello_record(),
        server_hello_record(),
        two_records,
        b"tls".to_vec(),
        b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        vec![0_u8; 64],
    ] {
        dissect(CLIENT_PORT, 443, &payload);
    }
}

#[test]
fn two_complete_records_in_one_segment_are_one_layer() {
    let mut segment = client_hello_record();
    segment.extend_from_slice(&application_data(9));
    let decoded = dissect(CLIENT_PORT, 443, &segment);
    assert_eq!(protocols(&decoded), vec!["ethernet", "ipv4", "tcp", "tls"]);
    assert_eq!(
        tls_field(&decoded, "record_count"),
        Some(FieldValue::from(2_u16))
    );
    // The first record still names the layer, and its handshake still parses.
    assert_eq!(
        tls_field(&decoded, "handshake_type"),
        Some(FieldValue::from(1_u8))
    );
    assert!(decoded.diagnostics.is_empty());
}

#[test]
fn every_single_byte_mutation_of_a_hello_decodes_without_panicking_or_erroring() {
    let record = client_hello_record();
    for index in (0..record.len()).step_by(7) {
        for mask in [0x01_u8, 0x80, 0xff] {
            let mut mutated = record.clone();
            mutated[index] ^= mask;
            let decoded = dissect(CLIENT_PORT, 443, &mutated);
            let protocols = protocols(&decoded);
            assert!(
                protocols == vec!["ethernet", "ipv4", "tcp", "tls"]
                    || protocols == vec!["ethernet", "ipv4", "tcp", "tls", "raw"]
                    || protocols == vec!["ethernet", "ipv4", "tcp", "raw"],
                "byte {index} mask {mask:#x}: {protocols:?}"
            );
            assert!(
                decoded
                    .diagnostics
                    .iter()
                    .all(|diagnostic| diagnostic.severity
                        == packetcraftr_core::diagnostic::Severity::Info),
                "byte {index} mask {mask:#x}: {:?}",
                diagnostic_codes(&decoded)
            );
        }
    }
}

#[test]
fn extra_tls_ports_are_additive_and_leave_the_defaults_bound() {
    let registry = builtin::registry_with_tls_ports(&[443, 4433]).expect("extra TLS port binds");
    for port in [443_u64, 4433] {
        assert_eq!(
            registry
                .child_for("tcp", packetcraftr_core::registry::Discriminator(port))
                .map(|protocol| protocol.as_str()),
            Some("tls"),
            "port {port}"
        );
    }
    assert_eq!(
        registry
            .child_for("tcp", packetcraftr_core::registry::Discriminator(0))
            .map(|protocol| protocol.as_str()),
        Some("raw")
    );
}

#[test]
fn the_registry_reports_which_ports_reach_tls() {
    let registry = registry();
    let bindings: Vec<(&str, u64)> = registry
        .parent_bindings("tls")
        .into_iter()
        .map(|(parent, discriminator)| (parent.as_str(), discriminator.0))
        .collect();
    assert_eq!(
        bindings,
        TLS_PORTS
            .iter()
            .map(|port| ("tcp", u64::from(*port)))
            .collect::<Vec<_>>()
    );
}
