// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::decoded::protocols;
use common::registry;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use packetcraftr_core::document;
use packetcraftr_core::field::FieldValue;
use packetcraftr_core::filter::{Context as FilterContext, Filter};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::protocol::application::tls::Tls;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::Tcp;
use packetcraftr_core::{build, codec, decode, packet::Packet};

use common::tls_frames::{ClientHelloSpec, application_data, client_hello, handshake_record};
use common::tls_vectors::{CLIENT_HELLO_VECTORS, SERVER_HELLO_VECTORS, decode_hex};

const TLS_PORTS: &[u16] = &[443, 465, 636, 853, 993, 995, 8443];

const CLIENT_PORT: u16 = 40_000;

fn client_hello_record() -> Vec<u8> {
    decode_hex(CLIENT_HELLO_VECTORS[1].record_hex)
}

fn server_hello_record() -> Vec<u8> {
    decode_hex(SERVER_HELLO_VECTORS[0].record_hex)
}

fn client_hello_record_with_server_name(name: &str) -> Vec<u8> {
    handshake_record(&client_hello(&ClientHelloSpec {
        sni: Some(name.to_owned()),
        alpn: Vec::new(),
        supported_groups: Vec::new(),
        key_share_groups: Vec::new(),
        ..ClientHelloSpec::default()
    }))
}

fn client_hello_record_with_extensions(count: u16) -> Vec<u8> {
    let extensions: Vec<u8> = (0..count)
        .flat_map(|index| [&(0x2000 + index).to_be_bytes()[..], &[0, 0]].concat())
        .collect();
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x11; 32]);
    body.push(0);
    body.extend_from_slice(&[0, 2, 0x13, 0x01]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&u16::try_from(extensions.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&extensions);
    let length = u32::try_from(body.len()).unwrap().to_be_bytes();
    let mut message = vec![1, length[1], length[2], length[3]];
    message.extend_from_slice(&body);
    handshake_record(&message)
}

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
        .build(packet, codec::Context::default(), build::Options::default())
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
            codec::Context::default(),
            build::Options::default(),
        )
        .expect("dissected segment rebuilds");
    assert_eq!(
        rebuilt.bytes, built.bytes,
        "build(dissect(x)) must equal x on port {destination_port}"
    );
    decoded
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
        .map(|diagnostic| diagnostic.code)
        .collect()
}

fn matches(decoded: &decode::DecodedPacket, source: &str) -> bool {
    let registry = registry();
    Filter::compile(
        source,
        &registry,
        packetcraftr_core::filter::Limits::default(),
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
    assert_eq!(tls_field(&decoded, "cipher_suite"), None);
    assert_eq!(tls_field(&decoded, "selected_version"), None);
    assert!(decoded.diagnostics.is_empty());
}

fn patch(mut record: Vec<u8>, marker: &[u8], replacement: &[u8]) -> Vec<u8> {
    assert_eq!(marker.len(), replacement.len());
    let start = record
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("marker is in the record");
    record[start..start + marker.len()].copy_from_slice(replacement);
    record
}

#[test]
fn alpn_text_escapes_the_wire_octets_rather_than_a_lossy_decoding() {
    let with_alpn = |name: &str| {
        handshake_record(&client_hello(&ClientHelloSpec {
            alpn: vec![name.to_owned()],
            ..ClientHelloSpec::default()
        }))
    };
    let invalid = patch(with_alpn("Zh2"), b"Zh2", b"\xffh2");
    let replacement_character = with_alpn("\u{fffd}h2");

    let alpn = |record: &[u8]| tls_field(&dissect(CLIENT_PORT, 443, record), "alpn");
    assert_eq!(
        alpn(&invalid),
        Some(FieldValue::List(vec![FieldValue::Text(
            "\\255h2".to_owned()
        )]))
    );
    assert_eq!(
        alpn(&replacement_character),
        Some(FieldValue::List(vec![FieldValue::Text(
            "\\239\\191\\189h2".to_owned()
        )]))
    );
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
fn a_client_hello_that_fails_to_parse_is_reported_rather_than_left_blank() {
    let decoded = dissect(CLIENT_PORT, 443, &client_hello_record_with_extensions(65));
    assert_eq!(protocols(&decoded), vec!["ethernet", "ipv4", "tcp", "tls"]);
    assert_eq!(
        tls_field(&decoded, "record_count"),
        Some(FieldValue::from(1_u16))
    );
    assert_eq!(tls_field(&decoded, "handshake_type"), None);
    assert_eq!(tls_field(&decoded, "ja3"), None);
    assert_eq!(tls_field(&decoded, "ja4"), None);
    assert_eq!(diagnostic_codes(&decoded), vec!["tls.handshake_unparsed"]);
    let diagnostic = &decoded.diagnostics[0];
    assert_eq!(
        diagnostic.severity,
        packetcraftr_core::diagnostic::Severity::Info
    );
    assert!(
        diagnostic
            .message
            .contains("extension count exceeds the limit of 64"),
        "{}",
        diagnostic.message
    );

    let at_the_limit = dissect(CLIENT_PORT, 443, &client_hello_record_with_extensions(64));
    assert_eq!(
        tls_field(&at_the_limit, "handshake_type"),
        Some(FieldValue::from(1_u8))
    );
    assert!(tls_field(&at_the_limit, "ja3").is_some());
    assert!(tls_field(&at_the_limit, "ja4").is_some());
    assert!(
        at_the_limit.diagnostics.is_empty(),
        "{:?}",
        diagnostic_codes(&at_the_limit)
    );
}

#[test]
fn a_server_hello_that_fails_to_parse_is_reported_too() {
    let mut record = server_hello_record();
    record.push(0);
    let record_length = u16::from_be_bytes([record[3], record[4]]) + 1;
    record[3..5].copy_from_slice(&record_length.to_be_bytes());
    record[8] += 1;
    let decoded = dissect(443, CLIENT_PORT, &record);
    assert_eq!(protocols(&decoded), vec!["ethernet", "ipv4", "tcp", "tls"]);
    assert_eq!(tls_field(&decoded, "handshake_type"), None);
    assert_eq!(tls_field(&decoded, "cipher_suite"), None);
    assert_eq!(diagnostic_codes(&decoded), vec!["tls.handshake_unparsed"]);
    assert!(
        decoded.diagnostics[0].message.contains("trailing bytes"),
        "{}",
        decoded.diagnostics[0].message
    );
}

#[test]
fn a_handshake_record_that_stops_short_or_is_encrypted_reports_nothing_unparsed() {
    let record = client_hello_record();
    let mut split = record[..5].to_vec();
    split[3..5].copy_from_slice(&40_u16.to_be_bytes());
    split.extend_from_slice(&record[5..45]);
    let decoded = dissect(CLIENT_PORT, 443, &split);
    assert_eq!(tls_field(&decoded, "handshake_type"), None);
    assert!(
        decoded.diagnostics.is_empty(),
        "{:?}",
        diagnostic_codes(&decoded)
    );

    let mut encrypted = record[..5].to_vec();
    encrypted[3..5].copy_from_slice(&40_u16.to_be_bytes());
    encrypted.extend_from_slice(&[0xab; 40]);
    let decoded = dissect(CLIENT_PORT, 443, &encrypted);
    assert_eq!(protocols(&decoded), vec!["ethernet", "ipv4", "tcp", "tls"]);
    assert_eq!(tls_field(&decoded, "handshake_type"), None);
    assert!(
        decoded.diagnostics.is_empty(),
        "{:?}",
        diagnostic_codes(&decoded)
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
fn an_incomplete_segment_round_trips_through_a_packet_document() {
    let mut segment = client_hello_record();
    segment.extend_from_slice(&application_data(18)[..7]);
    let decoded = dissect(CLIENT_PORT, 443, &segment);
    let recreated = document::Packet::from_packet(&decoded.packet)
        .to_packet(&registry(), 8)
        .expect("the document rebuilds the packet");
    let tls = recreated.get::<Tls>().expect("a tls layer");
    assert!(tls.incomplete);
    assert_eq!(tls.wire(), decoded.packet.get::<Tls>().unwrap().wire());
    let bytes = build::Builder::new(registry())
        .build(
            recreated,
            codec::Context::default(),
            build::Options::default(),
        )
        .expect("the recreated packet builds")
        .bytes;
    let original = build::Builder::new(registry())
        .build(
            decoded.packet.clone(),
            codec::Context::default(),
            build::Options::default(),
        )
        .expect("the dissected packet builds")
        .bytes;
    assert_eq!(bytes, original);
}

#[test]
fn a_packet_document_rejects_a_non_boolean_incomplete_flag() {
    let decoded = dissect(CLIENT_PORT, 443, &client_hello_record());
    let mut document = document::Packet::from_packet(&decoded.packet);
    document
        .layers
        .iter_mut()
        .find(|layer| layer.protocol == "tls")
        .expect("a tls layer")
        .fields
        .insert("incomplete".to_owned(), FieldValue::from("yes"));
    assert!(matches!(
        document.to_packet(&registry(), 8),
        Err(document::Error::Layer {
            source: codec::Error::Field(packetcraftr_core::field::Error::WrongType {
                expected: "bool",
                ..
            }),
            ..
        })
    ));
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
fn two_complete_records_in_one_segment_are_one_layer() {
    let mut segment = client_hello_record();
    segment.extend_from_slice(&application_data(9));
    let decoded = dissect(CLIENT_PORT, 443, &segment);
    assert_eq!(protocols(&decoded), vec!["ethernet", "ipv4", "tcp", "tls"]);
    assert_eq!(
        tls_field(&decoded, "record_count"),
        Some(FieldValue::from(2_u16))
    );
    assert_eq!(
        tls_field(&decoded, "handshake_type"),
        Some(FieldValue::from(1_u8))
    );
    assert!(decoded.diagnostics.is_empty());
}

#[test]
fn extra_tls_ports_are_additive_and_leave_the_defaults_bound() {
    let registry = builtin::registry_with_tls_ports(&[443, 4433]).expect("extra TLS port binds");
    for port in [443_u64, 4433] {
        assert_eq!(
            registry
                .child_for("tcp", packetcraftr_core::registry::Discriminator(port))
                .map(packetcraftr_core::layer::Id::as_str),
            Some("tls"),
            "port {port}"
        );
    }
    assert_eq!(
        registry
            .child_for("tcp", packetcraftr_core::registry::Discriminator(0))
            .map(packetcraftr_core::layer::Id::as_str),
        Some("raw")
    );
}

#[test]
fn extra_tls_ports_refuse_the_raw_fallback_and_ports_bound_elsewhere() {
    for port in [0_u16, 53, 80] {
        assert!(
            matches!(
                builtin::registry_with_tls_ports(&[port]),
                Err(packetcraftr_core::registry::Error::BindingConflict { discriminator, .. })
                    if discriminator == u64::from(port)
            ),
            "port {port}"
        );
    }
}
