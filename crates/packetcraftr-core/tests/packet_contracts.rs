// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::{
    Packet, document,
    layer::{Padding, Raw},
    registry::Builder,
};

#[test]
fn packet_edits_preserve_padding_boundaries() {
    let mut packet = Packet::new();
    packet.push(Raw::new(vec![1_u8, 2]));
    packet.push(Padding::after_layer(vec![0_u8; 2], 1));

    packet
        .insert(0, Raw::new(vec![9_u8]))
        .expect("insertion should succeed");
    assert_eq!(
        packet
            .get::<Padding>()
            .and_then(|padding| padding.outside_layer),
        Some(2)
    );

    let error = packet
        .remove(2)
        .expect_err("removing a referenced padding boundary must fail closed");
    assert!(matches!(
        error,
        packetcraftr_core::Error::PaddingBoundaryRemoval { index: 2 }
    ));
}

#[test]
fn registry_rejects_conflicting_roots_and_bindings() {
    let mut builder = Builder::new();
    builder
        .bind_link_type(1, "raw")
        .expect("first root binding should succeed");
    assert!(matches!(
        builder.bind_link_type(1, "other"),
        Err(packetcraftr_core::registry::Error::DuplicateLinkType { link_type: 1 })
    ));

    let mut builder = Builder::new();
    builder
        .bind("parent", 7, "first", 10)
        .expect("first child binding should succeed");
    assert!(matches!(
        builder.bind("parent", 7, "second", 10),
        Err(packetcraftr_core::registry::Error::BindingConflict {
            discriminator: 7,
            priority: 10,
            ..
        })
    ));
}

#[test]
fn unresolved_registry_references_are_rejected_at_finalization() {
    let mut builder = Builder::new();
    builder
        .bind_link_type(101, "missing")
        .expect("binding is staged until finalization");
    assert!(matches!(
        builder.build(),
        Err(packetcraftr_core::registry::Error::UnknownProtocol { protocol }) if protocol.as_str() == "missing"
    ));
}

#[test]
fn packet_documents_enforce_byte_layer_and_duplicate_key_limits() {
    let minimal = r#"{"schema":"packetcraftr.packet/v1","layers":[]}"#;
    assert!(matches!(
        document::Packet::parse(minimal, document::Format::Json, minimal.len() - 1),
        Err(document::Error::SizeLimit { .. })
    ));

    let one_layer = r#"{"schema":"packetcraftr.packet/v1","layers":[{"protocol":"raw"}]}"#;
    assert!(matches!(
        document::Packet::parse_with_resource_limits(
            one_layer,
            document::Format::Json,
            one_layer.len(),
            0,
            document::DEFAULT_MAX_DOCUMENT_NESTING,
        ),
        Err(document::Error::LayerLimit { limit: 0 })
    ));

    let duplicate = "schema: packetcraftr.packet/v1\nschema: duplicate\nlayers: []\n";
    assert!(document::Packet::parse(duplicate, document::Format::Yaml, duplicate.len(),).is_err());
}

#[test]
fn scoped_core_api_paths_are_available() {
    use packetcraftr_core::{
        build::{BuiltPacket, Context, Mode},
        codec::{
            DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext,
        },
        decode::{DecodedPacket, Dissector},
        diagnostic::{Diagnostic, Severity},
        expression::parse,
        field::{FieldKind, FieldValue, WireValue},
        layer::{FieldError, FieldSchema},
        layout::{ByteRange, FieldLayout, LayerLayout, PacketLayout},
        matcher::{MatchResult, ResponseMatcher},
        registry::Registry,
    };

    let _build_context = Context::default();
    let _build_mode = Mode::Strict;
    let _build_options = packetcraftr_core::build::Options::default();
    let _build_error: Option<packetcraftr_core::build::Error> = None;
    let _built_packet: Option<BuiltPacket> = None;
    let _dissector: Option<Dissector> = None;
    let _decode_options = packetcraftr_core::decode::Options::default();
    let _decode_error: Option<packetcraftr_core::decode::Error> = None;
    let _decoded_packet: Option<DecodedPacket> = None;
    let _codec_error: Option<packetcraftr_core::codec::Error> = None;
    let _decoded_layer: Option<DecodedLayerValue> = None;
    let _encoded_layer: Option<EncodedLayer> = None;
    let _codec: Option<&dyn LayerCodec> = None;
    let _decode_context: Option<LayerDecodeContext<'_>> = None;
    let _encode_context: Option<LayerEncodeContext<'_>> = None;
    let _field_error: Option<FieldError> = None;
    let _field_schema: Option<&FieldSchema> = None;
    let _matcher: Option<&dyn ResponseMatcher> = None;
    let parse: fn(
        &str,
        &Registry,
        packetcraftr_core::expression::Options,
    ) -> Result<Packet, packetcraftr_core::expression::Error> = parse;
    let _ = parse;

    let diag = Diagnostic::warning("W001", "test warning").at_layer(0);
    assert_eq!(diag.severity, Severity::Warning);

    let br = ByteRange::new(0, 14);
    let fl = FieldLayout {
        name: "src_mac".to_string(),
        range: br,
    };
    let ll = LayerLayout {
        index: 0,
        protocol: packetcraftr_core::layer::Id::new("ethernet"),
        range: ByteRange::new(0, 14),
        fields: vec![fl],
    };
    let pl = PacketLayout { layers: vec![ll] };
    assert_eq!(pl.layers.len(), 1);

    let fval = FieldValue::Unsigned(80);
    assert!(matches!(fval, FieldValue::Unsigned(80)));
    assert_eq!(FieldKind::Unsigned, FieldKind::Unsigned);
    assert!(matches!(WireValue::<u16>::Auto, WireValue::Auto));
    assert!(!MatchResult::no_match().matched);
}

#[test]
fn build_and_decode_round_trip() {
    use packetcraftr_core::{
        Packet,
        build::{Builder, Context},
        decode::Dissector,
        field::WireValue,
        frame::{Frame, LinkType},
        protocol::{link::Ethernet, network::Ipv4, transport::Tcp},
    };
    use std::sync::Arc;

    let reg =
        Arc::new(packetcraftr_core::protocol::builtin::registry().expect("built-in registry"));
    let builder = Builder::new(reg.clone());
    let dissector = Dissector::new(reg);

    let eth = Ethernet {
        destination: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        source: [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb],
        ether_type: WireValue::Exact(0x0800),
    };

    let ip = Ipv4 {
        source: "192.168.1.100".parse().unwrap(),
        destination: "10.0.0.1".parse().unwrap(),
        protocol: WireValue::Exact(6),
        ttl: 64,
        ..Ipv4::default()
    };

    let tcp = Tcp {
        source_port: 12345,
        destination_port: 80,
        sequence: 1000,
        acknowledgment: 0,
        flags: 0x02,
        ..Tcp::default()
    };

    let mut packet = Packet::new();
    packet.push(eth);
    packet.push(ip);
    packet.push(tcp);

    let build_res = builder
        .build(
            packet.clone(),
            Context::default(),
            packetcraftr_core::build::Options::default(),
        )
        .expect("build should succeed");

    assert!(!build_res.bytes.is_empty());

    let frame = Frame::without_timestamp(LinkType::ETHERNET, build_res.bytes).expect("valid frame");
    let decode_res = dissector
        .decode(frame, packetcraftr_core::decode::Options::default())
        .expect("decode should succeed");

    assert_eq!(decode_res.packet.len(), 3);
}

#[test]
fn dissector_handles_arbitrary_input() {
    use bytes::Bytes;
    use packetcraftr_core::{
        decode::Dissector,
        frame::{Frame, LinkType},
    };
    use std::sync::Arc;

    let reg =
        Arc::new(packetcraftr_core::protocol::builtin::registry().expect("built-in registry"));
    let dissector = Dissector::new(reg);

    let test_cases: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        vec![0xff; 1],
        vec![0xff; 14],
        vec![0x45, 0x00, 0x00, 0x14],
        vec![0x60, 0x00, 0x00, 0x00],
        (0..255).collect(),
        vec![0x00; 1000],
    ];

    for bytes in test_cases {
        if let Ok(frame) = Frame::without_timestamp(LinkType::ETHERNET, Bytes::from(bytes)) {
            let _res = dissector.decode(frame, packetcraftr_core::decode::Options::default());
        }
    }
}

#[test]
fn expression_and_filter_parsers_validate_inputs() {
    use packetcraftr_core::{expression::parse, filter::Filter};

    let reg = packetcraftr_core::protocol::builtin::registry().expect("built-in registry");

    let valid_expressions = vec![
        "ethernet / ipv4(source=192.168.1.1, destination=10.0.0.1) / tcp(destination_port=80)",
        "ipv4 / udp(destination_port=53)",
        "raw(hex=\"01020304\")",
    ];

    for expr_str in valid_expressions {
        let parsed = parse(
            expr_str,
            &reg,
            packetcraftr_core::expression::Options::default(),
        );
        assert!(
            parsed.is_ok(),
            "Failed to parse valid expression: {}",
            expr_str
        );
    }

    let invalid_expressions = vec![
        "invalid_proto_xyz",
        "ipv4(src=999.999.999.999)",
        "ethernet / (",
    ];

    for expr_str in invalid_expressions {
        let parsed = parse(
            expr_str,
            &reg,
            packetcraftr_core::expression::Options::default(),
        );
        assert!(
            parsed.is_err(),
            "Invalid expression should fail to parse: {}",
            expr_str
        );
    }

    let valid_filters = vec![
        "ipv4.source == 192.168.1.1",
        "tcp.dstport == 80",
        "ipv4.ttl > 30 && tcp.flags.syn",
        "udp.dstport in {53, 5353, 123}",
    ];

    for filter_str in valid_filters {
        let compiled = Filter::compile(
            filter_str,
            &reg,
            packetcraftr_core::filter::Options::default(),
        );
        assert!(compiled.is_ok(), "Failed to compile filter: {}", filter_str);
    }
}

#[test]
fn builder_enforces_packet_and_layer_limits() {
    use packetcraftr_core::{
        Packet,
        build::{Builder, Context},
        protocol::link::Ethernet,
    };
    use std::sync::Arc;

    let reg =
        Arc::new(packetcraftr_core::protocol::builtin::registry().expect("built-in registry"));
    let builder = Builder::new(reg);

    let empty_packet = Packet::new();
    let err = builder.build(
        empty_packet,
        Context::default(),
        packetcraftr_core::build::Options::default(),
    );
    assert!(err.is_err());

    let mut huge_packet = Packet::new();
    for _ in 0..100 {
        huge_packet.push(Ethernet::default());
    }
    let opts = packetcraftr_core::build::Options {
        max_layers: 10,
        ..Default::default()
    };
    let err2 = builder.build(huge_packet, Context::default(), opts);
    assert!(err2.is_err());
}
