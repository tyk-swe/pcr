// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::{
    Packet, document,
    layer::{Padding, Raw},
    registry::{Builder, Error as RegistryError},
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
        Err(RegistryError::DuplicateLinkType { link_type: 1 })
    ));

    let mut builder = Builder::new();
    builder
        .bind("parent", 7, "first", 10)
        .expect("first child binding should succeed");
    assert!(matches!(
        builder.bind("parent", 7, "second", 10),
        Err(RegistryError::BindingConflict {
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
        Err(RegistryError::UnknownProtocol { protocol }) if protocol.as_str() == "missing"
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
fn test_m2_reexports_and_aliases() {
    use packetcraftr_core::{
        codec,
        diagnostic::{Diagnostic, Severity},
        field::FieldValue,
        layer::Id as ProtocolId,
        layout::{ByteRange, FieldLayout, LayerLayout, PacketLayout},
    };

    let err: Option<codec::Error> = None;
    assert!(err.is_none());
    let _decoded_alias: Option<codec::Decoded> = None;
    let _encoded_alias: Option<codec::Encoded> = None;

    let diag = Diagnostic::warning("W001", "test warning").at_layer(0);
    assert_eq!(diag.severity, Severity::Warning);

    let br = ByteRange::new(0, 14);
    let fl = FieldLayout {
        name: "src_mac".to_string(),
        range: br,
    };
    let ll = LayerLayout {
        index: 0,
        protocol: ProtocolId::new("ethernet"),
        range: ByteRange::new(0, 14),
        fields: vec![fl],
    };
    let pl = PacketLayout { layers: vec![ll] };
    assert_eq!(pl.layers.len(), 1);

    let fval = FieldValue::Unsigned(80);
    assert!(matches!(fval, FieldValue::Unsigned(80)));
}

#[test]
fn test_m2_build_decode_roundtrip_stress() {
    use packetcraftr_core::{
        Packet,
        build::{BuildContext, BuildOptions, Builder},
        decode::{DecodeOptions, Dissector},
        field::WireValue,
        frame::{Frame, LinkType},
        protocol::{
            builtin::registry as default_registry, link::Ethernet, network::Ipv4, transport::Tcp,
        },
    };
    use std::sync::Arc;

    let reg = Arc::new(default_registry().expect("built-in registry"));
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
            BuildContext::default(),
            BuildOptions::default(),
        )
        .expect("build should succeed");

    assert!(!build_res.bytes.is_empty());

    let frame = Frame::without_timestamp(LinkType::ETHERNET, build_res.bytes).expect("valid frame");
    let decode_res = dissector
        .decode(frame, DecodeOptions::default())
        .expect("decode should succeed");

    assert_eq!(decode_res.packet.len(), 3);
}

#[test]
fn test_m2_dissector_fuzz_resilience() {
    use bytes::Bytes;
    use packetcraftr_core::{
        decode::{DecodeOptions, Dissector},
        frame::{Frame, LinkType},
        protocol::builtin::registry as default_registry,
    };
    use std::sync::Arc;

    let reg = Arc::new(default_registry().expect("built-in registry"));
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
            let _res = dissector.decode(frame, DecodeOptions::default());
        }
    }
}

#[test]
fn test_m2_expression_parser_and_filter_stress() {
    use packetcraftr_core::{
        expression::{Options as ExpressionOptions, parse as parse_expression},
        filter::{Filter, Options as FilterOptions},
        protocol::builtin::registry as default_registry,
    };

    let reg = default_registry().expect("built-in registry");

    let valid_expressions = vec![
        "ethernet / ipv4(source=192.168.1.1, destination=10.0.0.1) / tcp(destination_port=80)",
        "ipv4 / udp(destination_port=53)",
        "raw(hex=\"01020304\")",
    ];

    for expr_str in valid_expressions {
        let parsed = parse_expression(expr_str, &reg, ExpressionOptions::default());
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
        let parsed = parse_expression(expr_str, &reg, ExpressionOptions::default());
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
        let compiled = Filter::compile(filter_str, &reg, FilterOptions::default());
        assert!(compiled.is_ok(), "Failed to compile filter: {}", filter_str);
    }
}

#[test]
fn test_m2_builder_limits_stress() {
    use packetcraftr_core::{
        Packet,
        build::{BuildContext, BuildOptions, Builder},
        protocol::{builtin::registry as default_registry, link::Ethernet},
    };
    use std::sync::Arc;

    let reg = Arc::new(default_registry().expect("built-in registry"));
    let builder = Builder::new(reg);

    let empty_packet = Packet::new();
    let err = builder.build(
        empty_packet,
        BuildContext::default(),
        BuildOptions::default(),
    );
    assert!(err.is_err());

    let mut huge_packet = Packet::new();
    for _ in 0..100 {
        huge_packet.push(Ethernet::default());
    }
    let opts = BuildOptions {
        max_layers: 10,
        ..Default::default()
    };
    let err2 = builder.build(huge_packet, BuildContext::default(), opts);
    assert!(err2.is_err());
}
