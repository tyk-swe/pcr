// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use bytes::Bytes;
use packetcraftr_core::{
    build::Builder,
    decode::Dissector,
    expression,
    field::FieldValue,
    filter,
    frame::{Frame, LinkType},
    layer::{Layer, Malformed},
    protocol::{
        application::dhcp::{Dhcpv4, Dhcpv6, Duid, Limits, Option4, Option6, Value4, Value6},
        builtin,
    },
    template::Template,
};
use std::time::UNIX_EPOCH;
#[test]
fn dhcpv4_overload_unknown_options_and_original_wire_survive_round_trips() {
    let mut message = Dhcpv4::default();
    message.transaction_id = 0x12345678;
    message.your_address = "192.0.2.10".parse().unwrap();
    message.options.extend([
        Option4::server_identifier("192.0.2.1".parse().unwrap()),
        Option4::lease_time(3600),
        Option4::raw(222, Bytes::from_static(&[0xff, 0, 1])),
    ]);
    message.file_options.push(Option4 {
        code: 12,
        value: Value4::Text(Bytes::from_static(b"fixture.test")),
    });
    message
        .server_name_options
        .push(Option4::parameter_request(Bytes::from_static(&[1, 3, 6])));
    let wire = message.to_wire().unwrap();
    let parsed = Dhcpv4::try_from(wire.clone()).unwrap();
    assert_eq!(parsed.transaction_id, 0x12345678);
    assert_eq!(parsed.file_options, message.file_options);
    assert_eq!(parsed.server_name_options, message.server_name_options);
    assert_eq!(parsed.to_wire().unwrap(), wire);
    assert!(
        parsed
            .options
            .iter()
            .any(|option| option.code == 52 && option.value == Value4::Overload(3))
    );
    let mut noncanonical = Dhcpv4::default().to_wire().unwrap().to_vec();
    noncanonical.splice(240..240, [0, 0]);
    noncanonical.extend([0xaa, 0xbb]);
    let mut parsed = Dhcpv4::try_from(noncanonical.clone()).unwrap();
    assert_eq!(parsed.to_wire().unwrap().as_ref(), noncanonical);
    parsed.edit(|message| message.transaction_id = 9);
    let edited = parsed.to_wire().unwrap();
    assert!(edited.ends_with(&[0xaa, 0xbb]));
}
#[test]
fn named_dhcpv4_options_are_editable_through_templates_and_filters() {
    let registry = builtin::registry();
    let packet=expression::parse(r"ipv4(source=192.0.2.1,destination=192.0.2.10)/udp(source_port=67,destination_port=68)/dhcpv4(operation=2,message_type=5,transaction_id=7,your_address=192.0.2.10,options=[{code=53,value={message_type=5}},{code=51,value={seconds=3600}},{code=54,value={address=192.0.2.1}}])",&registry,Default::default()).unwrap();
    let template = Template::new(packet).axis(
        2,
        "options[1].value.seconds",
        vec![60u32.into(), 120u32.into()],
    );
    for (index, packet) in template.expand(2).unwrap().enumerate() {
        let built = Builder::new(registry.clone())
            .build(packet.unwrap(), Default::default(), Default::default())
            .unwrap();
        let decoded = Dissector::new(registry.clone())
            .decode(
                Frame::new(UNIX_EPOCH, LinkType::IPV4, built.bytes.clone()).unwrap(),
                Default::default(),
            )
            .unwrap();
        let dhcp = decoded.packet.get::<Dhcpv4>().unwrap();
        assert_eq!(dhcp.message_type(), Some(5));
        assert_eq!(dhcp.options[1].value, Value4::Seconds([60, 120][index]));
        let filter = filter::Filter::compile(
            "dhcpv4.message_type == 5 && dhcpv4.your_address == 192.0.2.10",
            &registry,
            Default::default(),
        )
        .unwrap();
        assert!(
            filter
                .matches(&filter::Context {
                    decoded: &decoded,
                    derived: &[],
                    number: 1,
                    tcp_stream: None,
                    udp_stream: None
                })
                .unwrap()
        );
        assert_eq!(
            Builder::new(registry.clone())
                .build(decoded.packet, Default::default(), Default::default())
                .unwrap()
                .bytes,
            built.bytes
        );
    }
}
fn reply() -> Dhcpv6 {
    let mut message = Dhcpv6::default();
    message.message_type = 7;
    message.transaction_id = 0x123456;
    message.options = vec![
        Option6::server_identifier(Duid::link_layer(1, [2, 0, 0, 0, 0, 1]).unwrap()),
        Option6::ia_na(
            7,
            60,
            120,
            vec![Option6::address("2001:db8::10".parse().unwrap(), 180, 300)],
        ),
        Option6::ia_pd(
            8,
            60,
            120,
            vec![Option6 {
                code: 26,
                value: Value6::Prefix {
                    prefix: "2001:db8:100::".parse().unwrap(),
                    prefix_length: 56,
                    preferred_lifetime: 180,
                    valid_lifetime: 300,
                    options: vec![Option6 {
                        code: 13,
                        value: Value6::Status {
                            code: 0,
                            message: Bytes::from_static(b"ok"),
                        },
                    }],
                },
            }],
        ),
        Option6::raw(65000, Bytes::from_static(&[0, 0xff, 3])),
    ];
    message
}
#[test]
fn dhcpv6_relay_address_associations_and_prefixes_are_typed_and_editable() {
    let inner = reply();
    let relay = Dhcpv6::relay_forward(
        1,
        "2001:db8::1".parse().unwrap(),
        "2001:db8::2".parse().unwrap(),
        inner,
    );
    let wire = relay.to_wire().unwrap();
    let mut decoded = Dhcpv6::try_from(wire.clone()).unwrap();
    assert_eq!(decoded.to_wire().unwrap(), wire);
    assert_eq!(decoded.message_type, 12);
    let path = "options[0].value.message.options[1].value.options[0].value.address"
        .parse()
        .unwrap();
    assert_eq!(
        decoded.field_path(&path),
        Some(FieldValue::Ipv6("2001:db8::10".parse().unwrap()))
    );
    decoded
        .set_field_path(&path, FieldValue::Ipv6("2001:db8::11".parse().unwrap()))
        .unwrap();
    let changed = decoded.to_wire().unwrap();
    let parsed = Dhcpv6::try_from(changed).unwrap();
    assert_eq!(
        parsed.field_path(&path),
        Some(FieldValue::Ipv6("2001:db8::11".parse().unwrap()))
    );
    let Value6::Relay(inner) = &parsed.options[0].value else {
        panic!("relay")
    };
    assert_eq!(
        inner.options[3].value,
        Value6::Raw(Bytes::from_static(&[0, 0xff, 3]))
    );
}
#[test]
fn dhcp_limits_and_malformed_lengths_fail_without_losing_capture_bytes() {
    let wire = reply().to_wire().unwrap();
    assert!(
        Dhcpv6::from_wire_with_limits(
            wire.clone(),
            Limits {
                max_options: 1,
                ..Default::default()
            }
        )
        .is_err()
    );
    assert!(Dhcpv6::try_from(wire.slice(..wire.len() - 1)).is_err());
    assert!(Dhcpv4::try_from(vec![0; 239]).is_err());
    let mut relay = Dhcpv6::default();
    for _ in 0..9 {
        relay = Dhcpv6::relay_forward(
            0,
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            relay,
        );
    }
    assert!(relay.to_wire().is_err());
    let mut raw = Dhcpv6::default();
    raw.options = vec![Option6::raw(9, wire.clone())];
    assert!(
        raw.to_wire_with_limits(Limits {
            max_nesting: 0,
            ..Default::default()
        })
        .is_err()
    );
    let mut invalid = Dhcpv4::default();
    invalid.file_options = vec![Option4::raw(220, Bytes::from(vec![1; 128]))];
    assert!(invalid.to_wire().is_err());
    let mut packet=expression::parse("ipv6(source=2001:db8::1,destination=2001:db8::2)/udp(source_port=547,destination_port=546)/dhcpv6()",&builtin::registry(),Default::default()).unwrap();
    packet.get_mut::<Dhcpv6>().unwrap().options = reply().options;
    let built = Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .unwrap();
    let mut malformed = built.bytes.to_vec();
    let end = malformed.len();
    malformed[end - 4] = 255; // final unknown option length low byte, before three payload bytes
    let decoded = Dissector::new(builtin::registry())
        .decode(
            Frame::new(UNIX_EPOCH, LinkType::IPV6, malformed.clone()).unwrap(),
            Default::default(),
        )
        .unwrap();
    assert_eq!(
        decoded.packet.get::<Malformed>().unwrap().bytes.as_ref(),
        &malformed[48..]
    );
    assert_eq!(decoded.original.as_ref(), malformed);
}

#[test]
fn dhcp_documents_and_nested_fuzz_targets_preserve_wire_and_enforce_limits() {
    use packetcraftr_core::{document, fuzz, packet::Packet};
    let registry = builtin::registry();
    let mut packet = Packet::new();
    packet.push(Dhcpv6::try_from(reply().to_wire().unwrap()).unwrap());
    let document = document::Packet::from_packet(&packet);
    let recreated = document.to_packet(&registry, 8).unwrap();
    assert_eq!(
        recreated.get::<Dhcpv6>().unwrap().to_wire().unwrap(),
        reply().to_wire().unwrap()
    );
    let report = fuzz::run(
        &fuzz::Request {
            cases: 4,
            targets: vec!["0.options[1].value.t1".parse().unwrap()],
            strategies: vec![fuzz::Strategy::Boundary],
            ..Default::default()
        },
        recreated,
        registry,
    )
    .unwrap();
    assert_eq!(report.cases.len(), 4);
    assert!(report.cases.iter().any(|case| case.built.is_some()));
    let mut relay = Dhcpv6::default();
    for _ in 0..8 {
        relay = Dhcpv6::relay_forward(
            0,
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            relay,
        );
    }
    let mut packet = Packet::new();
    packet.push(Dhcpv6::try_from(relay.to_wire().unwrap()).unwrap());
    let document = document::Packet::from_packet(&packet);
    assert!(document.to_packet(&builtin::registry(), 8).is_ok());
    assert!(Duid::link_layer(1, vec![0; 65_536]).is_err());
    assert!(Duid::link_layer(1, []).is_err());
}

#[test]
fn borrowed_dhcp_wire_enforces_message_byte_limit() {
    use packetcraftr_core::protocol::application::dhcp::{Error, Limit};

    // DHCPv4 retains trailing bytes after the end option.
    let mut v4 = Dhcpv4::default().to_wire().unwrap().to_vec();
    v4.resize(65_535, 0);
    assert_eq!(Dhcpv4::try_from(v4.as_slice()).unwrap().wire().as_ref(), v4);
    v4.push(0);
    assert!(matches!(
        Dhcpv4::try_from(v4.as_slice()),
        Err(Error::Limit(Limit::MessageBytes))
    ));

    // One unknown DHCPv6 option fills the remaining message bytes.
    let mut v6 = vec![1, 0, 0, 0, 0xfd, 0xe8];
    v6.extend_from_slice(&65_527u16.to_be_bytes());
    v6.resize(65_535, 0);
    assert_eq!(Dhcpv6::try_from(v6.as_slice()).unwrap().wire().as_ref(), v6);
    v6.push(0);
    assert!(matches!(
        Dhcpv6::try_from(v6.as_slice()),
        Err(Error::Limit(Limit::MessageBytes))
    ));
}

#[test]
fn dhcp_codec_failures_keep_the_dhcp_error_as_their_source() {
    use packetcraftr_core::codec;
    use packetcraftr_core::error::{Classified, source_chain};
    use packetcraftr_core::protocol::application::dhcp::Error;
    use std::collections::BTreeMap;
    use std::error::Error as _;

    let mut v4 = Dhcpv4::default().to_wire().unwrap().to_vec();
    v4[236..240].fill(0);
    let mut v6 = Dhcpv6::default().to_wire().unwrap().to_vec();
    v6.truncate(3);
    let registry = builtin::registry();
    for (protocol, wire) in [("dhcpv4", v4), ("dhcpv6", v6)] {
        let direct = match protocol {
            "dhcpv4" => Dhcpv4::try_from(wire.as_slice()).map(|_| ()),
            _ => Dhcpv6::try_from(wire.as_slice()).map(|_| ()),
        }
        .expect_err("the wire is refused");
        let fields = BTreeMap::from([("wire".to_owned(), FieldValue::Bytes(Bytes::from(wire)))]);
        let error = registry
            .codec(protocol)
            .expect("built-in DHCP codec")
            .make_layer(&fields)
            .expect_err("the codec refuses the wire");
        assert!(matches!(error, codec::Error::Rejected { .. }), "{error:?}");
        assert_eq!(error.to_string(), format!("invalid {protocol} layer"));
        let source = error
            .source()
            .and_then(|source| source.downcast_ref::<Error>())
            .expect("the DHCP error is the codec error's source");
        assert_eq!(source, &direct);
        assert_eq!(source_chain(&error), [direct.to_string()]);
        assert_eq!(error.classification().code, "packet.codec");
        assert_eq!(source.classification().code, "packet.dhcp");
    }
}

#[test]
fn dhcp_limits_above_their_ceiling_are_refused_rather_than_lowered() {
    use packetcraftr_core::error::Classified;
    use packetcraftr_core::protocol::application::dhcp::{
        Error, Limit, MAX_MESSAGE_BYTES, MAX_NESTING, MAX_OPTIONS,
    };

    let v4 = Dhcpv4::default();
    let v6 = Dhcpv6::default();
    let (v4_wire, v6_wire) = (v4.to_wire().unwrap(), v6.to_wire().unwrap());
    for (limits, limit, value, maximum) in [
        (
            Limits {
                max_message_bytes: MAX_MESSAGE_BYTES + 1,
                ..Limits::default()
            },
            Limit::MessageBytes,
            MAX_MESSAGE_BYTES + 1,
            MAX_MESSAGE_BYTES,
        ),
        (
            Limits {
                max_options: MAX_OPTIONS + 1,
                ..Limits::default()
            },
            Limit::OptionCount,
            MAX_OPTIONS + 1,
            MAX_OPTIONS,
        ),
        (
            Limits {
                max_nesting: MAX_NESTING + 1,
                ..Limits::default()
            },
            Limit::OptionNesting,
            MAX_NESTING + 1,
            MAX_NESTING,
        ),
    ] {
        let expected = Error::InvalidLimit {
            limit,
            value,
            maximum,
        };
        assert_eq!(limits.validate(), Err(expected.clone()));
        for refused in [
            Dhcpv4::from_wire_with_limits(v4_wire.clone(), limits).map(|_| ()),
            Dhcpv6::from_wire_with_limits(v6_wire.clone(), limits).map(|_| ()),
            v4.to_wire_with_limits(limits).map(|_| ()),
            v6.to_wire_with_limits(limits).map(|_| ()),
        ] {
            assert_eq!(refused, Err(expected.clone()));
        }
        assert_eq!(expected.classification().code, "policy.dhcp_limit");
    }

    // Every ceiling at its maximum is accepted as given.
    let widest = Limits {
        max_message_bytes: MAX_MESSAGE_BYTES,
        max_options: MAX_OPTIONS,
        max_nesting: MAX_NESTING,
    };
    assert_eq!(widest.validate(), Ok(()));
    assert!(Dhcpv4::from_wire_with_limits(v4_wire, widest).is_ok());
    assert!(Dhcpv6::from_wire_with_limits(v6_wire, widest).is_ok());
}
