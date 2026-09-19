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
    let path = "options[0].value.message.options[1].value.options[0].value.address";
    assert_eq!(
        decoded.field_path(path),
        Some(FieldValue::Ipv6("2001:db8::10".parse().unwrap()))
    );
    decoded
        .set_field_path(path, FieldValue::Ipv6("2001:db8::11".parse().unwrap()))
        .unwrap();
    let changed = decoded.to_wire().unwrap();
    let parsed = Dhcpv6::try_from(changed).unwrap();
    assert_eq!(
        parsed.field_path(path),
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
