// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use bytes::Bytes;
use packetcraftr_core::{
    build::Builder,
    decode::Dissector,
    expression,
    frame::{Frame, LinkType},
    layer::Malformed,
    protocol::{
        application::dhcp::{Dhcpv4, Dhcpv6, Duid, Error, Limit, Limits, Option4, Option6, Value6},
        builtin,
    },
};
use std::time::UNIX_EPOCH;
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
fn dhcp_limits_and_malformed_lengths_fail_without_losing_capture_bytes() {
    let wire = reply().to_wire().unwrap();
    assert_eq!(
        Dhcpv6::from_wire_with_limits(
            wire.clone(),
            Limits {
                max_options: 1,
                ..Default::default()
            }
        )
        .unwrap_err(),
        Error::Limit(Limit::OptionCount)
    );
    assert!(matches!(
        Dhcpv6::try_from(wire.slice(..wire.len() - 1)),
        Err(Error::Truncated {
            needed: 3,
            available: 2,
            ..
        })
    ));
    assert_eq!(
        Dhcpv4::try_from(vec![0; 239]).unwrap_err(),
        Error::Truncated {
            offset: 0,
            needed: 240,
            available: 239
        }
    );
    let mut relay = Dhcpv6::default();
    for _ in 0..9 {
        relay = Dhcpv6::relay_forward(
            0,
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            relay,
        );
    }
    assert_eq!(
        relay.to_wire().unwrap_err(),
        Error::Limit(Limit::RelayNesting)
    );
    let mut raw = Dhcpv6::default();
    raw.options = vec![Option6::raw(9, wire.clone())];
    assert_eq!(
        raw.to_wire_with_limits(Limits {
            max_nesting: 0,
            ..Default::default()
        })
        .unwrap_err(),
        Error::Limit(Limit::RelayNesting)
    );
    let mut invalid = Dhcpv4::default();
    invalid.file_options = vec![Option4::raw(220, Bytes::from(vec![1; 128]))];
    assert_eq!(
        invalid.to_wire().unwrap_err(),
        Error::Limit(Limit::EncodedBytes)
    );
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
    assert_eq!(decoded.frame.bytes().as_ref(), malformed);
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

    let widest = Limits {
        max_message_bytes: MAX_MESSAGE_BYTES,
        max_options: MAX_OPTIONS,
        max_nesting: MAX_NESTING,
    };
    assert_eq!(widest.validate(), Ok(()));
    assert!(Dhcpv4::from_wire_with_limits(v4_wire, widest).is_ok());
    assert!(Dhcpv6::from_wire_with_limits(v6_wire, widest).is_ok());
}
