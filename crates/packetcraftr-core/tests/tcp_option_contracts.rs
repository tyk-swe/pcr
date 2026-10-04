// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;

use bytes::Bytes;
use common::packets::{dissect, ipv4};
use packetcraftr_core::{
    build::Builder,
    error::render,
    expression,
    packet::Packet,
    protocol::builtin,
    protocol::transport::{Tcp, TcpOption},
};

const OPTIONS_OUT_OF_RANGE: &str = "field options on layer tcp is outside the allowed range";

fn reencode(packet: Packet) -> Bytes {
    Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .unwrap()
        .bytes
}

#[test]
fn unknown_bad_tcp_opts_keep_exact_wire_bytes() {
    let mut packet = Packet::new();
    packet.push(ipv4([192, 0, 2, 1], [198, 51, 100, 2]));
    packet.push(Tcp {
        source_port: 40_000,
        destination_port: 443,
        options: vec![
            TcpOption::Raw {
                kind: 30,
                data: Bytes::from_static(&[9, 9]),
            },
            TcpOption::Raw {
                kind: 2,
                data: Bytes::from_static(&[1, 2, 3]),
            },
            TcpOption::Trailing(Bytes::from_static(&[4, 0xee])),
        ],
        ..Tcp::default()
    });
    packet.push(packetcraftr_core::layer::Raw::new(b"payload".to_vec()));
    let built = Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .unwrap();
    // 4 + 5 + 2 = 11 option bytes padded to 12; wire keeps them verbatim.
    let options_area = &built.bytes[40..52];
    assert_eq!(
        options_area,
        &[30, 4, 9, 9, 2, 5, 1, 2, 3, 4, 0xee, 0],
        "unknown, nonstandard-length, and malformed bytes stay in order"
    );
    let decoded = dissect(built.bytes.clone());
    let tcp = decoded.packet.get::<Tcp>().unwrap();
    assert!(matches!(
        tcp.options.as_slice(),
        [
            TcpOption::Raw { kind: 30, .. },
            TcpOption::Raw { kind: 2, .. },
            TcpOption::Trailing(_)
        ]
    ));
    let [.., TcpOption::Trailing(tail)] = tcp.options.as_slice() else {
        panic!("options must end in trailing bytes");
    };
    assert_eq!(tail.as_ref(), &[4, 0xee, 0]);
    assert_eq!(reencode(decoded.packet.clone()), built.bytes);
}

#[test]
fn tcp_opts_byte_input() {
    let registry = builtin::registry();
    let prefix = "ipv4(source=192.0.2.1,destination=198.51.100.2)/";
    for (options, refusal) in [
        ("[{kind=0,data=hex(\"aa\")}]", OPTIONS_OUT_OF_RANGE),
        ("[{kind=1,data=hex(\"aa\")}]", OPTIONS_OUT_OF_RANGE),
        ("[{trailing=hex(\"aa\")},{kind=1}]", OPTIONS_OUT_OF_RANGE),
        (
            "[{kind=2,window_scale=7}]",
            "required field options.mss is absent",
        ),
        (
            "[{kind=3,mss=1460}]",
            "required field options.window_scale is absent",
        ),
        (
            "[{kind=8,tsval=1}]",
            "required field options.tsecr is absent",
        ),
        // Forty-one bytes of options exceed the TCP data-offset limit.
        (
            "hex(\"020405b401010101010101010101010101010101010101010101010101010101010101010101010101\")",
            OPTIONS_OUT_OF_RANGE,
        ),
        // Five SACK blocks need 42 option bytes.
        (
            "[{kind=5,sack=[{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2}]}]",
            OPTIONS_OUT_OF_RANGE,
        ),
    ] {
        let recipe = format!("{prefix}tcp(options={options})");
        let Err(error) = expression::parse(&recipe, &registry, Default::default()) else {
            panic!("{recipe} must be refused while parsing");
        };
        let rendered = render(&error);
        assert!(rendered.contains(refusal), "{recipe}: {rendered}");
    }
    let largest = expression::parse(
        "ipv4(source=192.0.2.1,destination=198.51.100.2)/tcp(options=hex(\"020405b4010101010101010101010101010101010101010101010101010101010101010101010101\"))",
        &registry,
        Default::default(),
    )
    .unwrap();
    Builder::new(registry.clone())
        .build(largest, Default::default(), Default::default())
        .expect("forty option bytes fit the TCP data offset");
    let packet = expression::parse(
        "tcp(options=hex(\"020405b401030307\"))",
        &registry,
        Default::default(),
    )
    .unwrap();
    let tcp = packet.get::<Tcp>().unwrap();
    assert_eq!(
        tcp.options,
        vec![
            TcpOption::Mss(1460),
            TcpOption::Nop,
            TcpOption::WindowScale(7)
        ]
    );
}
