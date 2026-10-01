// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use std::time::SystemTime;

use bytes::Bytes;
use common::packets::ipv4;
use packetcraftr_core::field::FieldValue;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::{Layer, Raw};
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::application::syslog::{
    MAX_MESSAGE_BYTES, MAX_STRUCTURED_DATA_ELEMENTS, Syslog, SyslogFormat,
};
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::transport::Udp;
use packetcraftr_core::{build, codec, decode};

const RFC5424_EXAMPLE: &[u8] = b"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"] \xef\xbb\xbfAn application event log entry...";
const RFC3164_EXAMPLE: &[u8] =
    b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8";

fn packet(payload: impl Layer) -> Packet {
    let mut packet = Packet::new();
    packet.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    packet.push(Udp {
        source_port: 40_000,
        destination_port: 514,
        ..Udp::default()
    });
    packet.push(payload);
    packet
}

fn build_with(packet: Packet, mode: codec::Mode) -> Result<build::BuiltPacket, build::Error> {
    build::Builder::new(builtin::registry()).build(
        packet,
        codec::Context::default(),
        build::Options {
            mode,
            ..build::Options::default()
        },
    )
}

fn dissect(bytes: impl Into<Bytes>) -> decode::DecodedPacket {
    let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::IPV4, bytes).unwrap();
    decode::Dissector::new(builtin::registry())
        .decode(frame, decode::Options::default())
        .unwrap()
}

/// A datagram to UDP 514 holding exactly `message`.
fn datagram(message: &[u8]) -> Bytes {
    build_with(packet(Raw::new(message.to_vec())), codec::Mode::Permissive)
        .unwrap()
        .bytes
}

fn protocols(decoded: &decode::DecodedPacket) -> Vec<&str> {
    decoded
        .packet
        .iter()
        .map(|layer| layer.protocol_id().as_str())
        .collect()
}

/// Dissects `message` and requires a strict rebuild to reproduce the datagram.
fn typed(message: &[u8]) -> Syslog {
    let wire = datagram(message);
    let decoded = dissect(wire.clone());
    assert_eq!(protocols(&decoded), ["ipv4", "udp", "syslog"]);
    assert!(decoded.diagnostics.is_empty(), "{:?}", decoded.diagnostics);
    let rebuilt = build_with(decoded.packet.clone(), codec::Mode::Strict).unwrap();
    assert_eq!(rebuilt.bytes, wire);
    decoded.packet.get::<Syslog>().unwrap().clone()
}

fn is_raw(message: &[u8]) -> bool {
    let decoded = dissect(datagram(message));
    let raw = protocols(&decoded) == ["ipv4", "udp", "raw"];
    if raw {
        assert_eq!(decoded.packet.get::<Raw>().unwrap().bytes.as_ref(), message);
    }
    raw
}

#[test]
fn rfc_5424_messages_expose_their_fields_and_reencode_identically() {
    let syslog = typed(RFC5424_EXAMPLE);
    assert_eq!((syslog.facility, syslog.severity), (20, 5));
    assert_eq!(syslog.format, SyslogFormat::Rfc5424);
    assert_eq!(syslog.version.as_ref(), b"1");
    assert_eq!(syslog.timestamp.as_ref(), b"2003-10-11T22:14:15.003Z");
    assert_eq!(syslog.hostname.as_ref(), b"mymachine.example.com");
    assert_eq!(syslog.app_name.as_ref(), b"evntslog");
    assert_eq!(syslog.procid.as_ref(), b"-");
    assert_eq!(syslog.msgid.as_ref(), b"ID47");
    assert_eq!(
        syslog.structured_data.as_ref(),
        &b"[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"]"[..]
    );
    assert_eq!(
        syslog.message.as_deref(),
        Some(&b"\xef\xbb\xbfAn application event log entry..."[..])
    );
    assert_eq!(syslog.field("facility"), Some(FieldValue::Unsigned(20)));
    assert_eq!(
        syslog.field("format"),
        Some(FieldValue::Text("rfc5424".to_owned()))
    );

    // an element's escaped bracket does not end it
    let escaped = typed(b"<14>1 - h a - - [id@1 k=\"a\\]b\"] text");
    assert_eq!(escaped.structured_data.as_ref(), &b"[id@1 k=\"a\\]b\"]"[..]);
    assert_eq!(escaped.message.as_deref(), Some(&b"text"[..]));
}

#[test]
fn rfc_3164_messages_keep_every_byte_after_the_priority() {
    let syslog = typed(RFC3164_EXAMPLE);
    assert_eq!((syslog.facility, syslog.severity), (4, 2));
    assert_eq!(syslog.format, SyslogFormat::Rfc3164);
    assert_eq!(
        syslog.message.as_deref(),
        Some(&b"Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"[..])
    );
    assert!(syslog.hostname.is_empty() && syslog.structured_data.is_empty());

    // shapes that only resemble RFC 5424 stay legacy text
    for message in [
        &b"<34>1 not enough header fields"[..],
        b"<34>2024-01-02T10:00:00Z host app: ISO timestamp without a version",
        b"<34>1 t h a p m [unterminated",
        b"<34>1 t h a p m -x",
        b"<34>0 t h a p m - zero version",
        b"<13>",
    ] {
        let syslog = typed(message);
        assert_eq!(syslog.format, SyslogFormat::Rfc3164, "{message:?}");
        assert_eq!(
            syslog.message.as_deref(),
            Some(&message[message.iter().position(|b| *b == b'>').unwrap() + 1..])
        );
    }
}

#[test]
fn nothing_is_normalised_and_invalid_utf8_is_preserved() {
    let syslog = typed(b"<14>1 - - - - - - \xff\xfe\x00 odd");
    assert_eq!(syslog.message.as_deref(), Some(&b"\xff\xfe\x00 odd"[..]));

    // a message that is absent differs from an empty one
    assert_eq!(typed(b"<14>1 - - - - - -").message, None);
    assert_eq!(
        typed(b"<14>1 - - - - - - ").message.as_deref(),
        Some(&b""[..])
    );
    assert_eq!(typed(b"<0>1 - - - - - -").facility, 0);
    let top = typed(b"<191>1 - - - - - -");
    assert_eq!((top.facility, top.severity), (23, 7));
}

#[test]
fn invalid_priorities_and_oversized_messages_decode_as_raw() {
    for message in [
        &b"<192>1 - - - - - -"[..],
        b"<999>hello",
        b"<34 missing close",
        b"<34",
        b"<>1 - - - - - -",
        b"<a>hello",
        b"<-1>hello",
        b"<1234>hello",
        b"<034>hello",
        b"<00>hello",
        b"34>hello",
        b" <34>hello",
        b"hello",
    ] {
        assert!(is_raw(message), "{message:?}");
    }

    let mut oversized = b"<14>".to_vec();
    oversized.resize(MAX_MESSAGE_BYTES + 1, b'x');
    assert!(is_raw(&oversized));
    oversized.pop();
    assert!(!is_raw(&oversized), "exactly at the cap is typed");
}

#[test]
fn structured_data_element_count_is_bounded() {
    let message = |elements: usize| {
        let mut message = b"<14>1 - - - - - ".to_vec();
        for _ in 0..elements {
            message.extend_from_slice(b"[a@1 k=\"v\"]");
        }
        message.extend_from_slice(b" text");
        message
    };
    let at_limit = typed(&message(MAX_STRUCTURED_DATA_ELEMENTS));
    assert_eq!(at_limit.format, SyslogFormat::Rfc5424);
    assert_eq!(
        at_limit.structured_data.len(),
        MAX_STRUCTURED_DATA_ELEMENTS * 11
    );
    assert!(is_raw(&message(MAX_STRUCTURED_DATA_ELEMENTS + 1)));
}

#[test]
fn building_enforces_the_priority_range_and_header_shape() {
    let strict = |syslog: Syslog| build_with(packet(syslog), codec::Mode::Strict);
    let permissive = |syslog: Syslog| build_with(packet(syslog), codec::Mode::Permissive);

    let built = strict(Syslog {
        facility: 23,
        severity: 7,
        ..Syslog::default()
    })
    .unwrap();
    assert_eq!(&built.bytes[28..], b"<191>1 - - - - - -");

    let out_of_range = Syslog {
        facility: 24,
        severity: 0,
        ..Syslog::default()
    };
    assert!(strict(out_of_range.clone()).is_err());
    let built = permissive(out_of_range).unwrap();
    assert!(
        built
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.syslog_priority")
    );
    assert_eq!(&built.bytes[28..], b"<192>1 - - - - - -");
    // what the decoder would not accept as a priority comes back as raw bytes
    assert_eq!(protocols(&dissect(built.bytes)), ["ipv4", "udp", "raw"]);

    let mut layer = Syslog::default();
    assert!(
        layer
            .set_field("facility", FieldValue::Unsigned(32))
            .is_err()
    );
    assert!(
        layer
            .set_field("severity", FieldValue::Unsigned(8))
            .is_err()
    );
    assert!(
        layer
            .set_field("format", FieldValue::Text("rfc9999".to_owned()))
            .is_err()
    );
    layer
        .set_field("hostname", FieldValue::Text("host".to_owned()))
        .unwrap();
    assert_eq!(layer.hostname.as_ref(), b"host");

    for (label, syslog) in [
        (
            "space in a header field",
            Syslog {
                hostname: Bytes::from_static(b"two words"),
                ..Syslog::default()
            },
        ),
        (
            "empty header field",
            Syslog {
                timestamp: Bytes::new(),
                ..Syslog::default()
            },
        ),
        (
            "hostname over 255 bytes",
            Syslog {
                hostname: Bytes::from(vec![b'h'; 256]),
                ..Syslog::default()
            },
        ),
        (
            "bad structured data",
            Syslog {
                structured_data: Bytes::from_static(b"[open"),
                ..Syslog::default()
            },
        ),
        (
            "RFC 5424 field on a legacy message",
            Syslog {
                format: SyslogFormat::Rfc3164,
                ..Syslog::default()
            },
        ),
    ] {
        assert!(strict(syslog).is_err(), "{label}");
    }
    // a space would split the header, so no mode may emit it
    assert!(
        permissive(Syslog {
            hostname: Bytes::from_static(b"two words"),
            ..Syslog::default()
        })
        .is_err()
    );
    // the other deviations are diagnosed in permissive mode
    let built = permissive(Syslog {
        timestamp: Bytes::new(),
        ..Syslog::default()
    })
    .unwrap();
    assert!(
        built
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.syslog_header")
    );

    let oversized = Syslog {
        message: Some(Bytes::from(vec![b'x'; MAX_MESSAGE_BYTES])),
        ..Syslog::default()
    };
    assert!(permissive(oversized).is_err());
}

#[test]
fn deviating_headers_are_diagnosed_and_reencode_in_permissive_mode() {
    // a doubled separator leaves the timestamp empty
    let wire = datagram(b"<14>1  host app - - - message");
    let decoded = dissect(wire.clone());
    assert_eq!(protocols(&decoded), ["ipv4", "udp", "syslog"]);
    let diagnostic = decoded
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "decode.syslog_header")
        .expect("the empty timestamp is diagnosed");
    assert_eq!(diagnostic.field, Some("timestamp"));
    assert!(build_with(decoded.packet.clone(), codec::Mode::Strict).is_err());
    let rebuilt = build_with(decoded.packet, codec::Mode::Permissive).unwrap();
    assert_eq!(rebuilt.bytes, wire);
}

#[test]
fn constructed_messages_round_trip_through_the_wire() {
    let built = build_with(
        packet(Syslog {
            facility: 3,
            severity: 4,
            timestamp: Bytes::from_static(b"2026-01-02T03:04:05Z"),
            hostname: Bytes::from_static(b"gw"),
            app_name: Bytes::from_static(b"sshd"),
            procid: Bytes::from_static(b"812"),
            msgid: Bytes::from_static(b"AUTH"),
            structured_data: Bytes::from_static(b"[a@1 b=\"c\"]"),
            message: Some(Bytes::from_static(b"denied")),
            ..Syslog::default()
        }),
        codec::Mode::Strict,
    )
    .unwrap();
    assert_eq!(
        &built.bytes[28..],
        b"<28>1 2026-01-02T03:04:05Z gw sshd 812 AUTH [a@1 b=\"c\"] denied"
    );
    let syslog = typed(&built.bytes[28..]);
    assert_eq!((syslog.facility, syslog.severity), (3, 4));
    assert_eq!(syslog.app_name.as_ref(), b"sshd");

    let legacy = build_with(
        packet(Syslog {
            format: SyslogFormat::Rfc3164,
            version: Bytes::new(),
            timestamp: Bytes::new(),
            hostname: Bytes::new(),
            app_name: Bytes::new(),
            procid: Bytes::new(),
            msgid: Bytes::new(),
            structured_data: Bytes::new(),
            message: Some(Bytes::from_static(b"Jan  2 03:04:05 gw sshd: denied")),
            ..Syslog::default()
        }),
        codec::Mode::Strict,
    )
    .unwrap();
    assert_eq!(&legacy.bytes[28..], b"<14>Jan  2 03:04:05 gw sshd: denied");
}

#[test]
fn naming_only_the_legacy_format_in_a_recipe_builds_a_legacy_message() {
    let registry = builtin::registry();
    let recipe = |syslog: &str| {
        let text = format!(
            "ipv4(source=192.0.2.1,destination=192.0.2.2)/udp(source_port=40000,destination_port=514)/{syslog}"
        );
        let packet = packetcraftr_core::expression::parse(&text, &registry, Default::default())
            .expect("recipe parses");
        build_with(packet, codec::Mode::Strict)
    };

    let legacy = recipe(r#"syslog(format="rfc3164",message="hello")"#).unwrap();
    assert_eq!(&legacy.bytes[28..], b"<14>hello");

    // a value the caller set stays and is still refused on a legacy message
    assert!(recipe(r#"syslog(format="rfc3164",hostname="gw",message="hello")"#).is_err());

    // naming the default format changes nothing, including deliberate blanks
    let blank = recipe(r#"syslog(format="rfc5424",app_name="-",message="hello")"#).unwrap();
    assert_eq!(&blank.bytes[28..], b"<14>1 - - - - - - hello");
}

#[test]
fn switching_the_format_of_a_layer_moves_the_untouched_header_defaults() {
    let mut syslog = Syslog::default();
    syslog
        .set_field("format", FieldValue::Text("rfc3164".to_owned()))
        .unwrap();
    assert!(syslog.version.is_empty() && syslog.structured_data.is_empty());

    syslog
        .set_field("format", FieldValue::Text("rfc5424".to_owned()))
        .unwrap();
    assert_eq!(syslog, Syslog::default());
}
