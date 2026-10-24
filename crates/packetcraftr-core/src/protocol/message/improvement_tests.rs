// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use crate::{
    codec::{DecodeContext, Decoded},
    protocol::{builtin, framing::Framer},
};
use bytes::Bytes;

fn decode(name: &str, wire: &[u8]) -> Result<Decoded, crate::codec::Error> {
    let registry = builtin::registry();
    let decoded = registry.codec(name).unwrap().decode(
        Bytes::copy_from_slice(wire),
        &DecodeContext {
            parent: None,
            registry: &registry,
            network: None,
            hop_limit: None,
            discriminator: None,
        },
    )?;
    if decoded.layer.protocol_id().as_str() != name {
        return Err(crate::protocol::common::invalid(
            "test",
            "unsupported input retained raw",
        ));
    }
    Ok(decoded)
}

#[test]
fn improvement_text_targets_and_content_lengths() {
    for (name, version) in [("sip", "SIP/2.0"), ("rtsp", "RTSP/1.0")] {
        assert!(decode(name, format!("OPTIONS  {version}\r\n\r\n").as_bytes()).is_err());
        for length in ["0", " 0\t", "\t\r\n 0 "] {
            assert!(
                decode(
                    name,
                    format!("OPTIONS * {version}\r\nContent-Length:{length}\r\n\r\n").as_bytes()
                )
                .is_ok(),
                "{length:?}"
            );
        }
        for length in ["+0", "-0", "", "\u{b}0", "0\u{c}", "\u{a0}0", "0\r\n 0"] {
            assert!(
                decode(
                    name,
                    format!("OPTIONS * {version}\r\nContent-Length:{length}\r\n\r\n").as_bytes()
                )
                .is_err(),
                "{length:?}"
            );
        }
    }
}

#[test]
fn improvement_resp_framing_matches_canonical_decoder_and_depth() {
    for number in ["+1", "01", "-0", " 1"] {
        for tag in [":", "$", "*"] {
            let wire = format!("{tag}{number}\r\n");
            assert!(
                Framer::new("resp").progress(wire.as_bytes(), 4096).is_err(),
                "{wire:?}"
            );
            assert!(decode("resp", wire.as_bytes()).is_err());
        }
    }
    for leaf in [
        "+OK\r\n",
        ":0\r\n",
        "*0\r\n",
        "*-1\r\n",
        "$-1\r\n",
        "$0\r\n\r\n",
    ] {
        for depth in [15, 16] {
            let wire = format!("{}{leaf}", "*1\r\n".repeat(depth));
            let framed = Framer::new("resp").progress(wire.as_bytes(), 4096);
            assert_eq!(framed.is_ok(), depth == 15, "{leaf:?} at {depth}");
            assert_eq!(decode("resp", wire.as_bytes()).is_ok(), depth == 15);
        }
    }
    let wire = b"$9223372036854775807\r\n";
    assert!(Framer::new("resp").progress(wire, 4096).is_err());
    for wire in [b"$0\r\n\r\n".as_slice(), b"$3\r\nabc\r\n"] {
        assert_eq!(
            Framer::new("resp").progress(wire, 4096).unwrap(),
            Some(wire.len())
        );
    }
}

#[test]
fn improvement_resp_null_reflection_requires_canonical_empty_data() {
    use crate::{field::Value, layer::ReflectiveField, protocol::application::resp::RespValue};
    for (kind, good, bad) in [
        (
            "null_bulk",
            Value::Bytes(Bytes::new()),
            Value::Bytes(Bytes::from_static(b"discarded")),
        ),
        (
            "null_array",
            Value::List(vec![]),
            Value::List(vec![Value::Unsigned(1)]),
        ),
    ] {
        let value = |data| {
            Value::Object(
                [
                    ("kind".into(), Value::Text(kind.into())),
                    ("data".into(), data),
                ]
                .into(),
            )
        };
        let mut resp = RespValue::Integer(1);
        resp.set_reflective_value(value(good)).unwrap();
        assert!(resp.set_reflective_value(value(bad)).is_err());
        assert!(
            resp.set_reflective_value(value(Value::Bool(false)))
                .is_err()
        );
    }
}

fn slice<'a>(name: &str, field: &str, wire: &'a [u8]) -> &'a [u8] {
    let decoded = decode(name, wire).unwrap();
    let range = decoded
        .fields
        .iter()
        .find(|f| f.name == field)
        .unwrap()
        .range;
    &wire[range.start..range.end]
}

#[test]
fn improvement_application_layouts_expose_exact_content_ranges() {
    for (name, version) in [("sip", "SIP/2.0"), ("rtsp", "RTSP/1.0")] {
        let wire = format!("OPTIONS * {version}\r\nContent-Length:3\r\n\r\nabc");
        assert_eq!(slice(name, "body", wire.as_bytes()), b"abc");
        let empty = format!("OPTIONS * {version}\r\nContent-Length:0\r\n\r\n");
        assert_eq!(slice(name, "body", empty.as_bytes()), b"");
    }
    assert_eq!(slice("rtsp", "body", b"$\x02\0\x03abc"), b"abc");
    let mut memcached = vec![0x80, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 6];
    memcached.extend_from_slice(&[0; 12]);
    memcached.extend_from_slice(b"EKEval");
    for (field, expected) in [
        ("extras", b"E".as_slice()),
        ("key", b"KE"),
        ("value", b"val"),
    ] {
        assert_eq!(slice("memcached", field, &memcached), expected);
    }
    let ldap = b"\x30\x0a\x02\x01\x07\x65\x03\x0a\x01\0\xa0\0";
    for (field, expected) in [
        ("message_id", b"\x07".as_slice()),
        ("operation", b"\x65"),
        ("fields", b"\x0a\x01\0"),
        ("controls", b"\xa0\0"),
    ] {
        assert_eq!(slice("ldap", field, ldap), expected);
    }
    // Long-form lengths at both envelope and operation boundaries retain offsets.
    let mut operation = vec![4, 127];
    operation.extend([b'x'; 127]);
    let mut long_ldap = vec![0x30, 0x81, 137, 2, 1, 7, 0x65, 0x81, 129];
    long_ldap.extend_from_slice(&operation);
    long_ldap.extend_from_slice(&[0xa0, 0]);
    assert_eq!(slice("ldap", "message_id", &long_ldap), b"\x07");
    assert_eq!(slice("ldap", "fields", &long_ldap), operation);
    assert_eq!(slice("ldap", "controls", &long_ldap), b"\xa0\0");
    let coap = b"\x42\x01\0\x01TK\xb1x\x01y\xffPAY";
    for (field, expected) in [
        ("token", b"TK".as_slice()),
        ("options", b"\xb1x\x01y"),
        ("payload", b"PAY"),
    ] {
        assert_eq!(slice("coap", field, coap), expected);
    }
    for field in ["token", "options", "payload"] {
        assert_eq!(slice("coap", field, b"\x40\x01\0\x01"), b"");
    }
}

#[test]
fn improvement_mqtt_subscription_and_will_topics() {
    fn sized(value: &[u8], wire: &mut Vec<u8>) {
        wire.extend_from_slice(&(value.len() as u16).to_be_bytes());
        wire.extend_from_slice(value);
    }
    for topic in [
        b"a/+/#".as_slice(),
        b"+",
        b"#",
        b"/+/",
        b"a+",
        b"a/#/b",
        b"a/##",
        b"",
    ] {
        let valid = matches!(topic, b"a/+/#" | b"+" | b"#" | b"/+/");
        for packet_type in [8, 10] {
            let mut body = vec![0, 1];
            sized(topic, &mut body);
            if packet_type == 8 {
                body.push(0);
            }
            let mut wire = vec![packet_type << 4 | 2, body.len() as u8];
            wire.extend(body);
            assert_eq!(decode("mqtt", &wire).is_ok(), valid, "{topic:?}");
        }
    }
    for topic in [b"will/topic".as_slice(), b"", b"will/+", b"will/#"] {
        let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 4, 6, 0, 60, 0, 0];
        sized(topic, &mut body);
        sized(b"payload", &mut body);
        let mut wire = vec![0x10, body.len() as u8];
        wire.extend(body);
        assert_eq!(decode("mqtt", &wire).is_ok(), topic == b"will/topic");
    }
}
