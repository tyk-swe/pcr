// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use packetcraftr_core::{
    document::{Format, payload, recipe},
    error::{Classified, Kind},
    expression,
    field::FieldValue,
    packet::DEFAULT_MAX_LAYERS,
    packet::Packet,
    protocol::builtin,
};

const RAW_YAML: &str = include_str!("../../../examples/documents/packet-raw.yaml");
const IPV4_UDP_JSON: &str = include_str!("../../../examples/documents/packet-ipv4-udp.json");
const RECIPE: &str = "ipv4(src=192.0.2.1,dst=192.0.2.2)/udp(sport=9000,dport=9001)/raw()";

fn recipe(input: &str, declared: Option<Format>) -> Result<Packet, recipe::Error> {
    recipe::parse(input, declared, &builtin::registry(), DEFAULT_MAX_LAYERS)
}

fn names(packet: &Packet) -> Vec<String> {
    packet
        .iter()
        .map(|layer| layer.protocol_id().as_str().to_owned())
        .collect()
}

#[test]
fn recipes_read_as_documents_or_expressions() {
    assert_eq!(
        names(&recipe(RECIPE, None).unwrap()),
        ["ipv4", "udp", "raw"]
    );
    assert_eq!(names(&recipe(RAW_YAML, None).unwrap()), ["raw"]);
    assert_eq!(
        names(&recipe(&format!("\n  {IPV4_UDP_JSON}"), None).unwrap()),
        ["ethernet", "ipv4", "udp", "raw"]
    );
    let unmarked = RAW_YAML.replacen("schema: packetcraftr.packet/v2\n", "", 1)
        + "schema: packetcraftr.packet/v2\n";
    assert_eq!(names(&recipe(&unmarked, None).unwrap()), ["raw"]);
}

#[test]
fn a_declared_format_is_not_second_guessed() {
    let error = recipe(RAW_YAML, Some(Format::Json)).expect_err("YAML is not JSON");
    assert!(matches!(error, recipe::Error::Document(_)), "{error:?}");
    assert_eq!(error.classification().code, "cli.document_syntax");
    assert_eq!(
        names(&recipe(IPV4_UDP_JSON, Some(Format::Yaml)).unwrap()),
        ["ethernet", "ipv4", "udp", "raw"]
    );
    let error = recipe(RECIPE, Some(Format::Yaml)).expect_err("an expression is not YAML");
    assert!(matches!(error, recipe::Error::Document(_)), "{error:?}");
}

#[test]
fn unrecognized_text_reports_the_expression_failure_with_the_document_failure_as_cause() {
    let error = recipe("::: [ nope", None).expect_err("neither form");
    assert!(
        matches!(error, recipe::Error::Unrecognized { .. }),
        "{error:?}"
    );
    let classification = error.classification();
    assert_eq!(
        (classification.code, classification.kind),
        ("cli.expression_syntax", Kind::Usage)
    );
    assert!(error.to_string().starts_with("expression syntax error"));
    let causes = error.causes();
    assert_eq!(
        causes.first().map(String::as_str),
        Some("could not parse YAML packet document")
    );
    assert!(causes.len() >= 2, "{causes:?}");
}

fn syntax_error(source: &str) -> (usize, String) {
    match expression::parse(source, &builtin::registry(), expression::Limits::default()) {
        Err(expression::Error::Syntax { offset, message }) => (offset, message),
        other => panic!("{source}: expected a syntax error, got {other:?}"),
    }
}

#[test]
fn expression_syntax_errors_point_into_the_whole_expression() {
    for (marked, message) in [
        ("ethernet()/|/ipv4", "empty layer"),
        ("ethernet()/ |(ttl=1)", "missing protocol name"),
        (
            "ethernet()/ipv4|(ttl=1) x",
            "layer arguments must end with ')'",
        ),
        (
            "ethernet()/ipv4(ttl=1, |flags)",
            "expected field=value, got  flags",
        ),
        ("ethernet()/ipv4(ttl=1, |=2)", "empty field name"),
        ("ethernet()/ipv4(ttl=|)", "missing field value"),
        ("ethernet()/ipv4(ttl= |)", "missing field value"),
        ("ethernet()/  ipv4( ttl = |)", "missing field value"),
        (
            "ethernet()/ipv4(label=\"\u{e9}\", ttl=|)",
            "missing field value",
        ),
        ("ethernet()/ipv4(ttl=[1, |])", "missing field value"),
        ("ethernet()/ipv4(options={a=|})", "missing field value"),
        (
            "ethernet()/raw(payload=|bytes(\"a\") x)",
            "unterminated byte literal",
        ),
        (
            "ethernet()/raw(payload=hex(|\"abc\"))",
            "hex literal requires pairs of hexadecimal digits",
        ),
        ("ethernet()/ipv4(options=|[1] x)", "unterminated list"),
        ("ethernet()/ipv4(options=|{a=1} x)", "unterminated object"),
        (
            "ethernet()/ipv4(ttl=1,  options =  |[1] x)",
            "unterminated list",
        ),
        (
            "ethernet()/ipv4(options={a=1, |b})",
            "expected object field=value",
        ),
        (
            "ethernet()/ipv4(options={a=1, |bad name=2})",
            "invalid object field name",
        ),
        (
            "ethernet()/ipv4(options={a=1, |a=2})",
            "duplicate object field a",
        ),
        (
            "ethernet()/ipv4(ttl=|0xzz)",
            "invalid hexadecimal integer 0xzz",
        ),
        (
            "ethernet()/ipv4(label=|\"abc\" x)",
            "unterminated quoted string",
        ),
        (
            "ethernet()/ipv4(label=\"a\\|q\")",
            "unsupported escape `\\q`",
        ),
        (
            "ethernet()/ipv4(label=\"a|\"\"b\")",
            "unescaped quote in quoted string",
        ),
        ("tcp(a=[1|), b=(2])", "unexpected ')'"),
        ("ethernet()/tcp(a=[1|), b=(2])", "unexpected ')'"),
    ] {
        let expected = marked.find('|').expect("every case marks its offset");
        let source = marked.replacen('|', "", 1);
        let (offset, actual) = syntax_error(&source);
        assert_eq!(offset, expected, "{source}: {actual}");
        assert_eq!(actual, message, "{source}");
    }
}

#[test]
fn a_bare_value_reports_syntax_errors_against_the_text_it_was_given() {
    let error = expression::parse_value("  [1, ]", expression::Limits::default())
        .expect_err("empty list element");
    assert!(
        matches!(error, expression::Error::Syntax { offset: 6, .. }),
        "{error:?}"
    );
}

fn target(selector: &str) -> payload::Target {
    selector.parse().expect("valid target")
}

#[test]
fn a_payload_target_fills_one_empty_bytes_field() {
    let mut packet = recipe(RECIPE, None).unwrap();
    target("2.BYTES")
        .inject(&mut packet, || {
            Ok::<_, payload::Error>(Bytes::from_static(b"\xde\xad"))
        })
        .unwrap();
    assert_eq!(
        packet.layer(2).unwrap().field("bytes"),
        Some(FieldValue::Bytes(Bytes::from_static(b"\xde\xad")))
    );
}

#[test]
fn a_refused_payload_target_never_loads_its_bytes() {
    let occupied = "ipv4()/udp()/raw(hex=\"aa\")";
    for (recipe_text, selector, message) in [
        (
            RECIPE,
            "9.bytes",
            "payload layer index 9 is outside the recipe's 3 layers",
        ),
        (RECIPE, "2.nope", "payload field nope is unknown on layer 2"),
        (RECIPE, "2.a..b", "payload field a..b is unknown on layer 2"),
        (
            RECIPE,
            "1.source_port",
            "payload field source_port on layer 1 is not bytes-typed",
        ),
        (
            occupied,
            "2.bytes",
            "payload field bytes on layer 2 already holds recipe bytes",
        ),
    ] {
        let mut packet = recipe(recipe_text, None).unwrap();
        let error = target(selector)
            .inject(&mut packet, || -> Result<Bytes, payload::Error> {
                panic!("{selector} loaded its bytes")
            })
            .expect_err("refused");
        assert_eq!(error.to_string(), message);
        let classification = error.classification();
        assert_eq!(
            (classification.code, classification.kind),
            ("cli.error", Kind::Usage)
        );
        assert!(error.causes().is_empty());
    }
}
