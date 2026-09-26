// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Packet recipes: format detection, the expression-then-YAML fallback, and
//! payload targets.

use bytes::Bytes;
use packetcraftr_core::{
    document::{Format, PayloadError, PayloadTarget, RecipeError, parse_recipe},
    error::{Classified, Kind},
    field::FieldValue,
    layout::DEFAULT_MAX_LAYERS,
    packet::Packet,
    protocol::builtin,
};

const RAW_YAML: &str = include_str!("../../../examples/documents/packet-raw.yaml");
const IPV4_UDP_JSON: &str = include_str!("../../../examples/documents/packet-ipv4-udp.json");
const RECIPE: &str = "ipv4(src=192.0.2.1,dst=192.0.2.2)/udp(sport=9000,dport=9001)/raw()";

fn recipe(input: &str, declared: Option<Format>) -> Result<Packet, RecipeError> {
    parse_recipe(input, declared, &builtin::registry(), DEFAULT_MAX_LAYERS)
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
    // A YAML document without a leading marker is still a document.
    let unmarked = RAW_YAML.replacen("schema: packetcraftr.packet/v2\n", "", 1)
        + "schema: packetcraftr.packet/v2\n";
    assert_eq!(names(&recipe(&unmarked, None).unwrap()), ["raw"]);
}

#[test]
fn a_declared_format_is_not_second_guessed() {
    let error = recipe(RAW_YAML, Some(Format::Json)).expect_err("YAML is not JSON");
    assert!(matches!(error, RecipeError::Document(_)), "{error:?}");
    assert_eq!(error.classification().code, "cli.document_syntax");
    assert_eq!(
        names(&recipe(IPV4_UDP_JSON, Some(Format::Yaml)).unwrap()),
        ["ethernet", "ipv4", "udp", "raw"]
    );
    let error = recipe(RECIPE, Some(Format::Yaml)).expect_err("an expression is not YAML");
    assert!(matches!(error, RecipeError::Document(_)), "{error:?}");
}

#[test]
fn unrecognized_text_reports_the_expression_failure_with_the_document_failure_as_cause() {
    let error = recipe("::: [ nope", None).expect_err("neither form");
    assert!(
        matches!(error, RecipeError::Unrecognized { .. }),
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

fn target(selector: &str) -> PayloadTarget {
    selector.parse().expect("valid target")
}

#[test]
fn a_payload_target_fills_one_empty_bytes_field() {
    let mut packet = recipe(RECIPE, None).unwrap();
    target("2.BYTES")
        .inject(&mut packet, || {
            Ok::<_, PayloadError>(Bytes::from_static(b"\xde\xad"))
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
            "--payload-file layer index 9 is outside the recipe's 3 layers",
        ),
        (
            RECIPE,
            "2.nope",
            "--payload-file field nope is unknown on layer 2",
        ),
        (
            RECIPE,
            "2.a..b",
            "--payload-file field a..b is unknown on layer 2",
        ),
        (
            RECIPE,
            "1.source_port",
            "--payload-file field source_port on layer 1 is not bytes-typed",
        ),
        (
            occupied,
            "2.bytes",
            "--payload-file field bytes on layer 2 already holds recipe bytes",
        ),
    ] {
        let mut packet = recipe(recipe_text, None).unwrap();
        let error = target(selector)
            .inject(&mut packet, || -> Result<Bytes, PayloadError> {
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
