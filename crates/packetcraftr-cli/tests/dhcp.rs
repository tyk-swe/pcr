// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod support;
use support::{parse_json, run_success, schema_validator};
#[test]
fn dhcp_fixtures_build_dissect_and_project_typed_fields() {
    let root =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/documents");
    let validator = schema_validator();
    for (file, protocol, link_type, path, expected) in [
        (
            "packet-dhcpv4-offer.json",
            "dhcpv4",
            "228",
            "dhcpv4.options[1].value.seconds",
            serde_json::json!(3600),
        ),
        (
            "packet-dhcpv6-reply.json",
            "dhcpv6",
            "229",
            "dhcpv6.options[1].value.options[0].value.address",
            serde_json::json!("2001:db8::10"),
        ),
    ] {
        let packet = root.join(file);
        let built = parse_json(&run_success(&[
            "--output",
            "json",
            "build",
            "--packet-file",
            packet.to_str().unwrap(),
        ]));
        assert!(validator.is_valid(&built));
        let hex = built["result"]["bytes_hex"].as_str().unwrap();
        let decoded = parse_json(&run_success(&[
            "--output",
            "json",
            "dissect",
            "--hex",
            hex,
            "--link-type",
            link_type,
        ]));
        assert_eq!(
            decoded["result"]["dissection"]["packet"]["layers"][2]["protocol"],
            protocol
        );
        assert_eq!(decoded["result"]["dissection"]["bytes_hex"], hex);
        let projected = parse_json(&run_success(&[
            "--output",
            "json",
            "dissect",
            "--hex",
            hex,
            "--link-type",
            link_type,
            "--field",
            path,
        ]));
        assert_eq!(projected["result"]["rows"][0]["values"][0], expected);
    }
}
#[test]
fn recursive_field_discovery_uses_resolvable_compact_references() {
    let output = run_success(&["--output", "json", "protocols", "dhcpv6"]);
    assert!(output.stdout.len() < 200_000);
    let document = parse_json(&output);
    assert!(schema_validator().is_valid(&document));
    fn visit(value: &serde_json::Value, root: &serde_json::Value, references: &mut usize) {
        if let Some(reference) = value
            .get("children_reference")
            .and_then(serde_json::Value::as_str)
        {
            assert!(
                root.pointer(reference)
                    .is_some_and(serde_json::Value::is_array)
            );
            *references += 1;
        }
        if let Some(children) = value.get("children").and_then(serde_json::Value::as_array) {
            for child in children {
                visit(child, root, references);
            }
        }
    }
    let mut references = 0;
    for field in document["result"]["protocol"]["fields"].as_array().unwrap() {
        visit(field, field, &mut references);
    }
    assert!(references > 0);
}
