// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use jsonschema::Validator;
use packetcraftr::packet::document::{Format, Packet as PacketDocument};
use packetcraftr::{
    error::{Classification, Kind},
    output::{
        contract::Command as CommandName,
        envelope::{AggregateError, Error as OutputError, StreamError},
    },
};
use serde_json::{Value, json};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn json_file(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn validator(name: &str) -> Validator {
    let schema = json_file(root().join("schemas").join(name));
    jsonschema::draft202012::meta::validate(&schema)
        .unwrap_or_else(|error| panic!("{name} is not valid Draft 2020-12: {error}"));
    jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .unwrap()
}

#[test]
fn committed_schemas_and_every_document_example_validate() {
    let packet = validator("packetcraftr.packet.v1.schema.json");
    let output = validator("packetcraftr.output.v1.schema.json");
    let examples = root().join("examples/documents");

    for entry in fs::read_dir(&examples).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy();
        if name.starts_with("packet-") {
            let value = match path.extension().and_then(|extension| extension.to_str()) {
                Some("json") => json_file(&path),
                Some("yaml") => {
                    let input = fs::read_to_string(&path).unwrap();
                    serde_json::to_value(
                        PacketDocument::parse(&input, Format::Yaml, 1024 * 1024).unwrap(),
                    )
                    .unwrap()
                }
                _ => continue,
            };
            assert!(
                packet.is_valid(&value),
                "{name}: {:?}",
                packet.iter_errors(&value).collect::<Vec<_>>()
            );
        } else if name.starts_with("output-") && path.extension().is_some_and(|ext| ext == "json") {
            let value = json_file(&path);
            assert!(
                output.is_valid(&value),
                "{name}: {:?}",
                output.iter_errors(&value).collect::<Vec<_>>()
            );
        }
    }
}

#[test]
fn output_schema_command_vocabulary_matches_the_authoritative_contract() {
    let schema = json_file(root().join("schemas/packetcraftr.output.v1.schema.json"));
    let command_enum = schema["$defs"]["baseEnvelope"]["properties"]["command"]["enum"]
        .as_array()
        .unwrap();
    assert!(command_enum.iter().any(Value::is_null));

    let schema_command_names = command_enum
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let schema_commands = schema_command_names
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let contract_commands = CommandName::ALL
        .iter()
        .map(|command| command.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let schema_only = schema_commands
        .difference(&contract_commands)
        .cloned()
        .collect::<Vec<_>>();
    let contract_only = contract_commands
        .difference(&schema_commands)
        .cloned()
        .collect::<Vec<_>>();

    assert_eq!(
        schema_command_names.len(),
        schema_commands.len(),
        "output schema repeats a serialized command name"
    );
    assert!(
        schema_only.is_empty() && contract_only.is_empty(),
        "commands present in the output schema but absent from the authoritative contract: {schema_only:?}; commands present in the authoritative contract but absent from the output schema: {contract_only:?}"
    );
}

#[test]
fn every_relevant_command_golden_validates_against_the_output_schema() {
    let output = validator("packetcraftr.output.v1.schema.json");
    let examples = root().join("examples/documents");

    for command in CommandName::ALL {
        for suffix in ["success", "event", "complete", "error"] {
            let name = format!("output-{}-{suffix}.json", command.as_str());
            let path = examples.join(&name);
            if !path.is_file() {
                continue;
            }
            let value = json_file(&path);
            assert_eq!(value["command"], command.as_str(), "{name}");
            assert!(
                output.is_valid(&value),
                "{name}: {:?}",
                output.iter_errors(&value).collect::<Vec<_>>()
            );
        }
    }
}

#[test]
fn structured_error_envelope_for_every_command_validates_against_the_output_schema() {
    let output = validator("packetcraftr.output.v1.schema.json");
    let classification = Classification::new("test.output_contract", Kind::Cli, None);

    for command in CommandName::ALL {
        let error = OutputError::new(classification, "contract test error", Vec::new());
        let aggregate =
            serde_json::to_value(AggregateError::error(Some(*command), error.clone())).unwrap();
        let stream = serde_json::to_value(StreamError::error(Some(*command), 0, error)).unwrap();

        for (mode, value) in [("aggregate", aggregate), ("stream", stream)] {
            assert!(
                output.is_valid(&value),
                "{command} {mode}: {:?}",
                output.iter_errors(&value).collect::<Vec<_>>()
            );
        }
    }
}

#[test]
fn output_schema_rejects_unknown_command_spelling() {
    let output = validator("packetcraftr.output.v1.schema.json");
    let unknown = json!({
        "schema": "packetcraftr.output/v1",
        "command": "not_a_real_command",
        "mode": "aggregate",
        "status": "error",
        "error": {
            "code": "test.unknown_command",
            "kind": "cli",
            "message": "unknown command",
            "causes": []
        },
        "diagnostics": []
    });

    assert!(
        !output.is_valid(&unknown),
        "schema accepted an unknown command spelling: {unknown}"
    );
}

#[test]
fn dns_record_schema_accepts_every_output_variant() {
    let output = validator("packetcraftr.output.v1.schema.json");
    let template = json_file(root().join("examples/documents/output-dns-success.json"));

    for data in [
        json!({"type": "a", "address": "192.0.2.1"}),
        json!({"type": "aaaa", "address": "2001:db8::1"}),
        json!({"type": "cname", "canonical_name": "alias.example."}),
        json!({"type": "mx", "preference": 10, "exchange": "mail.example."}),
        json!({"type": "ns", "name_server": "ns.example."}),
        json!({"type": "ptr", "pointer": "host.example."}),
        json!({
            "type": "soa",
            "primary_name_server": "ns.example.",
            "responsible_mailbox": "hostmaster.example.",
            "serial": 1,
            "refresh": 2,
            "retry": 3,
            "expire": 4,
            "minimum": 5
        }),
        json!({"type": "srv", "priority": 0, "weight": 1, "port": 443, "target": "service.example."}),
        json!({"type": "txt", "strings": ["value"], "strings_hex": ["76616c7565"]}),
        json!({
            "type": "opt",
            "edns": {
                "udp_payload_size": 1232,
                "extended_response_code": 0,
                "version": 0,
                "dnssec_ok": false,
                "flags": 0,
                "options": []
            }
        }),
        json!({"type": "unknown", "type_code": 99, "rdata_hex": "00"}),
    ] {
        let mut document = template.clone();
        let record = document["result"]["answers"][0].as_object_mut().unwrap();
        record.retain(|field, _| matches!(field.as_str(), "owner" | "class" | "ttl"));
        record.extend(data.as_object().unwrap().clone());
        assert!(
            output.is_valid(&document),
            "rejected valid DNS record {data}: {:?}",
            output.iter_errors(&document).collect::<Vec<_>>()
        );
    }
}

#[test]
fn every_ndjson_line_is_an_independently_valid_record() {
    let output = validator("packetcraftr.output.v1.schema.json");
    let capture = root().join("tests/fixtures/captures/pcapng/multi-link.pcapng");

    let result = std::process::Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args(["--output", "ndjson", "read"])
        .arg(&capture)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stderr.is_empty());
    for (index, line) in result
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        let value: Value = serde_json::from_slice(line).unwrap();
        assert!(
            output.is_valid(&value),
            "record {index}: {:?}",
            output.iter_errors(&value).collect::<Vec<_>>()
        );
    }
}

#[test]
fn schemas_reject_representative_contract_violations() {
    let packet = validator("packetcraftr.packet.v1.schema.json");
    let output = validator("packetcraftr.output.v1.schema.json");

    for malformed in [
        json!({"schema": "packetcraftr.packet/v1"}),
        json!({"schema": "packetcraftr.packet/v1", "layers": [{"protocol": ""}]}),
        json!({"schema": "packetcraftr.packet/v1", "layers": [{"protocol": "raw", "fields": {"bytes": {"type": "bytes", "value": [256]}}}]}),
        json!({"schema": "packetcraftr.packet/v1", "layers": [], "extra": true}),
    ] {
        assert!(
            !packet.is_valid(&malformed),
            "accepted malformed packet {malformed}"
        );
    }

    for malformed in [
        json!({"schema": "packetcraftr.output/v1", "command": "build", "mode": "aggregate", "status": "success", "diagnostics": []}),
        json!({"schema": "packetcraftr.output/v1", "command": "unknown", "mode": "aggregate", "status": "error", "error": {}, "diagnostics": []}),
        json!({"schema": "packetcraftr.output/v1", "command": "build", "mode": "stream", "status": "success", "sequence": 0, "result": {}, "diagnostics": []}),
        json!({"schema": "packetcraftr.output/v1", "command": "protocols", "mode": "aggregate", "status": "success", "result": {"protocols": [{"protocol": "ipv4", "aliases": [], "build": true, "dissect": true, "exact_round_trip": true, "matcher": false, "decode_only": false, "fields": []}]}, "diagnostics": []}),
        json!({"schema": "packetcraftr.output/v1", "command": "protocols", "mode": "aggregate", "status": "success", "result": {"protocol": {"protocol": "ipv4", "aliases": [], "build": true, "dissect": true, "exact_round_trip": true, "matcher": false, "decode_only": false, "fields": [{"name": "ttl", "kind": "integer", "required": true, "derived": false, "description": ""}]}}, "diagnostics": []}),
    ] {
        assert!(
            !output.is_valid(&malformed),
            "accepted malformed output {malformed}"
        );
    }

    let build_success = json_file(root().join("examples/documents/output-build-success.json"));

    let mut malformed_embedded_packet = build_success.clone();
    malformed_embedded_packet["result"]["packet"]["layers"][0]["fields"]["bytes"]["value"] =
        json!([256]);
    assert!(
        !packet.is_valid(&malformed_embedded_packet["result"]["packet"]),
        "accepted standalone packet with malformed field value"
    );
    assert!(
        !output.is_valid(&malformed_embedded_packet),
        "accepted output with malformed embedded packet field value"
    );

    let mut empty_embedded_field_name = build_success.clone();
    empty_embedded_field_name["result"]["packet"]["layers"][0]["fields"]
        .as_object_mut()
        .unwrap()
        .insert("".to_owned(), json!({"type": "unsigned", "value": 1}));
    assert!(
        !output.is_valid(&empty_embedded_field_name),
        "accepted output with an empty embedded packet field name"
    );

    let traceroute_success =
        json_file(root().join("examples/documents/output-traceroute-success.json"));

    let mut traceroute = traceroute_success.clone();
    traceroute["result"]["destination_port"] = json!(0);
    assert!(
        !output.is_valid(&traceroute),
        "accepted traceroute result with port zero"
    );
    traceroute["result"]["destination_port"] = json!(33_434);
    traceroute["result"]["hops"][0]["probes"][0]["destination_port"] = json!(0);
    assert!(
        !output.is_valid(&traceroute),
        "accepted traceroute probe with port zero"
    );

    let traceroute_complete =
        json_file(root().join("examples/documents/output-traceroute-complete.json"));

    let mut traceroute_completion = traceroute_complete.clone();
    traceroute_completion["result"]["destination_port"] = json!(0);
    assert!(
        !output.is_valid(&traceroute_completion),
        "accepted traceroute completion with port zero"
    );

    let mut missing_result_port = traceroute_success.clone();
    missing_result_port["result"]
        .as_object_mut()
        .unwrap()
        .remove("destination_port");
    assert!(
        !output.is_valid(&missing_result_port),
        "accepted UDP traceroute result without a destination port"
    );

    let mut icmp_result_port = traceroute_success.clone();
    icmp_result_port["result"]["strategy"] = json!("icmp");
    assert!(
        !output.is_valid(&icmp_result_port),
        "accepted ICMP traceroute result with a destination port"
    );

    let mut missing_probe_port = traceroute_success.clone();
    missing_probe_port["result"]["hops"][0]["probes"][0]
        .as_object_mut()
        .unwrap()
        .remove("destination_port");
    assert!(
        !output.is_valid(&missing_probe_port),
        "accepted UDP traceroute probe without a destination port"
    );

    let mut icmp_complete_port = traceroute_complete.clone();
    icmp_complete_port["result"]["strategy"] = json!("icmp");
    assert!(
        !output.is_valid(&icmp_complete_port),
        "accepted ICMP traceroute completion with a destination port"
    );

    let dns = json_file(root().join("examples/documents/output-dns-success.json"));

    let mut unsupported_dns_transport = dns.clone();
    unsupported_dns_transport["result"]["transport"] = json!("tcp");
    assert!(
        !output.is_valid(&unsupported_dns_transport),
        "accepted unsupported DNS transport"
    );

    let mut cross_variant_dns_record = dns.clone();
    cross_variant_dns_record["result"]["answers"][0]["address"] = json!("192.0.2.1");
    assert!(
        !output.is_valid(&cross_variant_dns_record),
        "accepted a TXT record with an A-record field"
    );

    for (record_type, address) in [("a", "192.0.2.1"), ("aaaa", "2001:db8::1")] {
        let mut dns_address_record = dns.clone();
        let record = dns_address_record["result"]["answers"][0]
            .as_object_mut()
            .unwrap();
        record.insert("type".to_owned(), json!(record_type));
        record.insert("address".to_owned(), json!(address));
        record.remove("strings");
        record.remove("strings_hex");
        assert!(
            output.is_valid(&dns_address_record),
            "rejected valid {record_type} record address"
        );
        dns_address_record["result"]["answers"][0]["address"] = json!("not-an-ip");
        assert!(
            !output.is_valid(&dns_address_record),
            "accepted malformed {record_type} record address"
        );
    }

    let mut stats = json_file(root().join("examples/documents/output-stats-success.json"));
    stats["result"]["conversations"][0]["address_a"] = json!("not-an-ip");
    assert!(!output.is_valid(&stats), "accepted malformed stats address");

    let mut plan = json_file(root().join("examples/documents/output-plan-success.json"));
    plan["result"]["route"]["route"]["selected_address"] = json!("not-an-ip");
    assert!(
        !output.is_valid(&plan),
        "accepted malformed nullable route address"
    );
}
