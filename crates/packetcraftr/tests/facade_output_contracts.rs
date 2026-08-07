// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{
    output::{
        contract::{CONTRACTS, Command, Format, SCHEMA_V1},
        envelope::{Aggregate, Stream},
    },
    protocol,
};
use serde_json::{Value, json};

#[test]
fn facade_reexports_domains_and_the_contract_matrix_is_complete() {
    let registry = protocol::builtin::registry().expect("facade protocol re-export must work");
    assert!(registry.codec("ipv4").is_some());
    assert_eq!(CONTRACTS.len(), Command::ALL.len());
    for (contract, command) in CONTRACTS.iter().zip(Command::ALL) {
        assert_eq!(&contract.command, command);
        assert!(!contract.formats.is_empty());
        assert!(contract.command.require_format(contract.formats[0]).is_ok());
    }
    assert!(Command::Protocols.require_format(Format::Ndjson).is_err());
}

#[test]
fn aggregate_and_stream_envelopes_keep_version_and_discriminators() {
    let aggregate = serde_json::to_value(Aggregate::success(
        Command::Protocols,
        json!({"count": 1}),
        Vec::new(),
    ))
    .expect("aggregate must serialize");
    assert_eq!(aggregate["schema"], SCHEMA_V1);
    assert_eq!(aggregate["command"], "protocols");
    assert_eq!(aggregate["mode"], "aggregate");
    assert_eq!(aggregate["status"], "success");
    assert!(aggregate.get("sequence").is_none());

    let stream = serde_json::to_value(Stream::success(
        Command::Read,
        7,
        json!({"frame": 1}),
        Vec::new(),
    ))
    .expect("stream must serialize");
    assert_eq!(stream["schema"], SCHEMA_V1);
    assert_eq!(stream["mode"], "stream");
    assert_eq!(stream["sequence"], 7);
}

#[test]
fn current_schema_and_published_examples_use_output_v1() {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../schemas/packetcraftr.output.v1.schema.json"
    ))
    .expect("output schema must be valid JSON");
    assert_eq!(
        schema["$defs"]["baseEnvelope"]["properties"]["schema"]["const"],
        SCHEMA_V1
    );

    for document in [
        include_str!("../../../examples/documents/output-build-success.json"),
        include_str!("../../../examples/documents/output-dns-error.json"),
        include_str!("../../../examples/documents/output-follow-event.json"),
    ] {
        let value: Value = serde_json::from_str(document).expect("example must be valid JSON");
        assert_eq!(value["schema"], SCHEMA_V1);
        assert!(matches!(
            value["status"].as_str(),
            Some("success" | "error")
        ));
    }
}
