// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{DocumentLimits, Error, Format, Limit, Packet};
use crate::document::PACKET_DOCUMENT_SCHEMA_V1;
use crate::error::{Classified, Kind};

const YAML: &str = "schema: packetcraftr.packet/v1\nlayers:\n  - protocol: raw\n    fields: {}\n";

#[test]
fn yaml_accepts_comments_and_terminators() {
    let expected = Packet::parse(YAML, Format::Yaml, YAML.len()).unwrap();
    assert_eq!(expected.schema, PACKET_DOCUMENT_SCHEMA_V1);
    assert_eq!(expected.layers.len(), 1);
    for prefix in ["", "---\n"] {
        for suffix in [
            "",
            "\n# trailing comment\n",
            "...\n",
            "... # end\n# comment\n",
        ] {
            let input = format!("{prefix}{YAML}{suffix}");
            assert_eq!(
                Packet::parse(&input, Format::Yaml, input.len()).unwrap(),
                expected,
                "{input:?}"
            );
        }
    }
}

fn assert_yaml_syntax_error(input: &str) {
    let error = Packet::parse(input, Format::Yaml, input.len()).unwrap_err();
    assert!(
        matches!(error, Error::Parse { format: "YAML", .. }),
        "{input:?}: {error:?}"
    );
    assert_eq!(error.limit(), None);
    assert_eq!(error.classification().code.as_str(), "cli.document_syntax");
    assert_eq!(error.classification().kind, Kind::Usage);
}

#[test]
fn yaml_rejects_multiple_documents() {
    for suffix in [
        "---\n{}\n",
        "---\nnull\n",
        "---\n",
        "---\n# empty document\n",
        "---\n...\n",
        "...\n---\n",
        "...\n%YAML 1.2\n---\n{}\n",
    ] {
        assert_yaml_syntax_error(&format!("{YAML}{suffix}"));
    }
}

#[test]
fn yaml_rejects_malformed_trailing_content() {
    for suffix in [
        "[unterminated\n",
        "]\n",
        "...\n[unterminated\n",
        "---\n[unterminated\n",
        "...\n%YAML invalid\n",
    ] {
        assert_yaml_syntax_error(&format!("{YAML}{suffix}"));
    }
}

#[test]
fn yaml_preserves_resource_limit_classification() {
    for (limit, limits) in [
        (
            Limit::InputBytes,
            DocumentLimits {
                max_input_bytes: YAML.len() - 1,
                ..DocumentLimits::DEFAULT
            },
        ),
        (
            Limit::Layers,
            DocumentLimits {
                max_layers: 0,
                ..DocumentLimits::DEFAULT
            },
        ),
    ] {
        let error = Packet::parse_with_limits(YAML, Format::Yaml, &limits).unwrap_err();
        assert_eq!(error.limit(), Some(limit));
        assert_eq!(error.classification().code.as_str(), "cli.document_limit");
        assert_eq!(error.classification().kind, Kind::Usage);
    }
}

#[test]
fn yaml_preserves_unsigned_timestamp_range() {
    use crate::build::{Builder, Options};
    use crate::codec::Addresses;
    use crate::field::Value;
    use crate::protocol::builtin;

    let registry = builtin::registry();
    for value in [0, i64::MAX as u64, (i64::MAX as u64) + 1, u64::MAX] {
        for fields in [
            format!("type: unsigned, value: {value}"),
            format!("value: {value}, type: unsigned"),
        ] {
            let input = format!(
                "schema: packetcraftr.packet/v1\nlayers:\n  - protocol: ntp\n    fields:\n      transmit_timestamp: {{{fields}}}\n"
            );
            let document = Packet::parse(&input, Format::Yaml, input.len()).unwrap();
            assert_eq!(
                document.layers[0].fields["transmit_timestamp"],
                Value::Unsigned(value)
            );
            let packet = document.to_packet(&registry, 1).unwrap();
            let built = Builder::new(registry.clone())
                .build(packet, Addresses::default(), Options::default())
                .unwrap();
            assert_eq!(&built.bytes[40..48], &value.to_be_bytes());
        }
    }
    for value in ["-1", "18446744073709551616", "1.5", "1.0"] {
        let input = format!(
            "schema: packetcraftr.packet/v1\nlayers:\n  - protocol: ntp\n    fields:\n      transmit_timestamp: {{type: unsigned, value: {value}}}\n"
        );
        assert!(Packet::parse(&input, Format::Yaml, input.len()).is_err());
    }
}
