// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{DocumentLimits, Error, Format, Limit, Packet};
use crate::document::PACKET_DOCUMENT_SCHEMA_V1;
use crate::error::{Classified, Kind};

const YAML: &str = "schema: packetcraftr.packet/v1\nlayers:\n  - protocol: raw\n    fields:\n      bytes:\n        type: bytes\n        value: [104, 105]\n";

#[test]
fn yaml_accepts_one_document_with_comments_and_terminators() {
    // https://yaml.org/spec/1.2.2/#912-document-markers checked 2026-10-25.
    let expected = Packet {
        schema: PACKET_DOCUMENT_SCHEMA_V1.to_owned(),
        layers: vec![crate::document::Layer {
            protocol: "raw".to_owned(),
            fields: [(
                "bytes".to_owned(),
                crate::field::Value::Bytes(bytes::Bytes::from_static(b"hi")),
            )]
            .into(),
        }],
    };
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
    assert_eq!(error.classification().code, "cli.document_syntax");
    assert_eq!(error.classification().kind, Kind::Usage);
}

#[test]
fn yaml_rejects_second_documents_including_empty_ones() {
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
    let admitted = Packet::parse_with_limits(
        YAML,
        Format::Yaml,
        &DocumentLimits {
            max_input_bytes: YAML.len(),
            max_layers: 1,
            ..DocumentLimits::DEFAULT
        },
    )
    .unwrap();
    assert_eq!(
        admitted.layers[0].fields["bytes"],
        crate::field::Value::Bytes(bytes::Bytes::from_static(b"hi"))
    );
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
        assert_eq!(error.classification().code, "cli.document_limit");
        assert_eq!(error.classification().kind, Kind::Usage);
    }
}
