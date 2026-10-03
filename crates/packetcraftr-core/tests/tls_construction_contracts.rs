// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use packetcraftr_core::{
    layer::Layer,
    protocol::application::tls::{Extension, Hello, HelloKind, Tls},
};

#[test]
fn oversized_fields_invalid_extensions_and_failed_edits_are_rejected_atomically() {
    let mut layer = Tls::try_from(Hello::default()).unwrap();
    let original = layer.clone();
    assert!(
        layer
            .set_field_path(
                &"hello.random".parse().unwrap(),
                Bytes::from_static(b"short").into()
            )
            .is_err()
    );
    assert_eq!(layer, original);
    for (hello, refusal) in [
        (
            Hello {
                session_id: Bytes::from(vec![0; 33]),
                ..Default::default()
            },
            "protocol or resource bound",
        ),
        (
            Hello {
                cipher_suites: vec![],
                ..Default::default()
            },
            "protocol or resource bound",
        ),
        (
            Hello {
                kind: HelloKind::Server,
                cipher_suites: vec![1, 2],
                ..Default::default()
            },
            "ServerHello selects one cipher and compression method",
        ),
        (
            Hello {
                extensions: vec![Extension {
                    kind: 16,
                    data: Bytes::from_static(&[0]),
                }],
                ..Default::default()
            },
            "hello fields contain an invalid handshake",
        ),
    ] {
        let error = Tls::try_from(hello).unwrap_err().to_string();
        assert!(error.contains(refusal), "{refusal:?} not in {error:?}");
    }
}
