// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use packetcraftr_core::{
    expression,
    layer::Layer,
    protocol::{
        application::tls::{Hello, HelloExtension, HelloKind, codec::Tls},
        builtin,
    },
    template::Template,
};

#[test]
fn typed_hellos_derive_lengths_and_fingerprints_and_preserve_unknown_extensions() {
    for kind in [HelloKind::Client, HelloKind::Server] {
        let mut hello = Hello {
            kind,
            session_id: Bytes::from_static(b"fixture"),
            ..Default::default()
        };
        hello.extensions.push(HelloExtension {
            kind: 0xaaaa,
            data: Bytes::from_static(b"opaque"),
        });
        if kind == HelloKind::Client {
            hello
                .extensions
                .push(HelloExtension::server_name("example.test").unwrap());
            hello
                .extensions
                .push(HelloExtension::alpn(&[Bytes::from_static(b"h2")]).unwrap());
        }
        let layer = Tls::from_hello(hello.clone()).unwrap();
        let decoded = Tls::from_wire(layer.wire()).unwrap();
        assert_eq!(decoded.hello, Some(hello));
        assert_eq!(decoded.wire(), layer.wire());
        if kind == HelloKind::Client {
            assert_eq!(decoded.sni.as_deref(), Some("example.test"));
            assert_eq!(decoded.alpn, ["h2"]);
            assert!(decoded.ja3.is_some());
        }
    }
}

#[test]
fn recipes_and_template_axes_author_nested_hello_fields() {
    let packet = expression::parse(r#"tls(hello={kind=client,cipher_suites=[0xc02f,0xc030],extensions=[{server_name="example.test"},{alpn=["h2","http/1.1"]},{type=65000,data=hex("00ff")} ]})"#, &builtin::registry(), Default::default()).unwrap();
    assert_eq!(
        packet.get::<Tls>().unwrap().sni.as_deref(),
        Some("example.test")
    );
    let template = Template::new(packet).axis(
        0,
        "hello.cipher_suites[0]",
        vec![0xc02fu16.into(), 0xc030u16.into()],
    );
    let mut fingerprints = Vec::new();
    for packet in template.expand(2).unwrap() {
        let packet = packet.unwrap();
        let tls = packet.get::<Tls>().unwrap();
        fingerprints.push(tls.ja3.clone().unwrap());
        assert_eq!(
            tls.hello.as_ref().unwrap().extensions[2].data.as_ref(),
            &[0, 255]
        );
    }
    assert_ne!(fingerprints[0], fingerprints[1]);
}

#[test]
fn oversized_fields_invalid_extensions_and_failed_edits_are_rejected_atomically() {
    let mut layer = Tls::from_hello(Hello::default()).unwrap();
    let original = layer.clone();
    assert!(
        layer
            .set_field_path("hello.random", Bytes::from_static(b"short").into())
            .is_err()
    );
    assert_eq!(layer, original);
    for hello in [
        Hello {
            session_id: Bytes::from(vec![0; 33]),
            ..Default::default()
        },
        Hello {
            cipher_suites: vec![],
            ..Default::default()
        },
        Hello {
            kind: HelloKind::Server,
            cipher_suites: vec![1, 2],
            ..Default::default()
        },
        Hello {
            extensions: vec![HelloExtension {
                kind: 16,
                data: Bytes::from_static(&[0]),
            }],
            ..Default::default()
        },
    ] {
        assert!(Tls::from_hello(hello).is_err());
    }
}
