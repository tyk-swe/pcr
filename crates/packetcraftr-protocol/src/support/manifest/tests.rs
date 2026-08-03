// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use super::*;
use packetcraftr_packet::{
    field::{FieldKind, FieldValue},
    layer::FieldError,
};

fn unique(values: &[&str]) -> bool {
    values.iter().copied().collect::<BTreeSet<_>>().len() == values.len()
}

fn representative_value(kind: FieldKind, name: &str) -> FieldValue {
    match kind {
        FieldKind::Bool => FieldValue::Bool(true),
        FieldKind::Unsigned => FieldValue::Unsigned(0),
        FieldKind::Signed => FieldValue::Signed(0),
        FieldKind::Text if name == "byte_order" => FieldValue::Text("little".to_owned()),
        FieldKind::Text => FieldValue::Text("value".to_owned()),
        FieldKind::Bytes if name == "address" => FieldValue::Bytes(Bytes::from(vec![0; 8])),
        FieldKind::Bytes => FieldValue::Bytes(Bytes::from_static(&[1, 2])),
        FieldKind::Ipv4 => FieldValue::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
        FieldKind::Ipv6 => FieldValue::Ipv6(Ipv6Addr::LOCALHOST),
        FieldKind::Mac => FieldValue::Mac([0, 1, 2, 3, 4, 5]),
        FieldKind::List => FieldValue::List(Vec::new()),
        _ => panic!("{name} uses field kind {kind:?}, which has no representative value yet"),
    }
}

fn definitely_wrong_value(kind: FieldKind) -> FieldValue {
    if kind == FieldKind::Bool {
        FieldValue::Text("wrong".to_owned())
    } else {
        FieldValue::Bool(false)
    }
}

#[test]
fn every_constructible_builtin_obeys_the_reflective_field_contract() {
    let registry = crate::builtin::registry().unwrap();
    for support in BUILTIN_PROTOCOLS.iter().filter(|support| support.build) {
        let codec = registry.codec_named(support.protocol).unwrap();
        let layer = codec.make_layer(&BTreeMap::new()).unwrap();
        let schema = layer.schema();
        let names = schema
            .fields
            .iter()
            .map(|field| field.name)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            names.len(),
            schema.fields.len(),
            "{} schema",
            support.protocol
        );

        for field in schema.fields {
            let value = representative_value(field.kind, field.name);
            let mut writable = layer.clone_box();
            writable
                .set_field(field.name, value.clone())
                .unwrap_or_else(|error| {
                    panic!(
                        "{}.{} rejected its schema type: {error}",
                        support.protocol, field.name
                    )
                });
            assert_eq!(
                writable.field(field.name),
                Some(value),
                "{}.{} setter/getter round trip",
                support.protocol,
                field.name
            );

            let mut wrong = layer.clone_box();
            assert!(
                matches!(
                    wrong.set_field(field.name, definitely_wrong_value(field.kind)),
                    Err(FieldError::WrongType { .. })
                ),
                "{}.{} accepted an incompatible type",
                support.protocol,
                field.name
            );
        }

        assert!(matches!(
            layer
                .clone_box()
                .set_field("__unknown", FieldValue::Bool(false)),
            Err(FieldError::UnknownField { .. })
        ));
    }
}

#[test]
fn address_fields_preserve_direct_text_setter_conversions() {
    let registry = crate::builtin::registry().unwrap();

    let mut ipv4 = registry
        .codec_named("ipv4")
        .unwrap()
        .make_layer(&BTreeMap::new())
        .unwrap();
    ipv4.set_field("source", FieldValue::Text("192.0.2.9".to_owned()))
        .unwrap();
    assert_eq!(
        ipv4.field("source"),
        Some(FieldValue::Ipv4(Ipv4Addr::new(192, 0, 2, 9)))
    );
    assert!(matches!(
        ipv4.set_field("source", FieldValue::Text("not-an-address".to_owned())),
        Err(FieldError::WrongType {
            expected: "ipv4",
            ..
        })
    ));

    let mut ipv6 = registry
        .codec_named("ipv6")
        .unwrap()
        .make_layer(&BTreeMap::new())
        .unwrap();
    ipv6.set_field("source", FieldValue::Text("2001:db8::9".to_owned()))
        .unwrap();
    assert_eq!(
        ipv6.field("source"),
        Some(FieldValue::Ipv6("2001:db8::9".parse().unwrap()))
    );

    let mut ethernet = registry
        .codec_named("ethernet")
        .unwrap()
        .make_layer(&BTreeMap::new())
        .unwrap();
    ethernet
        .set_field("source", FieldValue::Text("00-11-22-33-44-55".to_owned()))
        .unwrap();
    assert_eq!(
        ethernet.field("source"),
        Some(FieldValue::Mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
    );
}

#[test]
fn manifest_matches_the_default_registry_exactly() {
    let registry = crate::builtin::registry().unwrap();
    let declared = BUILTIN_PROTOCOLS
        .iter()
        .map(|support| (support.protocol, support))
        .collect::<BTreeMap<_, _>>();
    let actual = registry
        .protocols()
        .map(|protocol| protocol.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(declared.keys().copied().collect::<BTreeSet<_>>(), actual);
    assert_eq!(declared.len(), 37);

    for support in BUILTIN_PROTOCOLS {
        let identity = BuiltinProtocol::from_name(support.protocol)
            .expect("manifest protocol must have a catalog identity");
        assert_eq!(identity.aliases(), support.aliases);
        assert_eq!(identity.is_constructible(), support.build);
        assert_eq!(identity.is_dissectible(), support.dissect);
        assert_eq!(identity.has_exact_round_trip(), support.exact_round_trip);
        assert_eq!(identity.has_matcher(), support.matcher);
        assert!(unique(support.aliases), "{} aliases", support.protocol);
        let codec = registry
            .codec(support.protocol)
            .expect("declared protocol must have a codec");
        assert_eq!(
            codec.aliases(),
            support.aliases,
            "{} aliases",
            support.protocol
        );
        let constructed = codec.make_layer(&BTreeMap::new());
        assert_eq!(
            constructed.is_ok(),
            support.build,
            "{} constructibility",
            support.protocol
        );
        if let Ok(layer) = constructed {
            layer
                .validate_required_fields()
                .unwrap_or_else(|error| panic!("{} defaults: {error}", support.protocol));
        }
        assert_eq!(
            registry.matcher(support.protocol).is_some(),
            support.matcher,
            "{} matcher",
            support.protocol
        );
    }
    assert_eq!(
        BUILTIN_PROTOCOLS
            .iter()
            .filter(|support| support.decode_only)
            .map(|support| support.protocol)
            .collect::<Vec<_>>(),
        vec!["dns", "raw_ip"]
    );

    let roots = registry
        .link_type_roots()
        .map(|(link_type, protocol)| (link_type, protocol.as_str()))
        .collect::<BTreeMap<_, _>>();
    let declared_roots = BUILTIN_CAPTURE_ROOTS
        .iter()
        .map(|root| (root.link_type, root.protocol))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(declared_roots, roots);

    let matchers = registry
        .matcher_protocols()
        .map(|protocol| protocol.as_str())
        .collect::<BTreeSet<_>>();
    let declared_matchers = BUILTIN_PROTOCOLS
        .iter()
        .filter(|support| support.matcher)
        .map(|support| support.protocol)
        .collect::<BTreeSet<_>>();
    assert_eq!(matchers, declared_matchers);
}

#[test]
fn catalog_membership_is_independent_of_live_backend_features() {
    // Backends are feature-gated, but the portable built-in codec catalog
    // is not. This assertion runs in every CI feature profile.
    assert_eq!(BuiltinProtocol::ALL.len(), 37);
    assert_eq!(BUILTIN_PROTOCOLS.len(), BuiltinProtocol::ALL.len());
    assert!(BuiltinProtocol::ALL.contains(&BuiltinProtocol::RawIp));
}
