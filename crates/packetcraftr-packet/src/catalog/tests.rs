// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::Packet;
use crate::codec::{
    CodecError, DecodedLayerValue, EncodedLayer, NativeLayerDecodeContext, NativeLayerEncodeContext,
};
use crate::layer::{DynamicLayer, Layer, ValidatedFieldSet};
use crate::provider::{ProtocolProvider, ProtocolSession, ProviderMatch, ProviderProtocolKey};

#[derive(Debug)]
struct CountingProvider {
    provider: ProviderId,
    origin: RegistrationOrigin,
    schemas: BTreeMap<ProviderProtocolKey, Arc<LayerSchema>>,
    begins: Arc<AtomicUsize>,
}

impl ProtocolProvider for CountingProvider {
    fn provider_id(&self) -> &ProviderId {
        &self.provider
    }

    fn origin(&self) -> &RegistrationOrigin {
        &self.origin
    }

    fn begin_session(&self) -> Result<Box<dyn ProtocolSession>, ProviderError> {
        self.begins.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(CountingSession {
            schemas: self.schemas.clone(),
        }))
    }
}

#[derive(Debug)]
struct CountingSession {
    schemas: BTreeMap<ProviderProtocolKey, Arc<LayerSchema>>,
}

impl CountingSession {
    fn schema(&self, key: &ProviderProtocolKey) -> Result<Arc<LayerSchema>, CodecError> {
        self.schemas
            .get(key)
            .cloned()
            .ok_or_else(|| CodecError::Unsupported {
                protocol: ProtocolId::from_static("test.provider"),
                message: format!("unknown test provider key {key}"),
            })
    }
}

impl ProtocolSession for CountingSession {
    fn construct(
        &mut self,
        key: &ProviderProtocolKey,
        fields: &ValidatedFieldSet,
    ) -> Result<Box<dyn Layer>, CodecError> {
        self.schema(key)?;
        Ok(Box::new(DynamicLayer::from_validated(fields.clone())?))
    }

    fn encode(
        &mut self,
        key: &ProviderProtocolKey,
        layer: &dyn Layer,
        _payload: &[u8],
        _context: &NativeLayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        self.schema(key)?;
        Ok(EncodedLayer::header(Vec::new(), layer.clone_box()))
    }

    fn decode(
        &mut self,
        key: &ProviderProtocolKey,
        _input: &[u8],
        _context: &NativeLayerDecodeContext,
    ) -> Result<DecodedLayerValue, CodecError> {
        let schema = self.schema(key)?;
        Ok(DecodedLayerValue::terminal(
            Box::new(DynamicLayer::new(schema, [])?),
            0,
        ))
    }

    fn match_response(
        &mut self,
        key: &ProviderProtocolKey,
        _request: &Packet,
        _response: &Packet,
    ) -> Result<Option<ProviderMatch>, CodecError> {
        self.schema(key)?;
        Ok(None)
    }
}

fn native_origin(provider: &ProviderId) -> RegistrationOrigin {
    RegistrationOrigin::Native {
        provider: provider.clone(),
    }
}

fn registration_set(
    provider: &'static str,
    protocols: &[(&'static str, &'static str)],
    begins: Arc<AtomicUsize>,
) -> (ProtocolRegistrationSet, RegistrationOrigin) {
    let provider = ProviderId::from_static(provider);
    let origin = native_origin(&provider);
    let entries = protocols
        .iter()
        .map(|(protocol, key)| {
            let schema = Arc::new(
                LayerSchema::empty(
                    ProtocolId::from_static(protocol),
                    format!("{protocol} test schema"),
                    std::iter::empty::<&str>(),
                )
                .unwrap(),
            );
            (ProviderProtocolKey::from_static(key), schema)
        })
        .collect::<Vec<_>>();
    let factory = CountingProvider {
        provider: provider.clone(),
        origin: origin.clone(),
        schemas: entries.iter().cloned().collect(),
        begins,
    };
    let mut set = ProtocolRegistrationSet::new();
    set.register_provider(Arc::new(factory));
    for (key, schema) in entries {
        set.register_protocol(ProtocolRegistration::new(
            schema,
            provider.clone(),
            key,
            origin.clone(),
        ));
    }
    (set, origin)
}

#[test]
fn one_provider_session_is_lazy_and_reused_only_within_one_operation() {
    let begins = Arc::new(AtomicUsize::new(0));
    let (set, _) = registration_set(
        "test.multi_provider",
        &[("vendor.example.one", "one"), ("vendor.example.two", "two")],
        Arc::clone(&begins),
    );
    let mut builder = ProtocolCatalogBuilder::new();
    builder.registration_set(set);
    let catalog = Arc::new(builder.build().unwrap());

    let mut first = catalog.operation();
    assert_eq!(first.started_provider_count(), 0);
    first
        .construct_named(
            "vendor.example.one",
            std::iter::empty::<(&str, crate::field::FieldValue)>(),
        )
        .unwrap();
    first
        .construct_named(
            "vendor.example.two",
            std::iter::empty::<(&str, crate::field::FieldValue)>(),
        )
        .unwrap();
    assert_eq!(first.started_provider_count(), 1);
    assert_eq!(begins.load(Ordering::SeqCst), 1);

    let mut second = catalog.operation();
    second
        .construct_named(
            "vendor.example.two",
            std::iter::empty::<(&str, crate::field::FieldValue)>(),
        )
        .unwrap();
    assert_eq!(second.started_provider_count(), 1);
    assert_eq!(begins.load(Ordering::SeqCst), 2);
}

#[test]
fn equivalent_registration_order_produces_the_same_catalog_hash() {
    fn build(protocols: &[(&'static str, &'static str)]) -> ProtocolCatalogSnapshot {
        let begins = Arc::new(AtomicUsize::new(0));
        let (mut set, origin) = registration_set("test.deterministic", protocols, begins);
        set.capture_root(
            147,
            ProtocolId::from_static("vendor.example.parent"),
            origin.clone(),
        )
        .binding(ProtocolBindingRegistration::canonical(
            ProtocolId::from_static("vendor.example.parent"),
            7,
            ProtocolId::from_static("vendor.example.child"),
            origin,
        ));
        let mut builder = ProtocolCatalogBuilder::new();
        builder.registration_set(set);
        builder.build().unwrap()
    }

    let forward = build(&[
        ("vendor.example.parent", "parent"),
        ("vendor.example.child", "child"),
    ]);
    let reverse = build(&[
        ("vendor.example.child", "child"),
        ("vendor.example.parent", "parent"),
    ]);
    assert_eq!(forward.catalog_hash(), reverse.catalog_hash());
    assert_eq!(
        forward
            .protocols()
            .map(|(protocol, _)| protocol.as_str())
            .collect::<Vec<_>>(),
        reverse
            .protocols()
            .map(|(protocol, _)| protocol.as_str())
            .collect::<Vec<_>>()
    );
}

#[test]
fn selected_registration_provenance_is_retained_and_hashed() {
    fn build(binding_origin: RegistrationOrigin) -> ProtocolCatalogSnapshot {
        let (mut set, registration_origin) = registration_set(
            "test.provenance",
            &[
                ("vendor.example.parent", "parent"),
                ("vendor.example.child", "child"),
            ],
            Arc::new(AtomicUsize::new(0)),
        );
        let parent = ProtocolId::from_static("vendor.example.parent");
        let child = ProtocolId::from_static("vendor.example.child");
        set.capture_root(147, parent.clone(), registration_origin.clone())
            .binding(ProtocolBindingRegistration::canonical(
                parent.clone(),
                7,
                child.clone(),
                binding_origin,
            ))
            .fallback(parent, child, registration_origin);
        let mut builder = ProtocolCatalogBuilder::new();
        builder.registration_set(set);
        builder.build().unwrap()
    }

    let first_origin = RegistrationOrigin::Native {
        provider: ProviderId::from_static("test.binding.first"),
    };
    let second_origin = RegistrationOrigin::Native {
        provider: ProviderId::from_static("test.binding.second"),
    };
    let first = build(first_origin.clone());
    let second = build(second_origin);
    let parent = ProtocolId::from_static("vendor.example.parent");

    assert_eq!(
        first.capture_root_registration(147).unwrap().origin,
        native_origin(&ProviderId::from_static("test.provenance"))
    );
    assert_eq!(
        first
            .binding_registration(&parent, Discriminator(7))
            .unwrap()
            .origin,
        first_origin
    );
    assert_eq!(
        first.fallback_registration(&parent).unwrap().origin,
        native_origin(&ProviderId::from_static("test.provenance"))
    );
    assert_ne!(first.catalog_hash(), second.catalog_hash());
}

#[test]
fn decode_only_aliases_never_become_reverse_encoding_bindings() {
    let (mut set, origin) = registration_set(
        "test.decode_alias",
        &[
            ("vendor.example.parent", "parent"),
            ("vendor.example.child", "child"),
        ],
        Arc::new(AtomicUsize::new(0)),
    );
    let parent = ProtocolId::from_static("vendor.example.parent");
    let child = ProtocolId::from_static("vendor.example.child");
    set.binding(ProtocolBindingRegistration::canonical(
        parent.clone(),
        7,
        child.clone(),
        origin.clone(),
    ))
    .binding(ProtocolBindingRegistration::decode_only(
        parent.clone(),
        8,
        child.clone(),
        origin,
    ));
    let mut builder = ProtocolCatalogBuilder::new();
    builder.registration_set(set);
    let catalog = builder.build().unwrap();

    assert_eq!(catalog.child_for(&parent, Discriminator(7)), Some(&child));
    assert_eq!(catalog.child_for(&parent, Discriminator(8)), Some(&child));
    assert_eq!(
        catalog.discriminator_for(&parent, &child),
        Some(Discriminator(7))
    );
}

#[test]
fn two_canonical_reverse_bindings_fail_deterministically() {
    let (mut set, origin) = registration_set(
        "test.canonical_conflict",
        &[
            ("vendor.example.parent", "parent"),
            ("vendor.example.child", "child"),
        ],
        Arc::new(AtomicUsize::new(0)),
    );
    let parent = ProtocolId::from_static("vendor.example.parent");
    let child = ProtocolId::from_static("vendor.example.child");
    set.binding(ProtocolBindingRegistration::canonical(
        parent.clone(),
        7,
        child.clone(),
        origin.clone(),
    ))
    .binding(ProtocolBindingRegistration::canonical(
        parent.clone(),
        8,
        child.clone(),
        origin,
    ));
    let mut builder = ProtocolCatalogBuilder::new();
    builder.registration_set(set);
    assert!(matches!(
        builder.build(),
        Err(CatalogError::CanonicalBindingConflict {
            parent: actual_parent,
            child: actual_child,
        }) if actual_parent == parent && actual_child == child
    ));
}

#[test]
fn conflicting_protocols_require_an_exact_origin_selection() {
    let (first, first_origin) = registration_set(
        "test.conflict.first",
        &[("vendor.example.conflict", "conflict")],
        Arc::new(AtomicUsize::new(0)),
    );
    let (second, second_origin) = registration_set(
        "test.conflict.second",
        &[("vendor.example.conflict", "conflict")],
        Arc::new(AtomicUsize::new(0)),
    );
    let mut unselected = ProtocolCatalogBuilder::new();
    unselected.registration_set(first);
    unselected.registration_set(second);
    assert!(matches!(
        unselected.build(),
        Err(CatalogError::ProtocolConflict { .. })
    ));

    let (first, _) = registration_set(
        "test.conflict.first",
        &[("vendor.example.conflict", "conflict")],
        Arc::new(AtomicUsize::new(0)),
    );
    let (second, _) = registration_set(
        "test.conflict.second",
        &[("vendor.example.conflict", "conflict")],
        Arc::new(AtomicUsize::new(0)),
    );
    let mut policy = ProtocolCatalogPolicy::new();
    policy.select_protocol(
        ProtocolId::from_static("vendor.example.conflict"),
        second_origin.clone(),
    );
    let mut selected = ProtocolCatalogBuilder::new();
    selected
        .registration_set(first)
        .registration_set(second)
        .policy(policy);
    let catalog = selected.build().unwrap();
    assert_eq!(
        catalog
            .descriptor(&ProtocolId::from_static("vendor.example.conflict"))
            .unwrap()
            .origin,
        second_origin
    );
    assert_ne!(first_origin, second_origin);
}

#[test]
fn a_builtin_canonical_id_cannot_be_claimed_without_exact_selection() {
    let (set, origin) = registration_set(
        "test.ipv4.replacement",
        &[("ipv4", "ipv4")],
        Arc::new(AtomicUsize::new(0)),
    );
    let mut builder = ProtocolCatalogBuilder::new();
    builder.registration_set(set);
    assert!(matches!(
        builder.build(),
        Err(CatalogError::ProtectedProtocol { protocol })
            if protocol == ProtocolId::from_static("ipv4")
    ));

    let (set, _) = registration_set(
        "test.ipv4.replacement",
        &[("ipv4", "ipv4")],
        Arc::new(AtomicUsize::new(0)),
    );
    let mut policy = ProtocolCatalogPolicy::new();
    policy.select_protocol(ProtocolId::from_static("ipv4"), origin.clone());
    let mut builder = ProtocolCatalogBuilder::new();
    builder.registration_set(set).policy(policy);
    let catalog = builder.build().unwrap();
    assert_eq!(
        catalog
            .descriptor(&ProtocolId::from_static("ipv4"))
            .unwrap()
            .origin,
        origin
    );
}

#[test]
fn native_provider_origin_must_name_the_factory_identity() {
    let provider = ProviderId::from_static("test.provider.actual");
    let origin = RegistrationOrigin::Native {
        provider: ProviderId::from_static("test.provider.other"),
    };
    let factory = CountingProvider {
        provider: provider.clone(),
        origin,
        schemas: BTreeMap::new(),
        begins: Arc::new(AtomicUsize::new(0)),
    };
    let mut set = ProtocolRegistrationSet::new();
    set.register_provider(Arc::new(factory));
    let mut builder = ProtocolCatalogBuilder::new();
    builder.registration_set(set);

    assert!(matches!(
        builder.build(),
        Err(CatalogError::ProviderIdentityMismatch {
            provider: actual,
            ..
        }) if actual == provider
    ));
}
