// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::binding::FilterFieldBinding;
use super::builder::RegistryBuilder;
use super::error::RegistryError;
use crate::layer::ProtocolId;

#[test]
fn duplicate_filter_field_paths_are_rejected_case_insensitively() {
    let mut builder = RegistryBuilder::new();
    builder
        .bind_filter_field(
            "ip.src",
            FilterFieldBinding::Direct {
                protocol: ProtocolId::new("ipv4"),
                field: "source",
            },
        )
        .unwrap();
    assert!(matches!(
        builder.bind_filter_field(
            "IP.SRC",
            FilterFieldBinding::Direct {
                protocol: ProtocolId::new("ipv6"),
                field: "source",
            },
        ),
        Err(RegistryError::DuplicateFilterField { .. })
    ));
}

#[test]
fn a_filter_field_binding_on_an_unregistered_protocol_fails_the_build() {
    let mut builder = RegistryBuilder::new();
    builder
        .bind_filter_field(
            "ip.src",
            FilterFieldBinding::Direct {
                protocol: ProtocolId::new("ipv4"),
                field: "source",
            },
        )
        .unwrap();
    assert!(matches!(
        builder.build(),
        Err(RegistryError::UnknownProtocol { .. })
    ));
}

#[test]
fn a_bit_selection_that_addresses_nothing_is_rejected_at_the_call_site() {
    let mut builder = RegistryBuilder::new();
    let empty_mask = builder.bind_filter_field(
        "tcp.flags.syn",
        FilterFieldBinding::Bits {
            protocol: ProtocolId::new("tcp"),
            field: "flags",
            mask: 0,
            shift: 1,
        },
    );
    assert!(matches!(
        empty_mask,
        Err(RegistryError::InvalidFilterField { .. })
    ));

    let wide_shift = builder.bind_filter_field(
        "tcp.flags.fin",
        FilterFieldBinding::Bits {
            protocol: ProtocolId::new("tcp"),
            field: "flags",
            mask: 1,
            shift: u64::BITS,
        },
    );
    assert!(matches!(
        wide_shift,
        Err(RegistryError::InvalidFilterField { .. })
    ));

    // A shift past the mask's highest bit is in range but still extracts
    // nothing, so it must not build either.
    let shifted_past_mask = builder.bind_filter_field(
        "tcp.flags.rst",
        FilterFieldBinding::Bits {
            protocol: ProtocolId::new("tcp"),
            field: "flags",
            mask: 0x02,
            shift: 2,
        },
    );
    assert!(matches!(
        shifted_past_mask,
        Err(RegistryError::InvalidFilterField { .. })
    ));

    // The correct pairing for the same bit must still be accepted.
    builder
        .bind_filter_field(
            "tcp.flags.syn",
            FilterFieldBinding::Bits {
                protocol: ProtocolId::new("tcp"),
                field: "flags",
                mask: 0x02,
                shift: 1,
            },
        )
        .unwrap();
}

#[test]
fn an_either_binding_without_fields_is_rejected() {
    let mut builder = RegistryBuilder::new();
    assert!(matches!(
        builder.bind_filter_field(
            "tcp.port",
            FilterFieldBinding::Either {
                protocol: ProtocolId::new("tcp"),
                fields: &[],
            },
        ),
        Err(RegistryError::InvalidFilterField { .. })
    ));
}

#[test]
fn rebinding_a_child_is_idempotent_only_at_the_same_priority() {
    let mut builder = RegistryBuilder::new();
    builder.bind("parent", 1, "child", 10).unwrap();
    builder.bind("parent", 1, "child", 10).unwrap();
    assert!(matches!(
        builder.bind("parent", 1, "child", 20),
        Err(RegistryError::BindingConflict {
            discriminator: 1,
            priority: 20,
            ..
        })
    ));
}
