// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(test)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;

use super::adapter::{BufferBounds, WindowsAdapter, adapter_index_for, find_windows_adapter};
use super::enumeration::interfaces;
#[cfg(feature = "native-route")]
use super::query::encode_address;
use crate::{
    interface::{InterfaceFlags, InterfaceInfo},
    link::LinkCapability,
    route::{InterfaceId, Provider as RouteProvider, RouteSelectionReason},
};
use packetcraftr_core::frame::LinkType;

#[test]
fn adapter_buffer_bounds_reject_misaligned_and_out_of_range_pointers() {
    let storage = [0_u64; 8];
    let bounds =
        BufferBounds::new(storage.as_ptr().cast(), std::mem::size_of_val(&storage)).unwrap();
    assert!(bounds.contains(storage.as_ptr()));

    // SAFETY: the arithmetic creates inert test pointers only; neither is
    // dereferenced.
    let misaligned = unsafe { storage.as_ptr().cast::<u8>().add(1) }.cast::<u64>();
    assert!(!bounds.contains(misaligned));
    // SAFETY: this constructs the one-past-the-end sentinel pointer for a
    // bounds check only; it is not dereferenced.
    let end = unsafe {
        storage
            .as_ptr()
            .cast::<u8>()
            .add(std::mem::size_of_val(&storage))
    };
    assert!(!bounds.contains_bytes(end, 1));
}

#[cfg(feature = "native-route")]
#[test]
fn native_windows_provider_finds_loopback_routes_and_interfaces() {
    let interfaces = interfaces().unwrap();
    assert!(interfaces.iter().any(|interface| interface.flags.loopback));

    let provider = crate::route::SystemProvider;
    let ipv4 = provider
        .lookup_with_preferences(IpAddr::V4(Ipv4Addr::LOCALHOST), None, None)
        .unwrap();
    assert_eq!(ipv4.selection_reason, RouteSelectionReason::Local);
    assert!(ipv4.selected_address.is_some_and(|source| source.is_ipv4()));

    let ipv6 = provider
        .lookup_with_preferences(IpAddr::V6(Ipv6Addr::LOCALHOST), None, None)
        .unwrap();
    assert_eq!(ipv6.selection_reason, RouteSelectionReason::Local);
    assert!(ipv6.selected_address.is_some_and(|source| source.is_ipv6()));
}

#[cfg(feature = "native-route")]
#[test]
fn ipv6_scope_id_is_only_encoded_for_scoped_addresses() {
    let loopback = encode_address(IpAddr::V6(Ipv6Addr::LOCALHOST), 42);
    let global = encode_address(IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()), 42);
    let link_local = encode_address(IpAddr::V6("fe80::1".parse::<Ipv6Addr>().unwrap()), 42);

    // SAFETY: each value was constructed with its IPv6 union member active.
    assert_eq!(unsafe { loopback.Ipv6.Anonymous.sin6_scope_id }, 0);
    // SAFETY: each value was constructed with its IPv6 union member active.
    assert_eq!(unsafe { global.Ipv6.Anonymous.sin6_scope_id }, 0);
    // SAFETY: each value was constructed with its IPv6 union member active.
    assert_eq!(unsafe { link_local.Ipv6.Anonymous.sin6_scope_id }, 42);
}

#[test]
fn family_specific_adapter_indices_are_preserved_and_selected() {
    let adapter = WindowsAdapter {
        interface: InterfaceInfo {
            id: InterfaceId {
                name: "synthetic".to_owned(),
                index: 4,
            },
            description: None,
            mac_address: None,
            addresses: Vec::new(),
            flags: InterfaceFlags::default(),
            mtu: Some(1500),
            capability: LinkCapability::Layer3,
            link_type: LinkType::RAW,
        },
        ipv4_index: 4,
        ipv6_index: 9,
        luid: NET_LUID_LH::default(),
    };
    assert_eq!(
        adapter_index_for(&adapter, IpAddr::V4(Ipv4Addr::LOCALHOST)),
        4
    );
    assert_eq!(
        adapter_index_for(&adapter, IpAddr::V6(Ipv6Addr::LOCALHOST)),
        9
    );
    assert_eq!(
        find_windows_adapter(
            std::slice::from_ref(&adapter),
            &InterfaceId {
                name: "synthetic".to_owned(),
                index: 9,
            },
        )
        .unwrap()
        .ipv6_index,
        9
    );
}

#[test]
fn default_live_profile_enumerates_windows_interfaces() {
    let interfaces = interfaces().unwrap();
    assert!(!interfaces.is_empty());
    assert!(
        interfaces
            .iter()
            .all(|interface| interface.id.index != 0 && !interface.id.name.is_empty())
    );
}
