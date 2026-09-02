// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Protocol layer builders and registries shared by codec contracts.

use std::net::Ipv4Addr;
use std::sync::Arc;

use packetcraftr_core::frame::LinkType;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::network::{Ipv4, Ipv6};
use packetcraftr_core::registry::Registry;

/// A spare link type bound to an explicit root protocol so a dissection can
/// start below the capture layer.
pub(crate) const ROOT_LINK_TYPE: LinkType = LinkType(u32::MAX);

pub(crate) fn rooted_registry(root: &'static str) -> Arc<Registry> {
    Arc::new(
        builtin::registry_with(|builder| {
            builder.bind_link_type(ROOT_LINK_TYPE.0, root)?;
            Ok(())
        })
        .unwrap_or_else(|error| panic!("{root} root binding: {error}")),
    )
}

pub(crate) fn ipv4(source: [u8; 4], destination: [u8; 4]) -> Ipv4 {
    Ipv4 {
        source: Ipv4Addr::from(source),
        destination: Ipv4Addr::from(destination),
        ..Ipv4::default()
    }
}

pub(crate) fn ipv6(source: &str, destination: &str) -> Ipv6 {
    Ipv6 {
        source: source.parse().expect("source address"),
        destination: destination.parse().expect("destination address"),
        ..Ipv6::default()
    }
}
