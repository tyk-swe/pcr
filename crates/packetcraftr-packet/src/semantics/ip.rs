// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Canonical IP and live-route interpretation.

mod destination;
mod error;
mod ipv4_option;
mod path;
mod segment_routing;
mod transport;
mod vlan;

#[cfg(test)]
mod tests;

pub use destination::live_destinations;
pub use error::SemanticError;
pub use ipv4_option::ipv4_source_route_destinations;
pub use path::{
    DESTINATION, DESTINATION_PORT, IPV4_OPTIONS, IpPath, LAST_ENTRY, SEGMENTS, SEGMENTS_LEFT,
    SOURCE, SOURCE_PORT, TARGET_PROTOCOL, enclosing_ip_path, outer_ip_path, outer_layers,
    outer_scope_len,
};
pub use segment_routing::{SegmentRoute, validate_segment_route};
pub use transport::{TransportKey, transport_key, transport_keys_are_reversed};
pub use vlan::{VlanKind, VlanMetadata, vlan_metadata};
