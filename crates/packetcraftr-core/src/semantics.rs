// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Canonical interpretation of packet fields used at live boundaries.
//!
//! This is a seam for `packetcraftr`, not part of the public surface: it is
//! hidden from the docs and its items may change in any release.

use super::Packet;
use super::field::FieldValue;
use super::layer::Layer;
pub use super::protocol_catalog::BuiltinProtocol;
pub(crate) use super::protocol_catalog::builtin_protocol_catalog;

pub(crate) use ip::ipv4_source_route_destination;
pub use ip::{
    DESTINATION, DESTINATION_PORT, Error, IPV4_OPTIONS, IpPath, LAST_ENTRY, SEGMENTS,
    SEGMENTS_LEFT, SOURCE, SOURCE_PORT, SegmentRoute, TARGET_PROTOCOL, TransportKey, VlanKind,
    VlanMetadata, enclosing_ip_path, live_destinations, outer_ip_path, outer_layers,
    outer_scope_len, transport_key, transport_keys_are_reversed, validate_segment_route,
    vlan_metadata,
};

mod ip;
