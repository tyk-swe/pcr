// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private, canonical interpretation of packet fields used at live boundaries.

use super::Packet;
use super::field::FieldValue;
use super::layer::{Layer, ProtocolId};
#[doc(hidden)]
pub use super::protocol_catalog::BuiltinProtocol;
pub(crate) use super::protocol_catalog::builtin_protocol_catalog;

pub(crate) use ip::ipv4_source_route_destination;
pub use ip::{
    DESTINATION, DESTINATION_PORT, IPV4_OPTIONS, IpPath, LAST_ENTRY, SEGMENTS, SEGMENTS_LEFT,
    SOURCE, SOURCE_PORT, SegmentRoute, SemanticError, TARGET_PROTOCOL, TransportKey, VlanKind,
    VlanMetadata, enclosing_ip_path, live_destinations, outer_ip_path, outer_layers,
    outer_scope_len, transport_key, transport_keys_are_reversed, validate_segment_route,
    vlan_metadata,
};

mod ip;
