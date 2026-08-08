// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Helpers shared by the built-in `LayerCodec` implementations.
//!
//! Each submodule owns one concern; this module is a flat facade so codecs
//! keep importing from `protocol::common` regardless of where a helper lives.

mod checksum;
mod errors;
mod fields;
mod payload;
mod validation;

pub(crate) use checksum::{
    checksum, checksum_parts, network_from_addresses, transport_checksum, transport_checksum_parts,
};
pub(crate) use errors::{
    binding_protocol, invalid, out_of_range, protocol, truncated, wrong_layer, wrong_type,
};
pub(crate) use fields::{
    ValueExpectation, aliased_fields, expected_discriminator, expected_discriminator_for_value,
    make_layer, resolve_u8, resolve_u16, validate_dependent,
};
pub(crate) use payload::payload_without_padding;
pub(crate) use validation::{
    ensure_encode_budget, strict_or_diagnostic, validate_auto_raw_discriminator,
    validate_ipv6_routing_child, validate_raw_child_discriminator,
    validate_typed_child_discriminator,
};
