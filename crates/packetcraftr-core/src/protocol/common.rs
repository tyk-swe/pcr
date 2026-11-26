// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod checksum;
mod errors;
mod fields;
mod payload;
pub(crate) mod structured;
mod validation;

pub use checksum::{
    CHECKSUM_FAILURE_CODES, ChecksumAccumulator, GRE_CHECKSUM, ICMPV4_CHECKSUM, ICMPV6_CHECKSUM,
    IGMP_CHECKSUM, IPV4_CHECKSUM, SCTP_CHECKSUM, TCP_CHECKSUM, UDP_CHECKSUM, VRRP_CHECKSUM,
    checksum_parts,
};
pub(crate) use checksum::{network_from_addresses, transport_checksum_parts};
pub(crate) use errors::{
    invalid, out_of_range, read_only, rejected, truncated, typed_layer, unsupported, wrong_type,
};
pub(crate) use fields::{
    ValueExpectation, expected_discriminator, resolve_fixed, resolve_u8, resolve_u16,
    resolve_u16_discriminator, text_list, unsigned_list,
};
pub(crate) use payload::payload_without_padding;
pub(crate) use validation::{
    ensure_encode_budget, pad_options_to_four_bytes, reject_uncarried, strict_or_diagnostic,
    strict_or_diagnostic_error, validate_auto_raw_discriminator, validate_ipv6_routing_child,
    validate_raw_child_discriminator, validate_typed_child_discriminator, zero_pad_to_four_bytes,
};
