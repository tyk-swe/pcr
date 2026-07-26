// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared validation for results crossing a protocol-provider boundary.

use std::net::IpAddr;

use crate::codec::NetworkEnvelope;
use crate::layer::{Layer, ProtocolId};
use crate::layout::FieldLayout;

pub(crate) fn protocol_is_owned(expected: &ProtocolId, actual: &ProtocolId) -> bool {
    expected == actual
}

pub(crate) fn decoded_protocol_is_accepted(
    requested: &ProtocolId,
    accepted: &[ProtocolId],
    actual: &ProtocolId,
) -> bool {
    requested == actual || accepted.binary_search(actual).is_ok()
}

pub(crate) fn layer_count_within_limit(actual: usize, limit: usize) -> bool {
    actual <= limit
}

pub(crate) fn packet_size_within_limit(actual: usize, limit: usize) -> bool {
    actual <= limit
}

pub(crate) fn decode_payload_end(
    input_len: usize,
    consumed: usize,
    payload_offset: usize,
    payload_len: usize,
    stop: bool,
) -> Option<usize> {
    if consumed > input_len
        || payload_offset > input_len
        || consumed != payload_offset
        || (!stop && payload_offset == 0)
    {
        return None;
    }
    payload_offset
        .checked_add(payload_len)
        .filter(|end| *end <= input_len)
}

pub(crate) fn field_layouts_are_valid(
    layer: &dyn Layer,
    fields: &[FieldLayout],
    encoded_extent: usize,
) -> bool {
    fields.iter().all(|field| {
        layer.schema().field(&field.id).is_some()
            && field.range.start <= field.range.end
            && field.range.end <= encoded_extent
    })
}

pub(crate) fn network_envelope_is_valid(envelope: NetworkEnvelope) -> bool {
    addresses_share_family(envelope.source, envelope.destination)
}

pub(crate) fn optional_network_pair_is_valid(
    source: Option<IpAddr>,
    destination: Option<IpAddr>,
) -> bool {
    match (source, destination) {
        (Some(source), Some(destination)) => addresses_share_family(source, destination),
        _ => true,
    }
}

fn addresses_share_family(source: IpAddr, destination: IpAddr) -> bool {
    matches!(
        (source, destination),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn network_envelopes_must_use_one_address_family() {
        assert!(network_envelope_is_valid(NetworkEnvelope {
            source: Ipv4Addr::LOCALHOST.into(),
            destination: Ipv4Addr::UNSPECIFIED.into(),
        }));
        assert!(!network_envelope_is_valid(NetworkEnvelope {
            source: Ipv4Addr::LOCALHOST.into(),
            destination: Ipv6Addr::LOCALHOST.into(),
        }));
    }
}
