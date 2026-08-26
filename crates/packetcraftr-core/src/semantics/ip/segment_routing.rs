// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv6Addr;

use super::error::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentRoute {
    pub active_destination: Ipv6Addr,
    pub final_destination: Ipv6Addr,
    pub segments: Vec<Ipv6Addr>,
    pub active_index: usize,
}

/// Validates the routing state shared by typed packets and captured SRH bytes.
pub fn validate_segment_route(
    header_destination: Ipv6Addr,
    segments: Vec<Ipv6Addr>,
    segments_left: u8,
    last_entry: u8,
    flags: u8,
) -> Result<SegmentRoute, Error> {
    if segments.is_empty() || segments.len() > 127 {
        return Err(Error::new("SRH requires 1..=127 IPv6 segments"));
    }
    let expected_last = u8::try_from(segments.len().saturating_sub(1))
        .map_err(|_| Error::new("SRH segment count cannot be represented"))?;
    if last_entry != expected_last {
        return Err(Error::new(format!(
            "SRH last_entry {last_entry} does not match segment-list index {expected_last}"
        )));
    }
    if segments_left > last_entry {
        return Err(Error::new(format!(
            "SRH segments_left {segments_left} exceeds last_entry {last_entry}"
        )));
    }
    if flags != 0 {
        return Err(Error::new("unsupported SRH flags are non-zero"));
    }
    let active_index = usize::from(last_entry.saturating_sub(segments_left));
    #[expect(
        clippy::indexing_slicing,
        reason = "segments_left <= last_entry == segments.len() - 1 is checked above"
    )]
    let active_destination = segments[active_index];
    if !header_destination.is_unspecified() && header_destination != active_destination {
        return Err(Error::new(format!(
            "IPv6 header destination {header_destination} does not match active SRH segment {active_destination}"
        )));
    }
    let final_destination = *segments
        .last()
        .expect("non-empty segment list was validated");
    Ok(SegmentRoute {
        active_destination,
        final_destination,
        segments,
        active_index,
    })
}
