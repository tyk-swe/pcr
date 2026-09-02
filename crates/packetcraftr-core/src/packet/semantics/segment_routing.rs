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
    let Some(&final_destination) = segments.last().filter(|_| segments.len() <= 127) else {
        return Err(Error::SegmentCount);
    };
    let expected_last = u8::try_from(segments.len().saturating_sub(1))
        .map_err(|_| Error::SegmentCountUnrepresentable)?;
    if last_entry != expected_last {
        return Err(Error::SegmentLastEntry {
            last_entry,
            expected: expected_last,
        });
    }
    if segments_left > last_entry {
        return Err(Error::SegmentsLeft {
            segments_left,
            last_entry,
        });
    }
    if flags != 0 {
        return Err(Error::SegmentFlags);
    }
    let active_index = usize::from(last_entry.saturating_sub(segments_left));
    #[expect(
        clippy::indexing_slicing,
        reason = "segments_left <= last_entry == segments.len() - 1 is checked above"
    )]
    let active_destination = segments[active_index];
    if !header_destination.is_unspecified() && header_destination != active_destination {
        return Err(Error::SegmentDestinationMismatch {
            header: header_destination,
            active: active_destination,
        });
    }
    Ok(SegmentRoute {
        active_destination,
        final_destination,
        segments,
        active_index,
    })
}
