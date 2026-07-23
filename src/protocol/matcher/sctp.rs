// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use crate::packet::{Packet, field::FieldValue};

pub(super) fn sctp_initiate_tag(
    packet: &Packet,
    sctp_index: usize,
    expected_type: u8,
) -> Option<(u32, Bytes)> {
    let FieldValue::Bytes(bytes) = packet.layer(sctp_index + 1)?.field("bytes")? else {
        return None;
    };
    if bytes.len() < 20 || bytes[0] != expected_type {
        return None;
    }
    let chunk_len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if chunk_len < 20 || chunk_len > bytes.len() {
        return None;
    }
    Some((
        u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        bytes,
    ))
}
