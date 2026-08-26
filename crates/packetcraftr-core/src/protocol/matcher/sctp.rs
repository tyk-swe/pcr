// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use crate::{Packet, field::FieldValue};

pub(super) fn sctp_initiate_tag(
    packet: &Packet,
    sctp_index: usize,
    expected_type: u8,
) -> Option<(u32, Bytes)> {
    let chunk_index = sctp_index.checked_add(1)?;
    let FieldValue::Bytes(bytes) = packet.layer(chunk_index)?.field("bytes")? else {
        return None;
    };
    let header = bytes.first_chunk::<8>()?;
    if bytes.len() < 20 || header[0] != expected_type {
        return None;
    }
    let chunk_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
    if chunk_len < 20 || chunk_len > bytes.len() {
        return None;
    }
    let initiate_tag = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    Some((initiate_tag, bytes))
}
