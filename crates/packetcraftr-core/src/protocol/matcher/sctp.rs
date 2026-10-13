// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use crate::packet::Packet;

use super::opaque_bytes;

const CHUNK_HEADER_LEN: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SctpResponseKind {
    InitAck,
    Abort,
    Other,
}

pub(super) fn sctp_initiate_tag(
    packet: &Packet,
    sctp_index: usize,
    expected_type: u8,
) -> Option<(u32, Bytes)> {
    let chunk_index = sctp_index.checked_add(1)?;
    let bytes = opaque_bytes(packet.layer(chunk_index)?)?.clone();
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

pub(super) fn sctp_cookie_echo(packet: &Packet, sctp_index: usize) -> Option<Bytes> {
    let chunk_index = sctp_index.checked_add(1)?;
    let bytes = opaque_bytes(packet.layer(chunk_index)?)?.clone();
    let header = bytes.first_chunk::<CHUNK_HEADER_LEN>()?;
    if bytes.len() < 8 || header[0] != 10 {
        return None;
    }
    let chunk_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
    if chunk_len < 8 || chunk_len > bytes.len() {
        return None;
    }
    Some(bytes)
}

pub fn sctp_response_kind(packet: &Packet, sctp_index: usize) -> Option<SctpResponseKind> {
    let chunk_index = sctp_index.checked_add(1)?;
    let bytes = opaque_bytes(packet.layer(chunk_index)?)?;
    if bytes.is_empty() {
        return None;
    }
    if let Some((initiate_tag, _)) = sctp_initiate_tag(packet, sctp_index, 2)
        && initiate_tag != 0
    {
        return Some(SctpResponseKind::InitAck);
    }
    let mut cursor = 0_usize;
    let mut has_chunk = false;
    let mut has_abort = false;
    while cursor < bytes.len() {
        let remaining = bytes.len().saturating_sub(cursor);
        let chunk_header = bytes
            .get(cursor..)
            .and_then(<[u8]>::first_chunk::<CHUNK_HEADER_LEN>)?;
        let chunk_type = chunk_header[0];
        let chunk_len = usize::from(u16::from_be_bytes([chunk_header[2], chunk_header[3]]));
        if chunk_len < CHUNK_HEADER_LEN || chunk_len > remaining {
            return None;
        }
        let padded_len = chunk_len.checked_add(3).map(|length| length & !3)?;
        if padded_len > remaining {
            return None;
        }
        if chunk_type == 2 {
            // An INIT ACK with a zero initiate tag or truncated body is invalid.
            return None;
        }
        if chunk_type == 6 {
            has_abort = true;
        }
        has_chunk = true;
        cursor = cursor.saturating_add(padded_len);
    }
    if !has_chunk {
        return None;
    }
    if has_abort {
        Some(SctpResponseKind::Abort)
    } else {
        Some(SctpResponseKind::Other)
    }
}
