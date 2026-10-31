// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use sha2::{Digest, Sha256};

const MAGIC: &[u8; 4] = b"PCR1";
const VERSION: u8 = 1;
const KIND_PROBE: u8 = 1;
const KIND_REPLY: u8 = 2;
const HEADER_LEN: usize = 30;
const HASH_LEN: usize = 32;

pub const TOKEN_LEN: usize = 16;
pub const MIN_PAYLOAD_LEN: usize = HEADER_LEN + HASH_LEN;
pub const REPLY_LEN: usize = 28 + HASH_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Probe {
    pub token: [u8; TOKEN_LEN],
    pub variant_index: u16,
    pub attempt_seq: u32,
    pub payload_sha256: [u8; HASH_LEN],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub token: [u8; TOKEN_LEN],
    pub variant_index: u16,
    pub attempt_seq: u32,
    pub received_payload_sha256: [u8; HASH_LEN],
}

fn filler_byte(offset: usize) -> u8 {
    ((offset as u32).wrapping_mul(31).wrapping_add(7) & 0xFF) as u8
}

fn trailer(token: &[u8; TOKEN_LEN], prefix: &[u8]) -> [u8; HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(token);
    hasher.update(prefix);
    hasher.finalize().into()
}

pub fn payload_sha256(payload: &[u8]) -> [u8; HASH_LEN] {
    Sha256::digest(payload).into()
}

/// Builds one probe payload. `total_len` must already be validated against
/// [`MIN_PAYLOAD_LEN`] and the caller's maximum.
#[must_use]
pub fn build_probe(
    token: &[u8; TOKEN_LEN],
    variant_index: u16,
    attempt_seq: u32,
    total_len: usize,
) -> Vec<u8> {
    let mut payload = vec![0_u8; total_len];
    payload[0..4].copy_from_slice(MAGIC);
    payload[4] = VERSION;
    payload[5] = KIND_PROBE;
    payload[6..6 + TOKEN_LEN].copy_from_slice(token);
    payload[22..24].copy_from_slice(&variant_index.to_be_bytes());
    payload[24..28].copy_from_slice(&attempt_seq.to_be_bytes());
    payload[28..30].copy_from_slice(&(total_len as u16).to_be_bytes());
    for (offset, byte) in payload
        .iter_mut()
        .enumerate()
        .take(total_len - HASH_LEN)
        .skip(HEADER_LEN)
    {
        *byte = filler_byte(offset);
    }
    let digest = trailer(token, &payload[..total_len - HASH_LEN]);
    payload[total_len - HASH_LEN..].copy_from_slice(&digest);
    payload
}

#[must_use]
pub fn build_reply(probe: &Probe) -> Vec<u8> {
    let mut payload = vec![0_u8; REPLY_LEN];
    payload[0..4].copy_from_slice(MAGIC);
    payload[4] = VERSION;
    payload[5] = KIND_REPLY;
    payload[6..6 + TOKEN_LEN].copy_from_slice(&probe.token);
    payload[22..24].copy_from_slice(&probe.variant_index.to_be_bytes());
    payload[24..28].copy_from_slice(&probe.attempt_seq.to_be_bytes());
    payload[28..REPLY_LEN].copy_from_slice(&probe.payload_sha256);
    payload
}

fn header(payload: &[u8], kind: u8) -> Option<([u8; TOKEN_LEN], u16, u32)> {
    if payload.len() < 28 || &payload[0..4] != MAGIC || payload[4] != VERSION || payload[5] != kind
    {
        return None;
    }
    let mut token = [0_u8; TOKEN_LEN];
    token.copy_from_slice(&payload[6..6 + TOKEN_LEN]);
    let variant_index = u16::from_be_bytes(payload[22..24].try_into().ok()?);
    let attempt_seq = u32::from_be_bytes(payload[24..28].try_into().ok()?);
    Some((token, variant_index, attempt_seq))
}

#[must_use]
pub fn parse_probe(payload: &[u8]) -> Option<Probe> {
    if payload.len() < MIN_PAYLOAD_LEN {
        return None;
    }
    let (token, variant_index, attempt_seq) = header(payload, KIND_PROBE)?;
    let declared_len = usize::from(u16::from_be_bytes(payload[28..30].try_into().ok()?));
    if declared_len != payload.len() {
        return None;
    }
    let (prefix, presented) = payload.split_at(payload.len() - HASH_LEN);
    if trailer(&token, prefix).as_slice() != presented {
        return None;
    }
    Some(Probe {
        token,
        variant_index,
        attempt_seq,
        payload_sha256: payload_sha256(payload),
    })
}

#[must_use]
pub fn parse_reply(payload: &[u8]) -> Option<Reply> {
    if payload.len() != REPLY_LEN {
        return None;
    }
    let (token, variant_index, attempt_seq) = header(payload, KIND_REPLY)?;
    let mut received_payload_sha256 = [0_u8; HASH_LEN];
    received_payload_sha256.copy_from_slice(&payload[28..REPLY_LEN]);
    Some(Reply {
        token,
        variant_index,
        attempt_seq,
        received_payload_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: [u8; TOKEN_LEN] = [0x42; TOKEN_LEN];

    #[test]
    fn probe_round_trips_and_reply_names_the_probe() {
        let payload = build_probe(&TOKEN, 3, 7, 256);
        let probe = parse_probe(&payload).expect("probe parses");
        assert_eq!(probe.variant_index, 3);
        assert_eq!(probe.attempt_seq, 7);
        assert_eq!(probe.payload_sha256, payload_sha256(&payload));

        let reply = parse_reply(&build_reply(&probe)).expect("reply parses");
        assert_eq!(reply.variant_index, 3);
        assert_eq!(reply.attempt_seq, 7);
        assert_eq!(reply.received_payload_sha256, probe.payload_sha256);
    }

    #[test]
    fn tampered_probe_is_rejected() {
        let mut payload = build_probe(&TOKEN, 0, 0, 256);
        payload[100] ^= 0xFF;
        assert!(parse_probe(&payload).is_none());
    }

    #[test]
    fn reply_is_smaller_than_probe_and_wrong_kind_is_rejected() {
        let payload = build_probe(&TOKEN, 0, 0, 256);
        assert!(build_reply(&parse_probe(&payload).expect("probe")).len() < payload.len());
        assert!(parse_reply(&payload).is_none());
        assert!(parse_probe(&build_reply(&parse_probe(&payload).expect("probe"))).is_none());
    }
}
