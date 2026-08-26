// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::time::SystemTime;

pub(super) fn transaction_id() -> u16 {
    let bytes = entropy().to_le_bytes();
    u16::from_le_bytes([bytes[0], bytes[1]])
}

pub(super) fn source_port() -> u16 {
    packetcraftr::ephemeral_source_port(packetcraftr::EPHEMERAL_SOURCE_PORT_BASE, entropy())
}

fn entropy() -> u64 {
    let time = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u128(time);
    hasher.write_u32(std::process::id());
    hasher.finish()
}
