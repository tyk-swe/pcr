// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::time::SystemTime;

use packetcraftr::live as workflow;

pub(super) fn generated_dns_transaction_id() -> u16 {
    let bytes = generated_dns_entropy().to_le_bytes();
    u16::from_le_bytes([bytes[0], bytes[1]])
}

pub(super) fn generated_dns_source_port() -> u16 {
    const WIDTH: u16 = u16::MAX - workflow::dns::DNS_EPHEMERAL_SOURCE_PORT_BASE + 1;
    let offset = u16::try_from(generated_dns_entropy() % u64::from(WIDTH))
        .expect("ephemeral source-port offset is bounded to u16");
    workflow::dns::DNS_EPHEMERAL_SOURCE_PORT_BASE + offset
}

fn generated_dns_entropy() -> u64 {
    let time = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u128(time);
    hasher.write_u32(std::process::id());
    hasher.finish()
}
