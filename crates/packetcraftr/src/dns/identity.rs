// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Unpredictable DNS transaction identities and source ports, so an off-path
//! spoofer cannot guess the tuple a reply must match.

use packetcraftr_core::error::{BoundaryError, Classification, Kind};

/// Callers needing reproducible experiments supply a fixed identity in `Request` instead.
pub fn unpredictable_transaction_id() -> Result<u16, BoundaryError> {
    random_u16(getrandom::fill)
}

/// Retries rotate deterministically from this random base, not with independent entropy.
pub fn unpredictable_source_port() -> Result<u16, BoundaryError> {
    random_u16(getrandom::fill).map(|value| {
        crate::engine::correlation::ephemeral_source_port(
            crate::engine::correlation::EPHEMERAL_SOURCE_PORT_BASE,
            u64::from(value),
        )
    })
}

fn random_u16(
    fill: impl FnOnce(&mut [u8]) -> Result<(), getrandom::Error>,
) -> Result<u16, BoundaryError> {
    let mut bytes = [0; 2];
    fill(&mut bytes).map_err(|source| {
        BoundaryError::with_source(
            "could not obtain system randomness for DNS identity",
            Classification::new("io.dns_entropy", Kind::Io, None),
            std::iter::once(source.to_string())
                .chain(packetcraftr_core::error::source_chain(&source))
                .collect(),
            source,
        )
    })?;
    Ok(u16::from_ne_bytes(bytes))
}
