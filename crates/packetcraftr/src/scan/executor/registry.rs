// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
//! Operation-local protocol bindings make each explicit profile's wire intent
//! agree with strict building. The original client and registry remain intact:
//! the executor runs on a view of the client with the configured registry.
use crate::scan::Request;
use packetcraftr_core::{
    error::BoundaryError,
    layer::Id,
    registry::{Discriminator, Registry},
};
use std::sync::Arc;

/// Each scanned UDP port with a profile, and the protocol that profile
/// decodes the port as, in port order.
pub(super) fn bindings(request: &Request) -> Vec<(u16, Id)> {
    request
        .udp_profiles
        .iter()
        .filter(|(port, _)| request.ports.contains(port))
        .map(|(port, profile)| {
            (
                *port,
                Id::new(if profile.raw_payload() { "raw" } else { "dns" }),
            )
        })
        .collect()
}

/// `base` with `bindings` applied, or `base` itself when it already decodes
/// every bound port that way.
pub(super) fn configured(
    base: &Arc<Registry>,
    bindings: &[(u16, Id)],
) -> Result<Arc<Registry>, BoundaryError> {
    let overrides: Vec<_> = bindings
        .iter()
        .filter(|(port, child)| {
            base.child_for("udp", Discriminator(u64::from(*port))) != Some(*child)
        })
        .collect();
    if overrides.is_empty() {
        return Ok(base.clone());
    }
    let mut builder = base.to_builder();
    for (port, child) in overrides {
        builder
            .bind("udp", u64::from(*port), *child, i32::MAX)
            .map_err(profile_error)?;
    }
    builder.build().map(Arc::new).map_err(profile_error)
}

fn profile_error(error: impl std::fmt::Display) -> BoundaryError {
    BoundaryError::new(
        error.to_string(),
        packetcraftr_core::error::Classification::new(
            "cli.udp_profile",
            packetcraftr_core::error::Kind::Usage,
            None,
        ),
        Vec::new(),
    )
}
