// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use crate::probe;
use crate::scan::Request;
use packetcraftr_core::{
    error::BoundaryError,
    layer::Id,
    protocol::BuiltinProtocol,
    registry::{Discriminator, Registry},
};
use std::sync::Arc;

pub(super) fn bindings(request: &Request) -> Vec<(u16, Id)> {
    request
        .udp_profiles
        .iter()
        .filter(|(port, _)| {
            request
                .endpoints
                .contains(&probe::Endpoint::Udp { port: **port })
        })
        .map(|(port, profile)| {
            (
                *port,
                if profile.raw_payload() {
                    BuiltinProtocol::Raw.id()
                } else {
                    BuiltinProtocol::Dns.id()
                },
            )
        })
        .collect()
}

pub(super) fn configured(
    base: &Arc<Registry>,
    bindings: &[(u16, Id)],
) -> Result<Arc<Registry>, BoundaryError> {
    let overrides: Vec<_> = bindings
        .iter()
        .filter(|(port, child)| {
            base.child_for(
                BuiltinProtocol::Udp.as_str(),
                Discriminator(u64::from(*port)),
            ) != Some(*child)
        })
        .collect();
    if overrides.is_empty() {
        return Ok(base.clone());
    }
    let mut builder = base.to_builder();
    for (port, child) in overrides {
        builder
            .bind(
                BuiltinProtocol::Udp.id(),
                u64::from(*port),
                *child,
                i32::MAX,
            )
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
