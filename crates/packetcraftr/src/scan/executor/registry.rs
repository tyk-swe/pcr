// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
//! Operation-local protocol bindings make each explicit profile's wire intent
//! agree with strict building. The original client and registry remain intact:
//! the executor runs on a view of the client with the configured registry.
use crate::scan::Batch;
use packetcraftr_core::{
    error::BoundaryError,
    layer::Id,
    registry::{Discriminator, Registry},
};
use std::{collections::BTreeMap, sync::Arc};
pub(super) fn configured(
    base: &Arc<Registry>,
    batches: &[Batch],
) -> Result<Arc<Registry>, BoundaryError> {
    let mut mappings = BTreeMap::new();
    for batch in batches {
        let probe = batch.probe()?;
        if let Some(profile) = &probe.udp_profile
            && let Some(port) = probe.endpoint.port()
        {
            let child = Id::new(if profile.raw_payload() { "raw" } else { "dns" });
            if mappings
                .insert(port, child)
                .is_some_and(|previous| previous != child)
            {
                return Err(BoundaryError::from_error(crate::scan::profile::Error(
                    "conflicting wire profiles for one UDP port",
                )));
            }
        }
    }
    let overrides: Vec<_> = mappings
        .into_iter()
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
            .bind("udp", u64::from(port), child, i32::MAX)
            .map_err(|error| {
                BoundaryError::new(
                    error.to_string(),
                    packetcraftr_core::error::Classification::new(
                        "cli.udp_profile",
                        packetcraftr_core::error::Kind::Usage,
                        None,
                    ),
                    Vec::new(),
                )
            })?;
    }
    builder.build().map(Arc::new).map_err(|error| {
        BoundaryError::new(
            error.to_string(),
            packetcraftr_core::error::Classification::new(
                "cli.udp_profile",
                packetcraftr_core::error::Kind::Usage,
                None,
            ),
            Vec::new(),
        )
    })
}
