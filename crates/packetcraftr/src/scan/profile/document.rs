// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Compiles the assignments of a `packetcraftr.udp-profiles/v1` document,
//! read by core, into the per-port profiles a scan request takes.

use std::collections::BTreeMap;
use std::sync::Arc;

use packetcraftr_core::document::udp_profiles::{Assignment, MAX_PROFILE_BYTES, MAX_PROFILE_PORTS};

use super::{Error, UdpProfile};

/// Compiles a document's assignments, in order, into per-port profiles.
///
/// Each assignment names 1..=[`MAX_PROFILE_PORTS`] ports, and the document
/// maps at most [`MAX_PROFILE_PORTS`] ports in all. Identical profiles are
/// compiled and charged once and shared between their ports, whose compiled
/// storage stays within [`MAX_PROFILE_BYTES`]. A port may repeat only with an
/// identical profile.
pub fn compile(assignments: Vec<Assignment>) -> Result<BTreeMap<u16, Arc<UdpProfile>>, Error> {
    let mut profiles: BTreeMap<u16, Arc<UdpProfile>> = BTreeMap::new();
    let mut unique: Vec<Arc<UdpProfile>> = Vec::new();
    let mut charged = 0usize;
    for assignment in assignments {
        if assignment.ports.is_empty() || assignment.ports.len() > MAX_PROFILE_PORTS {
            return Err(Error::PortCount {
                count: assignment.ports.len(),
            });
        }
        let compiled = UdpProfile::new(assignment.profile)?;
        let profile = if let Some(existing) = unique.iter().find(|existing| ***existing == compiled)
        {
            existing.clone()
        } else {
            charged = charged.saturating_add(compiled.storage_bytes());
            if charged > MAX_PROFILE_BYTES {
                return Err(Error::Storage);
            }
            let compiled = Arc::new(compiled);
            unique.push(compiled.clone());
            compiled
        };
        for port in assignment.ports {
            if let Some(existing) = profiles.get(&port) {
                if existing.as_ref() != profile.as_ref() {
                    return Err(Error::ConflictingPort { port });
                }
            } else {
                if profiles.len() >= MAX_PROFILE_PORTS {
                    return Err(Error::MappedPorts);
                }
                profiles.insert(port, profile.clone());
            }
        }
    }
    Ok(profiles)
}
