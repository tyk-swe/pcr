// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::sync::Arc;

use packetcraftr_core::document::udp_profiles::{Assignment, MAX_PROFILE_BYTES, MAX_PROFILE_PORTS};

use super::{Error, UdpProfile};

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
