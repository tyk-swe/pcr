// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use crate::errors::CliError;
use packetcraftr::scan::profile::{Config, MAX_PROFILE_BYTES, MAX_PROFILE_PORTS, UdpProfile};
use packetcraftr_core::error::Kind;
use std::{collections::BTreeMap, path::Path, sync::Arc};
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema: String,
    profiles: Vec<Assignment>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Assignment {
    ports: Vec<u16>,
    profile: Config,
}
pub(super) fn load(
    path: Option<&Path>,
    transport: super::arguments::Transport,
) -> Result<BTreeMap<u16, Arc<UdpProfile>>, CliError> {
    let Some(path) = path else {
        return Ok(BTreeMap::new());
    };
    if !matches!(transport, super::arguments::Transport::Udp) {
        return Err(CliError::new(
            Kind::Usage,
            "--udp-profiles requires --transport udp",
        ));
    }
    let bytes = crate::input::read_bounded_json_document(path, MAX_PROFILE_BYTES)?;
    let document: Document = serde_json::from_slice(&bytes)
        .map_err(|error| CliError::new(Kind::Usage, format!("invalid UDP profiles: {error}")))?;
    if document.schema != "packetcraftr.udp-profiles/v1"
        || document.profiles.is_empty()
        || document.profiles.len() > 256
    {
        return Err(CliError::new(
            Kind::Usage,
            "UDP profiles require schema packetcraftr.udp-profiles/v1 and 1..=256 assignments",
        ));
    }
    let mut profiles: BTreeMap<u16, Arc<UdpProfile>> = BTreeMap::new();
    let mut unique: Vec<Arc<UdpProfile>> = Vec::new();
    let mut charged = 0usize;
    for assignment in document.profiles {
        if assignment.ports.is_empty() || assignment.ports.len() > MAX_PROFILE_PORTS {
            return Err(CliError::new(
                Kind::Usage,
                "each UDP profile needs 1..=4096 port entries",
            ));
        }
        let compiled = UdpProfile::new(assignment.profile).map_err(CliError::classified)?;
        let profile = if let Some(existing) = unique.iter().find(|existing| ***existing == compiled)
        {
            existing.clone()
        } else {
            charged = charged.saturating_add(compiled.storage_bytes());
            if charged > MAX_PROFILE_BYTES {
                return Err(CliError::new(
                    Kind::Usage,
                    "compiled UDP profiles exceed 1 MiB",
                ));
            }
            let compiled = Arc::new(compiled);
            unique.push(compiled.clone());
            compiled
        };
        for port in assignment.ports {
            if let Some(existing) = profiles.get(&port) {
                if existing.as_ref() != profile.as_ref() {
                    return Err(CliError::new(
                        Kind::Usage,
                        format!("conflicting UDP profiles for port {port}"),
                    ));
                }
            } else {
                if profiles.len() >= MAX_PROFILE_PORTS {
                    return Err(CliError::new(
                        Kind::Usage,
                        "UDP profiles exceed 4096 mapped ports",
                    ));
                }
                profiles.insert(port, profile.clone());
            }
        }
    }
    Ok(profiles)
}
