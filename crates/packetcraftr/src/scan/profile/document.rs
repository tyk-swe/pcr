// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The versioned `packetcraftr.udp-profiles/v1` document, which assigns
//! UDP profiles to destination ports.

use std::collections::BTreeMap;
use std::sync::Arc;

use packetcraftr_core::error::{Classification, Classified, Kind, Source, source_chain};
use serde::Deserialize;

use super::{Config, Error, MAX_PROFILE_BYTES, MAX_PROFILE_PORTS, UdpProfile};

/// The schema of a UDP profiles document.
pub const UDP_PROFILES_SCHEMA_V1: &str = "packetcraftr.udp-profiles/v1";
/// The most port assignments one UDP profiles document may hold.
pub const MAX_PROFILE_ASSIGNMENTS: usize = 256;

// serde names these types in syntax messages, which are published, so the
// names stay as they were.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema: String,
    profiles: Vec<Assignment>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Assignment {
    ports: Vec<u16>,
    profile: Config,
}

/// Reads a `packetcraftr.udp-profiles/v1` document into the per-port
/// profiles a scan request takes.
///
/// The document is at most [`MAX_PROFILE_BYTES`], holds
/// 1..=[`MAX_PROFILE_ASSIGNMENTS`] assignments of 1..=[`MAX_PROFILE_PORTS`]
/// ports each, and maps at most [`MAX_PROFILE_PORTS`] ports in all.
/// Identical profiles are compiled and charged once and shared between their
/// ports, whose compiled storage stays within [`MAX_PROFILE_BYTES`]. A port
/// may repeat only with an identical profile.
pub fn parse_document(document: &[u8]) -> Result<BTreeMap<u16, Arc<UdpProfile>>, DocumentError> {
    if document.len() > MAX_PROFILE_BYTES {
        return Err(DocumentError::DocumentSize {
            actual: document.len(),
            limit: MAX_PROFILE_BYTES,
        });
    }
    let document: Document = serde_json::from_slice(document)
        .map_err(|source| DocumentError::Syntax(Source::new(source)))?;
    if document.schema != UDP_PROFILES_SCHEMA_V1 {
        return Err(DocumentError::Schema {
            schema: document.schema,
        });
    }
    if document.profiles.is_empty() || document.profiles.len() > MAX_PROFILE_ASSIGNMENTS {
        return Err(DocumentError::AssignmentCount {
            count: document.profiles.len(),
        });
    }
    let mut profiles: BTreeMap<u16, Arc<UdpProfile>> = BTreeMap::new();
    let mut unique: Vec<Arc<UdpProfile>> = Vec::new();
    let mut charged = 0usize;
    for assignment in document.profiles {
        if assignment.ports.is_empty() || assignment.ports.len() > MAX_PROFILE_PORTS {
            return Err(DocumentError::PortCount {
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
                return Err(DocumentError::Storage);
            }
            let compiled = Arc::new(compiled);
            unique.push(compiled.clone());
            compiled
        };
        for port in assignment.ports {
            if let Some(existing) = profiles.get(&port) {
                if existing.as_ref() != profile.as_ref() {
                    return Err(DocumentError::ConflictingPort { port });
                }
            } else {
                if profiles.len() >= MAX_PROFILE_PORTS {
                    return Err(DocumentError::MappedPorts);
                }
                profiles.insert(port, profile.clone());
            }
        }
    }
    Ok(profiles)
}

/// Why a UDP profiles document could not be read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DocumentError {
    /// The document is larger than [`MAX_PROFILE_BYTES`].
    #[error("UDP profiles document has {actual} bytes, exceeding limit {limit}")]
    DocumentSize { actual: usize, limit: usize },
    /// The document is not JSON of the published shape. The message already
    /// names the parser's reason.
    #[error("invalid UDP profiles: {0}")]
    Syntax(#[source] Source),
    #[error("UDP profiles require schema packetcraftr.udp-profiles/v1 and 1..=256 assignments")]
    Schema { schema: String },
    #[error("UDP profiles require schema packetcraftr.udp-profiles/v1 and 1..=256 assignments")]
    AssignmentCount { count: usize },
    #[error("each UDP profile needs 1..=4096 port entries")]
    PortCount { count: usize },
    /// One profile is invalid; it keeps the profile's classification.
    #[error(transparent)]
    Profile(#[from] Error),
    /// The distinct compiled profiles exceed [`MAX_PROFILE_BYTES`].
    #[error("compiled UDP profiles exceed 1 MiB")]
    Storage,
    /// Two different profiles claim the same port.
    #[error("conflicting UDP profiles for port {port}")]
    ConflictingPort { port: u16 },
    /// The assignments map more than [`MAX_PROFILE_PORTS`] ports.
    #[error("UDP profiles exceed 4096 mapped ports")]
    MappedPorts,
}

impl Classified for DocumentError {
    fn classification(&self) -> Classification {
        match self {
            Self::Profile(source) => source.classification(),
            Self::DocumentSize { .. }
            | Self::Syntax(_)
            | Self::Schema { .. }
            | Self::AssignmentCount { .. }
            | Self::PortCount { .. }
            | Self::Storage
            | Self::ConflictingPort { .. }
            | Self::MappedPorts => Classification::new("cli.error", Kind::Usage, None),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            // The message already carries the parser's reason.
            Self::Syntax(_) => Vec::new(),
            _ => source_chain(self),
        }
    }
}
