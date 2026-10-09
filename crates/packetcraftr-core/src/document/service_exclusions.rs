// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Independently versioned sensitive-service exclusions, checked before planning.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::{
    port_catalog::Transport,
    service_probes::{Error as ValidationError, Metadata, identifier, invalid, metadata, text},
};
use crate::error::{Classification, Classified, Kind, Source};

pub const SERVICE_EXCLUSIONS_SCHEMA_V1: &str = "packetcraftr.service-exclusions/v1";
pub const MAX_EXCLUSIONS_BYTES: usize = 64 * 1024;
pub const MAX_EXCLUSION_ENTRIES: usize = 64;
/// Maximum ports per entry, alongside the entry-count and document-byte bounds.
pub const MAX_EXCLUSION_PORTS: usize = 2048;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exclusion {
    pub transport: Transport,
    pub ports: Vec<u16>,
    pub reason: String,
    pub metadata: Metadata,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exclusions {
    pub schema: String,
    pub name: String,
    pub version: String,
    pub entries: Vec<Exclusion>,
}

/// Exclusion-document error retaining the shared bounded validation source.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct Error(#[from] ValidationError);

impl Classified for Error {
    fn classification(&self) -> Classification {
        Classification::new("document.service_exclusions", Kind::Usage, None)
    }
}

impl Exclusions {
    /// Explicit operator override that removes the bundled exclusions. Its
    /// provenance remains distinct from the project's reviewed default list.
    pub fn empty() -> Self {
        Self {
            schema: SERVICE_EXCLUSIONS_SCHEMA_V1.into(),
            name: "operator-override".into(),
            version: "1".into(),
            entries: Vec::new(),
        }
    }

    pub fn excludes(&self, transport: Transport, port: u16) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.transport == transport && entry.ports.contains(&port))
    }

    pub fn validate(&self) -> Result<(), Error> {
        self.validate_entries().map_err(Error)
    }

    fn validate_entries(&self) -> Result<(), ValidationError> {
        if self.schema != SERVICE_EXCLUSIONS_SCHEMA_V1 {
            return Err(invalid("schema", "unsupported service-exclusions schema"));
        }
        identifier("exclusions name", &self.name)?;
        text("exclusions version", &self.version)?;
        if self.entries.len() > MAX_EXCLUSION_ENTRIES {
            return Err(invalid("exclusions entries", "expected at most 64 entries"));
        }
        for entry in &self.entries {
            text("exclusion reason", &entry.reason)?;
            metadata(&entry.metadata)?;
            if entry.ports.is_empty() || entry.ports.len() > MAX_EXCLUSION_PORTS {
                return Err(invalid(
                    "exclusion ports",
                    "expected 1 to 2048 ports per entry",
                ));
            }
            let mut seen = BTreeSet::new();
            for port in &entry.ports {
                if *port == 0 || !seen.insert(*port) {
                    return Err(invalid("exclusion port", "zero or duplicate port in entry"));
                }
            }
        }
        Ok(())
    }
}

pub fn parse(document: &[u8]) -> Result<Exclusions, Error> {
    if document.len() > MAX_EXCLUSIONS_BYTES {
        return Err(ValidationError::DocumentSize {
            actual: document.len(),
            limit: MAX_EXCLUSIONS_BYTES,
        }
        .into());
    }
    let exclusions: Exclusions = serde_json::from_slice(document)
        .map_err(|source| ValidationError::Syntax(Source::new(source)))?;
    exclusions.validate()?;
    Ok(exclusions)
}
