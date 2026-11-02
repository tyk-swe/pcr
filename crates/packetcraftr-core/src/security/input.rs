// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{AMBIGUOUS_OUTPUT_SCHEMA, OUTPUT_SCHEMA};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct Aggregate<T> {
    pub command: String,
    pub result: T,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid aggregate JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error(
        "{AMBIGUOUS_OUTPUT_SCHEMA} is ambiguous across releases, so regenerate the input with this release, which emits {OUTPUT_SCHEMA}"
    )]
    AmbiguousSchema,
    #[error("input must be successful aggregate {OUTPUT_SCHEMA} JSON from an allowed command")]
    InvalidEnvelope,
}

pub fn aggregate<T: DeserializeOwned>(
    bytes: &[u8],
    allowed_commands: &[&str],
) -> Result<Aggregate<T>, Error> {
    let envelope: Value = serde_json::from_slice(bytes)?;
    if envelope["schema"] == AMBIGUOUS_OUTPUT_SCHEMA {
        return Err(Error::AmbiguousSchema);
    }
    if envelope["schema"] != OUTPUT_SCHEMA
        || envelope["status"] != "success"
        || envelope["mode"] != "aggregate"
        || !envelope["command"]
            .as_str()
            .is_some_and(|command| allowed_commands.contains(&command))
    {
        return Err(Error::InvalidEnvelope);
    }
    Ok(serde_json::from_value(envelope)?)
}
