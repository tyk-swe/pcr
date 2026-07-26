// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Stable owned identifiers shared by packet, protocol, output, and catalog
//! boundaries.

use std::borrow::Borrow;
use std::fmt;

use serde::{Deserialize, Serialize};

/// An open, stable identifier for a protocol layer or codec.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProtocolId(String);

impl ProtocolId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ProtocolId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for ProtocolId {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl From<&str> for ProtocolId {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for ProtocolId {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl fmt::Display for ProtocolId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_ids_borrow_and_serialize_as_their_string() {
        let id = ProtocolId::from("ipv4");
        assert_eq!(<ProtocolId as Borrow<str>>::borrow(&id), "ipv4");
        assert_eq!(id.to_string(), "ipv4");
        assert_eq!(serde_json::to_string(&id).unwrap(), "\"ipv4\"");
    }
}
