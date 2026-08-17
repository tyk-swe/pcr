// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::error::Error;
use super::types::{PACKET_DOCUMENT_SCHEMA_V1, Packet};

impl Packet {
    pub fn validate_schema(&self) -> Result<(), Error> {
        if self.schema != PACKET_DOCUMENT_SCHEMA_V1 {
            return Err(Error::Schema {
                actual: self.schema.clone(),
                expected: PACKET_DOCUMENT_SCHEMA_V1,
            });
        }
        Ok(())
    }
}
