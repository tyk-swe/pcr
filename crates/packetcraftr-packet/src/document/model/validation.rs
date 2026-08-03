// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::error::DocumentError;
use super::types::{PACKET_DOCUMENT_SCHEMA_V1, PacketDocument};

impl PacketDocument {
    pub fn validate_schema(&self) -> Result<(), DocumentError> {
        if self.schema != PACKET_DOCUMENT_SCHEMA_V1 {
            return Err(DocumentError::Schema {
                actual: self.schema.clone(),
                expected: PACKET_DOCUMENT_SCHEMA_V1,
            });
        }
        Ok(())
    }
}
