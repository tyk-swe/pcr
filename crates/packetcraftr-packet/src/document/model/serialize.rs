// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::error::DocumentError;
use super::types::PacketDocument;

impl PacketDocument {
    pub fn to_json_pretty(&self) -> Result<String, DocumentError> {
        serde_json::to_string_pretty(self).map_err(|source| DocumentError::Serialize {
            format: "JSON",
            message: source.to_string(),
        })
    }

    pub fn to_yaml(&self) -> Result<String, DocumentError> {
        noyalib::to_string(self).map_err(|source| DocumentError::Serialize {
            format: "YAML",
            message: source.to_string(),
        })
    }
}
