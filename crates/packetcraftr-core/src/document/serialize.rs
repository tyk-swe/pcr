// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::error::Error;
use super::types::Packet;

impl Packet {
    pub fn to_json_pretty(&self) -> Result<String, Error> {
        serde_json::to_string_pretty(self).map_err(|source| Error::Serialize {
            format: "JSON",
            message: source.to_string(),
        })
    }

    pub fn to_yaml(&self) -> Result<String, Error> {
        noyalib::to_string(self).map_err(|source| Error::Serialize {
            format: "YAML",
            message: source.to_string(),
        })
    }
}
