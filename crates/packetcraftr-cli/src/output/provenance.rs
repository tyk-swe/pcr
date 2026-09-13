// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{contract::Error, frame::Timestamp};
use packetcraftr_core::analysis::provenance::SourceSet;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Source {
    pub number: u64,
    pub timestamp: Timestamp,
}
pub fn from_source_set(value: &SourceSet) -> Result<Vec<Source>, Error> {
    value
        .frames()
        .iter()
        .map(|frame| {
            Ok(Source {
                number: frame.number,
                timestamp: Timestamp::try_from(frame.timestamp)?,
            })
        })
        .collect()
}
