// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{contract::Error, frame::Timestamp};
use packetcraftr_core::analysis::provenance::SourceFrame;
use serde::Serialize;

/// One capture frame a reconstructed record drew bytes from.
#[derive(Debug, Serialize)]
pub struct Source {
    pub number: u64,
    pub timestamp: Timestamp,
}

impl TryFrom<&SourceFrame> for Source {
    type Error = Error;

    fn try_from(frame: &SourceFrame) -> Result<Self, Error> {
        Ok(Self {
            number: frame.number,
            timestamp: Timestamp::try_from(frame.timestamp)?,
        })
    }
}
