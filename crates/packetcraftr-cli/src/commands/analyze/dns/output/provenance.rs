// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output::contract::Error;

use crate::output::frame::Timestamp;
use packetcraftr_core::analysis::provenance::SourceFrame;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(crate) struct Source {
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
