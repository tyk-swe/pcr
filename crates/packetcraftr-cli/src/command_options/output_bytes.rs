// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;
use packetcraftr_core::error::Kind;

#[derive(Clone, Copy, Debug)]
pub(crate) struct OutputBytes(usize);

impl OutputBytes {
    pub(crate) const MAX: usize = 256 * 1024 * 1024;

    pub(crate) fn new(value: usize, option: &'static str) -> Result<Self, CliError> {
        if !(1..=Self::MAX).contains(&value) {
            return Err(CliError::new(
                Kind::Usage,
                format!("{option} must be in 1..={}", Self::MAX),
            ));
        }
        Ok(Self(value))
    }

    pub(crate) const fn get(self) -> usize {
        self.0
    }
}
