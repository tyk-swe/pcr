// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Lowercase hexadecimal rendering shared by machine payloads and text output.

use std::fmt;

use serde::{Serialize, Serializer};

/// Bytes rendered as contiguous lowercase hex digits.
#[derive(Clone, Copy, Debug)]
pub struct CompactHex<'a>(pub &'a [u8]);

impl fmt::Display for CompactHex<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for CompactHex<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

/// Renders `bytes` as contiguous lowercase hex digits.
#[must_use]
pub fn compact_hex(bytes: &[u8]) -> String {
    CompactHex(bytes).to_string()
}
