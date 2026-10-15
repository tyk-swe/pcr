// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::protocol::application::dns::Error;

pub(super) fn read_u16(message: &[u8], offset: usize, field: &'static str) -> Result<u16, Error> {
    let bytes: [u8; 2] = message
        .get(offset..offset.saturating_add(2))
        .and_then(|slice| <[u8; 2]>::try_from(slice).ok())
        .ok_or(Error::TruncatedField {
            field,
            offset,
            needed: offset.saturating_add(2),
        })?;
    Ok(u16::from_be_bytes(bytes))
}

pub(super) fn read_u32(message: &[u8], offset: usize, field: &'static str) -> Result<u32, Error> {
    let bytes: [u8; 4] = message
        .get(offset..offset.saturating_add(4))
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
        .ok_or(Error::TruncatedField {
            field,
            offset,
            needed: offset.saturating_add(4),
        })?;
    Ok(u32::from_be_bytes(bytes))
}
