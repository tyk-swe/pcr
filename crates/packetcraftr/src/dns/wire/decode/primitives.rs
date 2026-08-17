// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Fixed-width bounded reads used by DNS decoding stages.

pub(super) fn read_u16(
    message: &[u8],
    offset: usize,
    field: &'static str,
) -> Result<u16, super::super::super::error::WireError> {
    let bytes = message
        .get(offset..offset.saturating_add(2))
        .ok_or(super::super::super::error::WireError::TruncatedField { field, offset })?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

pub(super) fn read_u32(
    message: &[u8],
    offset: usize,
    field: &'static str,
) -> Result<u32, super::super::super::error::WireError> {
    let bytes = message
        .get(offset..offset.saturating_add(4))
        .ok_or(super::super::super::error::WireError::TruncatedField { field, offset })?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}
