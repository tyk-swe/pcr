// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::codec::EncodeContext;

use super::errors::invalid;

pub(crate) fn payload_without_padding<'a>(
    name: &'static str,
    payload: &'a [u8],
    context: &EncodeContext<'_>,
) -> Result<&'a [u8], crate::codec::Error> {
    let trailing = context
        .trailing_padding
        .ok_or_else(|| invalid(name, "trailing padding length overflow"))?;
    let covered = payload
        .len()
        .checked_sub(trailing)
        .ok_or_else(|| invalid(name, "trailing padding exceeds encoded payload"))?;
    Ok(&payload[..covered])
}
