// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(crate) mod huffman;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IntegerError {
    Truncated,
    Overflow,
}

pub(crate) fn integer(input: &[u8], pos: &mut usize, prefix: u32) -> Result<u64, IntegerError> {
    let first = *input.get(*pos).ok_or(IntegerError::Truncated)?;
    *pos += 1;
    let mask = (1u64 << prefix) - 1;
    let mut value = u64::from(first) & mask;
    if value < mask {
        return Ok(value);
    }
    let mut shift = 0u32;
    loop {
        let byte = *input.get(*pos).ok_or(IntegerError::Truncated)?;
        *pos += 1;
        let digit = u64::from(byte & 0x7f);
        if shift >= 64 || digit > (u64::MAX >> shift) {
            return Err(IntegerError::Overflow);
        }
        value = value
            .checked_add(digit << shift)
            .ok_or(IntegerError::Overflow)?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}
