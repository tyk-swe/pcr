// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared bounded option framing.

use super::super::{
    error::Error,
    model::{Endianness, Format},
    wire::{PCAPNG_OPTION_END, align_to_usize, decode_u16},
};

pub(super) fn visit_options<F>(
    options: &[u8],
    endianness: Endianness,
    context: &'static str,
    mut visitor: F,
) -> Result<(), Error>
where
    F: FnMut(u16, &[u8]) -> Result<(), Error>,
{
    let mut offset = 0_usize;
    while offset < options.len() {
        if options.len() - offset < 4 {
            return Err(Error::Truncated {
                context,
                expected: offset + 4,
                actual: options.len(),
            });
        }
        let code = decode_u16(endianness, &options[offset..offset + 2])?;
        let length = usize::from(decode_u16(endianness, &options[offset + 2..offset + 4])?);
        offset += 4;
        if code == PCAPNG_OPTION_END {
            if length != 0 {
                return Err(Error::InvalidData {
                    format: Format::PcapNg,
                    reason: "end-of-options marker has a non-zero length",
                });
            }
            if options[offset..].iter().any(|byte| *byte != 0) {
                return Err(Error::InvalidData {
                    format: Format::PcapNg,
                    reason: "non-zero bytes follow the end-of-options marker",
                });
            }
            return Ok(());
        }
        let padded_length = align_to_usize(length)?;
        let end = offset
            .checked_add(padded_length)
            .ok_or(Error::InvalidData {
                format: Format::PcapNg,
                reason: "option length overflow",
            })?;
        if end > options.len() {
            return Err(Error::Truncated {
                context,
                expected: end,
                actual: options.len(),
            });
        }
        visitor(code, &options[offset..offset + length])?;
        offset = end;
    }
    Ok(())
}
