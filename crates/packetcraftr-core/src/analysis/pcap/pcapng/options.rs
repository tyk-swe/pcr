// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared bounded option framing.

use bytes::Bytes;

use super::super::{
    error::Error,
    model::{Endianness, Format, PcapNgOption},
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
        let header_end = offset.checked_add(4).ok_or(Error::InvalidData {
            format: Format::PcapNg,
            reason: "option length overflow",
        })?;
        let Some(header) = options
            .get(offset..header_end)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        else {
            return Err(Error::Truncated {
                context,
                expected: header_end,
                actual: options.len(),
            });
        };
        let code = decode_u16(endianness, &header)?;
        let length = usize::from(decode_u16(endianness, &header[2..])?);
        offset = header_end;
        if code == PCAPNG_OPTION_END {
            if length != 0 {
                return Err(Error::InvalidData {
                    format: Format::PcapNg,
                    reason: "end-of-options marker has a non-zero length",
                });
            }
            if options
                .get(offset..)
                .is_some_and(|trailing| trailing.iter().any(|byte| *byte != 0))
            {
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
        let value_end = offset.checked_add(length).ok_or(Error::InvalidData {
            format: Format::PcapNg,
            reason: "option length overflow",
        })?;
        let value = options.get(offset..value_end).ok_or(Error::Truncated {
            context,
            expected: value_end,
            actual: options.len(),
        })?;
        visitor(code, value)?;
        offset = end;
    }
    Ok(())
}

pub(super) fn parse_options(
    options: &[u8],
    endianness: Endianness,
    context: &'static str,
) -> Result<Vec<PcapNgOption>, Error> {
    let mut parsed = Vec::new();
    visit_options(options, endianness, context, |code, value| {
        parsed.push(PcapNgOption {
            code,
            value: Bytes::copy_from_slice(value),
        });
        Ok(())
    })?;
    Ok(parsed)
}
