// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use crate::capture_file::{
    error::Error,
    format::{Endianness, Format},
    header::PcapNgOption,
    wire::{PCAPNG_OPTION_END, align_to_usize, decode_u16},
};

/// Decodes a block's option list, retaining at most `max_options` entries.
pub(super) fn parse_options(
    options: &[u8],
    endianness: Endianness,
    context: &'static str,
    max_options: usize,
) -> Result<Vec<PcapNgOption>, Error> {
    let mut parsed = Vec::new();
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
            // the header read succeeded, so `offset <= options.len()`
            if options[offset..].iter().any(|byte| *byte != 0) {
                return Err(Error::InvalidData {
                    format: Format::PcapNg,
                    reason: "non-zero bytes follow the end-of-options marker",
                });
            }
            return Ok(parsed);
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
        if parsed.len() >= max_options {
            return Err(Error::OptionLimit { limit: max_options });
        }
        // `length <= padded_length`, so the value ends at or before `end`, within `options`
        let value = &options[offset..offset + length];
        parsed.push(PcapNgOption {
            code,
            value: Bytes::copy_from_slice(value),
        });
        offset = end;
    }
    Ok(parsed)
}

pub(super) fn unique_option<'a>(
    options: &'a [PcapNgOption],
    code: u16,
    duplicate: &'static str,
) -> Result<Option<&'a [u8]>, Error> {
    let mut matching = options.iter().filter(|option| option.code == code);
    let first = matching.next();
    if matching.next().is_some() {
        return Err(Error::InvalidData {
            format: Format::PcapNg,
            reason: duplicate,
        });
    }
    Ok(first.map(|option| option.value.as_ref()))
}
