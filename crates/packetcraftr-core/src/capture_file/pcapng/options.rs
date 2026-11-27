// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use crate::capture_file::{
    DEFAULT_MAX_OPTIONS_PER_BLOCK,
    error::Error,
    format::{Endianness, Format},
    header::PcapNgOption,
    wire::{
        PCAPNG_OPTION_CUSTOM_BINARY_NO_COPY, PCAPNG_OPTION_CUSTOM_UTF8_NO_COPY, PCAPNG_OPTION_END,
        align_to_usize, decode_u16,
    },
};

/// Decodes a block's option list, retaining at most `max_options` entries.
pub(super) fn parse_options(
    options: &[u8],
    endianness: Endianness,
    context: &'static str,
    max_options: usize,
) -> Result<Vec<PcapNgOption>, Error> {
    let mut parsed = Vec::new();
    visit_options(options, endianness, context, max_options, |code, value| {
        parsed.push(PcapNgOption {
            code,
            value: Bytes::copy_from_slice(value),
        });
        Ok(())
    })?;
    Ok(parsed)
}

pub(super) fn visit_options<'a>(
    options: &'a [u8],
    endianness: Endianness,
    context: &'static str,
    max_options: usize,
    mut visit: impl FnMut(u16, &'a [u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut count = 0;
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
        if count >= max_options {
            return Err(Error::OptionLimit { limit: max_options });
        }
        // `length <= padded_length`, so the value ends at or before `end`, within `options`
        let value = &options[offset..offset + length];
        visit(code, value)?;
        count += 1;
        offset = end;
    }
    Ok(())
}

pub(in crate::capture_file) fn validate_copyable_option(code: u16) -> Result<(), Error> {
    if matches!(
        code,
        PCAPNG_OPTION_CUSTOM_UTF8_NO_COPY | PCAPNG_OPTION_CUSTOM_BINARY_NO_COPY
    ) {
        return Err(Error::TransformMetadata("non-copyable PCAPNG option"));
    }
    Ok(())
}

pub(in crate::capture_file) fn validate_metadata_options(
    raw: &[u8],
    endianness: Endianness,
    name_resolution: bool,
) -> Result<(), Error> {
    let body = &raw[8..raw.len() - 4];
    let malformed = Error::TransformMetadata("malformed PCAPNG metadata block");
    let options = if name_resolution {
        let mut remaining = body;
        loop {
            let (header, tail) = remaining
                .split_at_checked(4)
                .ok_or(Error::TransformMetadata(
                    "malformed PCAPNG name resolution records",
                ))?;
            let kind = decode_u16(endianness, header)?;
            let length = decode_u16(endianness, &header[2..])?;
            if kind == 0 {
                if length != 0 {
                    return Err(malformed);
                }
                break tail;
            }
            remaining = tail.get(align_to_usize(usize::from(length))?..).ok_or(
                Error::TransformMetadata("malformed PCAPNG name resolution record"),
            )?;
        }
    } else {
        body.get(12..).ok_or(malformed)?
    };
    visit_options(
        options,
        endianness,
        "pcapng metadata options",
        DEFAULT_MAX_OPTIONS_PER_BLOCK,
        |code, _| validate_copyable_option(code),
    )
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
