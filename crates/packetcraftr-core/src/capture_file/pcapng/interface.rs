// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::frame::LinkType;

use super::options::{parse_options, unique_option};
use crate::capture_file::{
    error::Error,
    format::{Endianness, Format, TimestampResolution},
    header::{Interface, PcapNgOption},
    wire::{
        DEFAULT_TIMESTAMP_RESOLUTION, PCAPNG_OPTION_IF_TSOFFSET, PCAPNG_OPTION_IF_TSRESOL,
        decode_i64, decode_u16, decode_u32,
    },
};

pub(in crate::capture_file) fn parse_interface_description(
    body: &[u8],
    endianness: Endianness,
    max_options: usize,
) -> Result<(Interface, Vec<PcapNgOption>), Error> {
    if body.len() < 8 {
        return Err(Error::InvalidData {
            format: Format::PcapNg,
            reason: "interface description block is shorter than 8 bytes",
        });
    }
    let link_type = LinkType(u32::from(decode_u16(endianness, body)?));
    // the length guard leaves at least eight bytes
    let snap_len = decode_u32(endianness, &body[4..8])?;
    let options = parse_options(
        &body[8..],
        endianness,
        "pcapng interface options",
        max_options,
    )?;
    let timestamp_resolution = match unique_option(
        &options,
        PCAPNG_OPTION_IF_TSRESOL,
        "if_tsresol option appears more than once",
    )? {
        None => DEFAULT_TIMESTAMP_RESOLUTION,
        Some(&[tsresol]) => TimestampResolution::from_tsresol(tsresol),
        Some(_) => {
            return Err(Error::InvalidData {
                format: Format::PcapNg,
                reason: "if_tsresol option must contain one byte",
            });
        }
    };
    let timestamp_offset = match unique_option(
        &options,
        PCAPNG_OPTION_IF_TSOFFSET,
        "if_tsoffset option appears more than once",
    )? {
        None => 0,
        Some(value) if value.len() == 8 => decode_i64(endianness, value)?,
        Some(_) => {
            return Err(Error::InvalidData {
                format: Format::PcapNg,
                reason: "if_tsoffset option must contain eight bytes",
            });
        }
    };
    let interface = Interface {
        link_type,
        snap_len,
        timestamp_resolution,
        timestamp_offset,
    };
    Ok((interface, options))
}
