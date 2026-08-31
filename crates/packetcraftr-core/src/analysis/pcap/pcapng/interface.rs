// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Interface-description block parsing.

use crate::frame::LinkType;

use super::options::visit_options;
use crate::analysis::pcap::{
    error::Error,
    model::{Endianness, Format, Interface, TimestampResolution},
    wire::{
        DEFAULT_TIMESTAMP_RESOLUTION, PCAPNG_OPTION_IF_TSOFFSET, PCAPNG_OPTION_IF_TSRESOL,
        decode_i64, decode_u16, decode_u32,
    },
};

pub(in crate::analysis::pcap) fn parse_interface_description(
    body: &[u8],
    endianness: Endianness,
) -> Result<Interface, Error> {
    if body.len() < 8 {
        return Err(Error::InvalidData {
            format: Format::PcapNg,
            reason: "interface description block is shorter than 8 bytes",
        });
    }
    let link_type = LinkType(u32::from(decode_u16(endianness, body)?));
    let snap_len = decode_u32(
        endianness,
        body.get(4..).ok_or(Error::InvalidData {
            format: Format::PcapNg,
            reason: "interface description block is shorter than 8 bytes",
        })?,
    )?;
    let mut timestamp_resolution = DEFAULT_TIMESTAMP_RESOLUTION;
    let mut timestamp_offset = 0_i64;
    let mut saw_timestamp_resolution = false;
    let mut saw_timestamp_offset = false;
    let option_bytes = body.get(8..).ok_or(Error::InvalidData {
        format: Format::PcapNg,
        reason: "interface description block is shorter than 8 bytes",
    })?;
    visit_options(
        option_bytes,
        endianness,
        "pcapng interface options",
        |code, value| {
            match code {
                PCAPNG_OPTION_IF_TSRESOL => {
                    if saw_timestamp_resolution {
                        return Err(Error::InvalidData {
                            format: Format::PcapNg,
                            reason: "if_tsresol option appears more than once",
                        });
                    }
                    saw_timestamp_resolution = true;
                    let &[resolution] = value else {
                        return Err(Error::InvalidData {
                            format: Format::PcapNg,
                            reason: "if_tsresol option must contain one byte",
                        });
                    };
                    timestamp_resolution = if resolution & 0x80 == 0 {
                        TimestampResolution::Decimal(resolution)
                    } else {
                        TimestampResolution::Binary(resolution & 0x7f)
                    };
                }
                PCAPNG_OPTION_IF_TSOFFSET => {
                    if saw_timestamp_offset {
                        return Err(Error::InvalidData {
                            format: Format::PcapNg,
                            reason: "if_tsoffset option appears more than once",
                        });
                    }
                    saw_timestamp_offset = true;
                    if value.len() != 8 {
                        return Err(Error::InvalidData {
                            format: Format::PcapNg,
                            reason: "if_tsoffset option must contain eight bytes",
                        });
                    }
                    timestamp_offset = decode_i64(endianness, value)?;
                }
                _ => {}
            }
            Ok(())
        },
    )?;
    Ok(Interface {
        link_type,
        snap_len,
        timestamp_resolution,
        timestamp_offset,
    })
}
