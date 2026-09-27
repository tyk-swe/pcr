// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use packetcraftr::capture::Source;
use packetcraftr_core::capture_file::{self, Error, Format, Writer};
use std::io::Write;
pub(super) fn initialize<W: Write>(
    destination: W,
    format: Format,
    sources: &[Source],
    limits: capture_file::Limits,
) -> Result<Writer<W>, Error> {
    let maximum = sources
        .iter()
        .map(|source| source.metadata.snap_length)
        .max()
        .ok_or(Error::InvalidData {
            format,
            reason: "capture has no sources",
        })?;
    if format == Format::Pcap {
        if sources.len() != 1 {
            return Err(Error::InvalidData {
                format,
                reason: "classic PCAP cannot preserve multiple capture interfaces",
            });
        }
        return Writer::pcap_with_options(
            destination,
            sources[0].metadata.link_type,
            capture_file::PcapOptions {
                snap_len: maximum,
                max_size: maximum,
                stream_limits: limits,
                ..Default::default()
            },
        );
    }
    let maximum = maximum
        .checked_add(47)
        .ok_or(Error::InvalidData {
            format,
            reason: "snapshot cannot fit capture block framing",
        })?
        .max(8192);
    let mut writer = Writer::pcapng_with_options(
        destination,
        capture_file::PcapNgOptions {
            max_size: maximum,
            max_interfaces: sources.len(),
            stream_limits: limits,
            ..Default::default()
        },
    )?;
    for source in sources {
        let description = capture_file::Interface {
            link_type: source.metadata.link_type,
            snap_len: u32::try_from(source.metadata.snap_length).map_err(|_| {
                Error::InvalidData {
                    format,
                    reason: "snapshot exceeds capture wire range",
                }
            })?,
            timestamp_resolution: capture_file::TimestampResolution::Decimal(9),
            timestamp_offset: 0,
        };
        let id = writer.add_interface_description_with_options(
            description,
            &[capture_file::PcapNgOption {
                code: 2,
                value: bytes::Bytes::copy_from_slice(source.metadata.interface.name.as_bytes()),
            }],
        )?;
        if id as usize != source.index {
            return Err(Error::InvalidData {
                format,
                reason: "capture source IDs are not contiguous",
            });
        }
    }
    Ok(writer)
}
