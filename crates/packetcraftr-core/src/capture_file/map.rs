// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::pcapng::{
    validate_copyable_option, validate_metadata_options, validate_rewritable_packet_flags,
};
use super::wire::{
    PCAPNG_CUSTOM_BLOCK, PCAPNG_OPTION_COMMENT, PCAPNG_OPTION_CUSTOM_BINARY,
    PCAPNG_OPTION_CUSTOM_UTF8, PCAPNG_OPTION_END, PCAPNG_OPTION_EPB_FLAGS, PCAPNG_OPTION_EPB_HASH,
    PCAPNG_OPTION_IF_RXSPEED, PCAPNG_OPTION_IF_SPEED, PCAPNG_OPTION_IF_TSOFFSET,
    PCAPNG_OPTION_IF_TSRESOL, PCAPNG_OPTION_IF_TXSPEED,
};
use super::{
    Budget, CaptureHeader, DEFAULT_MAX_OPTIONS_PER_BLOCK, Endianness, Error, Format, Interface,
    Limits, MetadataBlockKind, PacketBlockKind, PcapNgOption, PcapNgOptions, Reader, RecordKind,
    Writer,
};
use crate::{error::BoundaryError, frame::Frame};
use std::io::{Read, Write};
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct MapReport {
    pub frames_read: u64,
    pub frames_changed: u64,
    pub captured_bytes_read: u64,
    pub captured_bytes_written: u64,
    pub interfaces: usize,
    pub source_metadata_records: u64,
}
/// Output can be partial on failure; publish a temporary file on success.
pub fn map_frames<R: Read, W: Write, F>(
    reader: &mut Reader<R>,
    output: &mut Writer<W>,
    limits: Limits,
    maximum_growth: usize,
    map: F,
) -> Result<MapReport, Error>
where
    F: FnMut(u64, &Frame) -> Result<Frame, BoundaryError>,
{
    map_records(reader, output, limits, maximum_growth, false, map)
}

/// Rewrites a fresh capture reader to PCAPNG, preserving source section byte order and metadata.
/// The caller can stage the destination to publish it only on success.
pub fn map_frames_preserving_metadata<R: Read, W: Write, F>(
    reader: &mut Reader<R>,
    destination: W,
    options: PcapNgOptions,
    maximum_growth: usize,
    map: F,
) -> Result<(W, MapReport), Error>
where
    F: FnMut(u64, &Frame) -> Result<Frame, BoundaryError>,
{
    let section = match reader.header() {
        CaptureHeader::PcapNg(section) => {
            validate_copyable_options(&section.options)?;
            Some(section)
        }
        CaptureHeader::Pcap(_) => None,
    };
    let mut output = Writer::pcapng_with_section(destination, options, section)?;
    let report = map_records(
        reader,
        &mut output,
        options.stream_limits,
        maximum_growth,
        true,
        map,
    )?;
    Ok((output.into_inner(), report))
}

fn map_records<R: Read, W: Write, F>(
    reader: &mut Reader<R>,
    output: &mut Writer<W>,
    limits: Limits,
    maximum_growth: usize,
    preserve: bool,
    mut map: F,
) -> Result<MapReport, Error>
where
    F: FnMut(u64, &Frame) -> Result<Frame, BoundaryError>,
{
    let mut budget = Budget::new(limits)?;
    if output.format() != Format::PcapNg {
        return Err(Error::WrongWriterFormat {
            expected: Format::PcapNg,
            actual: output.format(),
        });
    }
    if maximum_growth > 256 {
        return Err(Error::TransformMetadata(
            "more than 256 growth bytes per frame",
        ));
    }
    let starting_bytes = output.captured_bytes_written();
    let mut report = MapReport::default();
    let mut endianness = reader.endianness();
    reader.refuse_declared_fcs()?;
    if matches!(reader.header(), CaptureHeader::Pcap(_)) {
        for interface in reader.interfaces() {
            let id = add_interface(output, interface.clone(), &[], maximum_growth, endianness)?;
            if id as usize != report.interfaces {
                return Err(Error::TransformMetadata("nonempty output interface table"));
            }
            report.interfaces += 1;
        }
    }
    while let Some(record) = reader.next_record()? {
        let raw = &record.raw;
        match record.kind {
            RecordKind::Metadata(metadata) => {
                report.source_metadata_records += 1;
                match metadata {
                    MetadataBlockKind::Section(section) => {
                        endianness = section.endianness;
                        if preserve {
                            validate_copyable_options(&section.options)?;
                            output.start_section_with(Some(&section))?;
                        } else {
                            output.start_section()?;
                        }
                    }
                    MetadataBlockKind::InterfaceDescription {
                        global_id,
                        interface,
                        options,
                        ..
                    } => {
                        reader.refuse_declared_fcs()?;
                        let id = if preserve {
                            validate_copyable_options(&options)?;
                            output.copy_interface_block(
                                grow_interface(interface, maximum_growth)?,
                                raw,
                            )?
                        } else {
                            add_interface(output, interface, &options, maximum_growth, endianness)?
                        };
                        if id != global_id {
                            return Err(Error::TransformMetadata(
                                "nonempty output interface table",
                            ));
                        }
                        report.interfaces += 1;
                    }
                    other if preserve => match other {
                        MetadataBlockKind::NameResolution { .. }
                        | MetadataBlockKind::InterfaceStatistics { .. } => {
                            validate_metadata_options(
                                raw,
                                endianness,
                                matches!(other, MetadataBlockKind::NameResolution { .. }),
                            )?;
                            output.copy_metadata_block(raw)?;
                        }
                        MetadataBlockKind::Custom {
                            block_type: PCAPNG_CUSTOM_BLOCK,
                            ..
                        } => {
                            if raw.len() < 16 {
                                return Err(Error::TransformMetadata(
                                    "malformed PCAPNG custom block",
                                ));
                            }
                            output.copy_metadata_block(raw)?;
                        }
                        _ => return Err(Error::TransformMetadata("unsupported PCAPNG block")),
                    },
                    _ => {}
                }
            }
            RecordKind::Packet { block, options, .. } => {
                validate_rewritable_packet_flags(&options, endianness, "malformed packet flags")
                    .map_err(Error::TransformMetadata)?;
                let frame = record
                    .frame
                    .ok_or(Error::TransformMetadata("packet record without frame"))?;
                budget.charge(frame.captured_length())?;
                (report.frames_read, report.captured_bytes_read) =
                    (budget.frames(), budget.captured_bytes());
                let mut changed =
                    map(report.frames_read, &frame).map_err(|source| Error::Transform {
                        number: report.frames_read,
                        source,
                    })?;
                if changed.timestamp != frame.timestamp
                    || changed.interface != frame.interface
                    || changed.link_type != frame.link_type
                    || changed.direction != frame.direction
                {
                    return Err(Error::TransformIdentity {
                        number: report.frames_read,
                    });
                }
                if changed.bytes().len() > frame.bytes().len().saturating_add(maximum_growth) {
                    return Err(Error::TransformMetadata(
                        "mapper exceeded declared frame growth",
                    ));
                }
                let was_changed = changed != frame;
                if was_changed {
                    report.frames_changed += 1;
                }
                if changed.interface.is_none() {
                    changed.interface = Some(0);
                }
                if preserve && block != PacketBlockKind::Classic {
                    validate_packet_options(block, &options, changed.bytes() != frame.bytes())?;
                    if block == PacketBlockKind::Simple {
                        output.write_simple_frame(&changed)?;
                    } else {
                        output.write_mapped_frame(&changed, &frame, raw, was_changed)?;
                    }
                } else {
                    output.write_frame(&changed)?;
                }
            }
        }
    }
    report.captured_bytes_written = output.captured_bytes_written() - starting_bytes;
    Ok(report)
}
fn validate_copyable_options(options: &[PcapNgOption]) -> Result<(), Error> {
    if options.len() > DEFAULT_MAX_OPTIONS_PER_BLOCK {
        return Err(Error::OptionLimit {
            limit: DEFAULT_MAX_OPTIONS_PER_BLOCK,
        });
    }
    options
        .iter()
        .try_for_each(|option| validate_copyable_option(option.code))
}

fn validate_packet_options(
    block: PacketBlockKind,
    options: &[PcapNgOption],
    changed: bool,
) -> Result<(), Error> {
    validate_copyable_options(options)?;
    if !changed {
        return Ok(());
    }
    for option in options {
        match option.code {
            PCAPNG_OPTION_COMMENT
            | PCAPNG_OPTION_EPB_FLAGS
            | PCAPNG_OPTION_CUSTOM_UTF8
            | PCAPNG_OPTION_CUSTOM_BINARY => {}
            PCAPNG_OPTION_EPB_HASH => {
                return Err(Error::TransformMetadata("hash of an edited packet"));
            }
            // These Enhanced Packet Block options describe capture provenance.
            4..=8 if block == PacketBlockKind::Enhanced => {}
            _ => {
                return Err(Error::TransformMetadata(
                    "unknown option on an edited packet",
                ));
            }
        }
    }
    Ok(())
}

fn grow_interface(mut interface: Interface, growth: usize) -> Result<Interface, Error> {
    if interface.snap_len != 0 {
        interface.snap_len =
            interface
                .snap_len
                .checked_add(growth as u32)
                .ok_or(Error::InvalidData {
                    format: Format::PcapNg,
                    reason: "rewritten interface snapshot length overflows",
                })?;
    }
    Ok(interface)
}

fn add_interface<W: Write>(
    output: &mut Writer<W>,
    interface: Interface,
    options: &[PcapNgOption],
    growth: usize,
    source_endianness: Endianness,
) -> Result<u32, Error> {
    let interface = grow_interface(interface, growth)?;
    let retained = options
        .iter()
        .filter(|option| {
            !matches!(
                option.code,
                PCAPNG_OPTION_END | PCAPNG_OPTION_IF_TSRESOL | PCAPNG_OPTION_IF_TSOFFSET
            )
        })
        .map(|option| rewrite_interface_option(option, source_endianness, output.endianness()))
        .collect::<Result<Vec<_>, _>>()?;
    output.add_interface_description_with_options(interface, &retained)
}

fn rewrite_interface_option(
    option: &PcapNgOption,
    source: Endianness,
    target: Endianness,
) -> Result<PcapNgOption, Error> {
    if source == target
        || !matches!(
            option.code,
            PCAPNG_OPTION_IF_SPEED | PCAPNG_OPTION_IF_TXSPEED | PCAPNG_OPTION_IF_RXSPEED
        )
    {
        return Ok(option.clone());
    }
    let value: [u8; 8] = option
        .value
        .as_ref()
        .try_into()
        .map_err(|_| Error::TransformMetadata("malformed interface speed"))?;
    Ok(PcapNgOption {
        code: option.code,
        value: value.into_iter().rev().collect::<Vec<_>>().into(),
    })
}
