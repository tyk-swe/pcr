// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::pcapng::validate_rewritable_packet_flags;
use super::wire::{
    PCAPNG_OPTION_END, PCAPNG_OPTION_IF_FCSLEN, PCAPNG_OPTION_IF_TSOFFSET, PCAPNG_OPTION_IF_TSRESOL,
};
use super::{
    CaptureHeader, Error, Format, Interface, Limits, MetadataBlockKind, PcapNgOption, Reader,
    RecordKind, Writer,
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
/// Map packet bytes into one PCAPNG section while retaining global interface
/// identity, times, and interface options. Source section structure, statistics,
/// packet options and other non-interface metadata are discarded. Declared FCS
/// and extended packet flags are rejected. `maximum_growth` extends snap lengths
/// and bounds each mapper result. The mapper may change bytes/lengths, not capture
/// identity. Output can be partial on failure; publish a temporary file on success.
pub fn map_frames<R: Read, W: Write, F>(
    reader: &mut Reader<R>,
    output: &mut Writer<W>,
    limits: Limits,
    maximum_growth: usize,
    mut map: F,
) -> Result<MapReport, Error>
where
    F: FnMut(u64, &Frame) -> Result<Frame, BoundaryError>,
{
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
    let mut report = MapReport::default();
    let mut endianness = reader.endianness();
    if let CaptureHeader::Pcap(header) = reader.header() {
        if header.network & 0xffff0000 != 0 {
            return Err(Error::TransformMetadata("classic link/FCS flags"));
        }
        for interface in reader.interfaces() {
            let id = add_interface(output, interface.clone(), &[], maximum_growth)?;
            if id as usize != report.interfaces {
                return Err(Error::TransformMetadata("nonempty output interface table"));
            }
            report.interfaces += 1;
        }
    }
    while let Some(record) = reader.next_record()? {
        match record.kind {
            RecordKind::Metadata(metadata) => {
                report.source_metadata_records += 1;
                match metadata {
                    MetadataBlockKind::Section(section) => endianness = section.endianness,
                    MetadataBlockKind::InterfaceDescription {
                        global_id,
                        interface,
                        options,
                        ..
                    } => {
                        if options
                            .iter()
                            .any(|option| option.code == PCAPNG_OPTION_IF_FCSLEN)
                        {
                            return Err(Error::TransformMetadata("interface FCS length"));
                        }
                        let id = add_interface(output, interface, &options, maximum_growth)?;
                        if id != global_id {
                            return Err(Error::TransformMetadata(
                                "nonempty output interface table",
                            ));
                        }
                        report.interfaces += 1;
                    }
                    _ => {}
                }
            }
            RecordKind::Packet { options, .. } => {
                validate_rewritable_packet_flags(&options, endianness, "malformed packet flags")
                    .map_err(Error::TransformMetadata)?;
                let frame = record
                    .frame
                    .ok_or(Error::TransformMetadata("packet record without frame"))?;
                (report.frames_read, report.captured_bytes_read) = limits.advance(
                    report.frames_read,
                    report.captured_bytes_read,
                    frame.captured_length(),
                )?;
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
                if changed.bytes() != frame.bytes() {
                    report.frames_changed += 1;
                }
                if changed.interface.is_none() {
                    changed.interface = Some(0);
                }
                output.write_frame(&changed)?;
                report.captured_bytes_written = report
                    .captured_bytes_written
                    .checked_add(u64::from(changed.captured_length()))
                    .ok_or(Error::StreamByteLimitExceeded {
                        actual: u64::MAX,
                        limit: limits.max_bytes,
                    })?;
            }
        }
    }
    Ok(report)
}
fn add_interface<W: Write>(
    output: &mut Writer<W>,
    mut interface: Interface,
    options: &[PcapNgOption],
    growth: usize,
) -> Result<u32, Error> {
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
    let retained: Vec<_> = options
        .iter()
        .filter(|option| {
            !matches!(
                option.code,
                PCAPNG_OPTION_END | PCAPNG_OPTION_IF_TSRESOL | PCAPNG_OPTION_IF_TSOFFSET
            )
        })
        .cloned()
        .collect();
    output.add_interface_description_with_options(interface, &retained)
}
