// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::io::{Read, Write};

use serde::{Deserialize, Serialize};

use super::{
    Budget, DEFAULT_MAX_TOTAL_INTERFACES, Error, Format, Interface, Limits, PcapNgOptions,
    PcapOptions, Reader, TimestampResolution, Writer,
};
use crate::error::BoundaryError;
use crate::frame::{DEFAULT_MAX_SIZE, Direction, Frame};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NormalizeOptions {
    pub max_size: usize,
    pub max_interfaces: usize,
    pub stream_limits: Limits,
}

impl Default for NormalizeOptions {
    fn default() -> Self {
        Self {
            max_size: DEFAULT_MAX_SIZE,
            max_interfaces: DEFAULT_MAX_TOTAL_INTERFACES,
            stream_limits: Limits::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizeReport {
    pub format: Format,
    pub frames_read: u64,
    pub frames_selected: u64,
    pub captured_bytes_read: u64,
    pub captured_bytes_selected: u64,
    pub interfaces: usize,
}

/// Normalizes selected frames from `reader` into a fresh `format` capture stream.
///
/// Every read frame (selected or not) is charged to `options.stream_limits` and checked
/// against declared frame check sequences. The predicate receives the one-based source
/// frame number.
pub fn normalize<R: Read, W: Write, F>(
    reader: &mut Reader<R>,
    destination: W,
    format: Format,
    options: NormalizeOptions,
    predicate: F,
) -> Result<(W, NormalizeReport), Error>
where
    F: FnMut(u64, &Frame) -> Result<bool, BoundaryError>,
{
    reader.refuse_declared_fcs()?;
    match format {
        Format::PcapNg => normalize_to_pcapng(reader, destination, options, predicate),
        Format::Pcap => normalize_to_pcap(reader, destination, options, predicate),
    }
}

fn next_selected<R: Read>(
    reader: &mut Reader<R>,
    budget: &mut Budget,
    predicate: &mut impl FnMut(u64, &Frame) -> Result<bool, BoundaryError>,
) -> Result<Option<(u64, Frame)>, Error> {
    loop {
        let next = reader.next_exact_frame()?;
        reader.refuse_declared_fcs()?;
        let Some(frame) = next else {
            return Ok(None);
        };
        budget.charge(frame.captured_length())?;
        let source_frame = budget.frames();
        if !predicate(source_frame, &frame).map_err(|source| Error::Predicate {
            number: source_frame,
            source,
        })? {
            continue;
        }
        return Ok(Some((source_frame, frame)));
    }
}

fn source_description<R: Read>(reader: &Reader<R>, source_interface: u32) -> &Interface {
    let source_index = usize::try_from(source_interface)
        .expect("reader interface IDs fit the in-memory interface table");
    reader
        .interfaces()
        .get(source_index)
        .expect("reader registers each frame interface before returning the frame")
}

fn normalize_to_pcapng<R: Read, W: Write>(
    reader: &mut Reader<R>,
    destination: W,
    options: NormalizeOptions,
    mut predicate: impl FnMut(u64, &Frame) -> Result<bool, BoundaryError>,
) -> Result<(W, NormalizeReport), Error> {
    let mut writer = Writer::pcapng_with_options(
        destination,
        PcapNgOptions {
            max_size: options.max_size,
            max_interfaces: options.max_interfaces,
            stream_limits: options.stream_limits,
            ..PcapNgOptions::default()
        },
    )?;
    let mut budget = Budget::new(options.stream_limits)?;
    let mut interface_map: BTreeMap<u32, u32> = BTreeMap::new();
    let mut frames_selected = 0_u64;
    let mut captured_bytes_selected = 0_u64;
    while let Some((_, mut frame)) = next_selected(reader, &mut budget, &mut predicate)? {
        // Classic PCAP exposes its single interface at zero; PCAPNG frame IDs are global.
        let source_interface = frame.interface.unwrap_or(0);
        let output_interface = match interface_map.get(&source_interface) {
            Some(&id) => id,
            None => {
                let description = source_description(reader, source_interface).clone();
                let id = writer.add_interface_description_with_options(description, &[])?;
                interface_map.insert(source_interface, id);
                id
            }
        };
        frame.interface = Some(output_interface);
        writer.write_frame(&frame)?;
        frames_selected = frames_selected.saturating_add(1);
        captured_bytes_selected =
            captured_bytes_selected.saturating_add(u64::from(frame.captured_length()));
    }
    writer.flush()?;
    Ok((
        writer.into_inner(),
        NormalizeReport {
            format: Format::PcapNg,
            frames_read: budget.frames(),
            frames_selected,
            captured_bytes_read: budget.captured_bytes(),
            captured_bytes_selected,
            interfaces: interface_map.len(),
        },
    ))
}

/// Classic PCAP fixes its header before the first record, so the writer opens at the first
/// selected frame, and a later conflict can leave the earlier records already written.
fn normalize_to_pcap<R: Read, W: Write>(
    reader: &mut Reader<R>,
    destination: W,
    options: NormalizeOptions,
    mut predicate: impl FnMut(u64, &Frame) -> Result<bool, BoundaryError>,
) -> Result<(W, NormalizeReport), Error> {
    let mut budget = Budget::new(options.stream_limits)?;
    let mut destination = Some(destination);
    let mut open: Option<(u32, Writer<W>)> = None;
    let mut frames_selected = 0_u64;
    let mut captured_bytes_selected = 0_u64;
    while let Some((source_frame, mut frame)) = next_selected(reader, &mut budget, &mut predicate)?
    {
        let source_interface = frame.interface.unwrap_or(0);
        if open.is_none() {
            let opened = open_classic_writer(
                destination.take().expect("the writer opens once"),
                source_description(reader, source_interface),
                options,
            )?;
            open = Some((source_interface, opened));
        }
        let Some((first_interface, writer)) = open.as_mut() else {
            unreachable!("the writer opened above");
        };
        if source_interface != *first_interface {
            return Err(Error::PcapNormalizeInterfaceConflict {
                number: source_frame,
                first_interface: *first_interface,
                first_link_type: source_description(reader, *first_interface).link_type.0,
                other_interface: source_interface,
                other_link_type: source_description(reader, source_interface).link_type.0,
            });
        }
        match frame.direction {
            None | Some(Direction::Unknown) => frame.direction = None,
            Some(_) => {
                return Err(Error::PcapNormalizeDirection {
                    number: source_frame,
                });
            }
        }
        frame.interface = None;
        writer.write_frame(&frame)?;
        frames_selected = frames_selected.saturating_add(1);
        captured_bytes_selected =
            captured_bytes_selected.saturating_add(u64::from(frame.captured_length()));
    }
    match open {
        Some((_, mut writer)) => {
            writer.flush()?;
            Ok((
                writer.into_inner(),
                NormalizeReport {
                    format: Format::Pcap,
                    frames_read: budget.frames(),
                    frames_selected,
                    captured_bytes_read: budget.captured_bytes(),
                    captured_bytes_selected,
                    interfaces: 1,
                },
            ))
        }
        None => Err(Error::EmptyPcapNormalization),
    }
}

fn open_classic_writer<W: Write>(
    destination: W,
    description: &Interface,
    options: NormalizeOptions,
) -> Result<Writer<W>, Error> {
    let timestamp_resolution = match description.timestamp_resolution {
        resolution @ (TimestampResolution::Decimal(6) | TimestampResolution::Decimal(9)) => {
            resolution
        }
        resolution => return Err(Error::PcapNormalizeTimestampResolution { resolution }),
    };
    // PCAPNG marks an unlimited snapshot with zero; classic PCAP needs a finite header value.
    let snap_len = match description.snap_len {
        0 => options.max_size,
        snap_len => usize::try_from(snap_len).unwrap_or(usize::MAX),
    };
    Writer::pcap_with_options(
        destination,
        description.link_type,
        PcapOptions {
            timestamp_resolution,
            snap_len,
            max_size: options.max_size,
            stream_limits: options.stream_limits,
            ..PcapOptions::default()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{Classified, Code, Coordinate};
    use crate::frame::LinkType;
    use bytes::Bytes;
    use std::io::Cursor;
    use std::time::{Duration, UNIX_EPOCH};

    fn pcapng_capture(
        frames: &[(u32, LinkType, Option<Direction>, TimestampResolution)],
    ) -> Vec<u8> {
        let mut writer = Writer::pcapng_with_options(Vec::new(), PcapNgOptions::default()).unwrap();
        let mut added = BTreeMap::new();
        for (idx, &(source_id, link_type, direction, timestamp_resolution)) in
            frames.iter().enumerate()
        {
            let id = *added.entry(source_id).or_insert_with(|| {
                writer
                    .add_interface_description_with_options(
                        Interface {
                            link_type,
                            snap_len: 0,
                            timestamp_resolution,
                            timestamp_offset: 0,
                        },
                        &[],
                    )
                    .unwrap()
            });
            let mut frame = Frame::new(
                Some(UNIX_EPOCH + Duration::from_secs(idx as u64 + 1)),
                link_type,
                Bytes::from_static(&[1, 2, 3, 4]),
            )
            .unwrap();
            frame.interface = Some(id);
            frame.direction = direction;
            writer.write_frame(&frame).unwrap();
        }
        writer.into_inner()
    }

    #[test]
    fn normalizes_selected_frames_to_pcapng_and_deduplicates_interfaces() {
        let input = pcapng_capture(&[
            (0, LinkType::ETHERNET, None, TimestampResolution::Decimal(6)),
            (
                1,
                LinkType::IPV4,
                Some(Direction::Inbound),
                TimestampResolution::Decimal(9),
            ),
            (1, LinkType::IPV4, None, TimestampResolution::Decimal(9)),
        ]);
        let mut reader = Reader::with_limits(Cursor::new(input), Default::default()).unwrap();
        let (out, report) = normalize(
            &mut reader,
            Vec::new(),
            Format::PcapNg,
            NormalizeOptions::default(),
            |number, _| Ok(number >= 2),
        )
        .unwrap();
        assert_eq!(report.format, Format::PcapNg);
        assert_eq!(report.frames_read, 3);
        assert_eq!(report.frames_selected, 2);
        assert_eq!(report.interfaces, 1);

        let mut check = Reader::with_limits(Cursor::new(out), Default::default()).unwrap();
        assert_eq!(check.format(), Format::PcapNg);
        let first = check.next_exact_frame().unwrap().unwrap();
        assert_eq!(first.interface, Some(0));
        assert_eq!(first.link_type, LinkType::IPV4);
        assert_eq!(first.direction, Some(Direction::Inbound));
    }

    #[test]
    fn normalizes_single_interface_to_classic_pcap_and_rejects_unrepresentable_metadata() {
        let ok_input = pcapng_capture(&[(
            0,
            LinkType::IPV4,
            Some(Direction::Unknown),
            TimestampResolution::Decimal(6),
        )]);
        let mut reader = Reader::with_limits(Cursor::new(ok_input), Default::default()).unwrap();
        let (out, report) = normalize(
            &mut reader,
            Vec::new(),
            Format::Pcap,
            NormalizeOptions::default(),
            |_, _| Ok(true),
        )
        .unwrap();
        assert_eq!(report.format, Format::Pcap);
        assert_eq!(report.frames_selected, 1);
        let mut check = Reader::with_limits(Cursor::new(out), Default::default()).unwrap();
        assert_eq!(check.format(), Format::Pcap);
        assert_eq!(check.next_exact_frame().unwrap().unwrap().direction, None);

        let empty_input =
            pcapng_capture(&[(0, LinkType::IPV4, None, TimestampResolution::Decimal(6))]);
        let mut reader = Reader::with_limits(Cursor::new(empty_input), Default::default()).unwrap();
        let err = normalize(
            &mut reader,
            Vec::new(),
            Format::Pcap,
            NormalizeOptions::default(),
            |_, _| Ok(false),
        )
        .unwrap_err();
        assert!(matches!(err, Error::EmptyPcapNormalization));
        assert_eq!(err.classification().code, Code::CliCaptureOption);

        let dir_input = pcapng_capture(&[(
            0,
            LinkType::IPV4,
            Some(Direction::Outbound),
            TimestampResolution::Decimal(6),
        )]);
        let mut reader = Reader::with_limits(Cursor::new(dir_input), Default::default()).unwrap();
        let err = normalize(
            &mut reader,
            Vec::new(),
            Format::Pcap,
            NormalizeOptions::default(),
            |_, _| Ok(true),
        )
        .unwrap_err();
        assert!(matches!(err, Error::PcapNormalizeDirection { number: 1 }));
        assert_eq!(
            err.classification().code,
            Code::PacketCaptureTransformMetadata
        );
        assert_eq!(err.context(), Some(Coordinate::SourceFrame(1)));

        let conflict_input = pcapng_capture(&[
            (0, LinkType::ETHERNET, None, TimestampResolution::Decimal(6)),
            (1, LinkType::IPV4, None, TimestampResolution::Decimal(6)),
        ]);
        let mut reader =
            Reader::with_limits(Cursor::new(conflict_input), Default::default()).unwrap();
        let err = normalize(
            &mut reader,
            Vec::new(),
            Format::Pcap,
            NormalizeOptions::default(),
            |_, _| Ok(true),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::PcapNormalizeInterfaceConflict {
                number: 2,
                first_interface: 0,
                other_interface: 1,
                ..
            }
        ));
        assert_eq!(
            err.classification().code,
            Code::PacketCaptureTransformMetadata
        );
        assert_eq!(err.context(), Some(Coordinate::SourceFrame(2)));

        let res_input =
            pcapng_capture(&[(0, LinkType::IPV4, None, TimestampResolution::Decimal(3))]);
        let mut reader = Reader::with_limits(Cursor::new(res_input), Default::default()).unwrap();
        let err = normalize(
            &mut reader,
            Vec::new(),
            Format::Pcap,
            NormalizeOptions::default(),
            |_, _| Ok(true),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::PcapNormalizeTimestampResolution {
                resolution: TimestampResolution::Decimal(3)
            }
        ));
        assert_eq!(
            err.classification().code,
            Code::PacketCaptureTransformMetadata
        );
    }
}
