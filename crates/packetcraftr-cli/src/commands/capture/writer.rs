// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use packetcraftr::capture::Source;
use packetcraftr_core::capture_file::{self, Error, Format, Writer};
use packetcraftr_core::frame::Frame;
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
/// Classic PCAP carries no interface IDs; `initialize` admits one source for it.
pub(super) fn write_frame<W: Write>(writer: &mut Writer<W>, mut frame: Frame) -> Result<(), Error> {
    if writer.format() == Format::Pcap {
        frame.interface = None;
    }
    writer.write_frame(&frame)
}
#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::frame::LinkType;
    use packetcraftr_netio::{
        capture::{Limits, Metadata, Stats},
        interface::Id,
    };
    use std::time::{Duration, UNIX_EPOCH};
    fn sources() -> Vec<Source> {
        vec![Source {
            index: 0,
            metadata: Metadata {
                interface: Id {
                    name: "fixture0".to_owned(),
                    index: 1,
                },
                link_type: LinkType::RAW,
                snap_length: 64,
                native: Default::default(),
            },
            limits: Limits {
                snap_length: 64,
                ..Default::default()
            },
            metadata_valid: true,
            ready: true,
            shutdown_confirmed: false,
            statistics_valid: true,
            statistics: Stats::default(),
            delivered_frames: 0,
            delivered_bytes: 0,
            admitted_frames: 0,
            matched_frames: 0,
            emitted_frames: 0,
            late_frames: 0,
        }]
    }
    fn engine_frame() -> Frame {
        let mut frame = Frame::new(
            UNIX_EPOCH + Duration::new(7, 123_456_789),
            LinkType::RAW,
            vec![0x45; 32],
        )
        .unwrap();
        frame.interface = Some(0);
        frame
    }
    fn round_trip(format: Format) -> Frame {
        let mut writer = initialize(
            Vec::new(),
            format,
            &sources(),
            capture_file::Limits {
                max_frames: 10,
                max_bytes: 1024,
            },
        )
        .unwrap();
        write_frame(&mut writer, engine_frame()).unwrap();
        let bytes = writer.into_inner();
        let mut reader = capture_file::Reader::new(bytes.as_slice()).unwrap();
        let frame = reader.next_frame().unwrap().expect("one frame");
        assert!(reader.next_frame().unwrap().is_none());
        frame
    }
    #[test]
    fn classic_pcap_writes_engine_frames_without_interface_ids() {
        let frame = round_trip(Format::Pcap);
        assert_eq!(frame.interface, None);
        assert_eq!(frame.bytes(), engine_frame().bytes());
        assert_eq!(frame.timestamp, engine_frame().timestamp);
    }
    #[test]
    fn pcapng_keeps_the_engine_interface_id() {
        let frame = round_trip(Format::PcapNg);
        assert_eq!(frame.interface, Some(0));
        assert_eq!(frame.bytes(), engine_frame().bytes());
        assert_eq!(frame.timestamp, engine_frame().timestamp);
    }
}
