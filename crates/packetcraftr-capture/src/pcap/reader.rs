// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Read;

use crate::{Frame, LinkType};

use super::classic::{read_next_pcap_frame, read_pcap_header};
use super::models::{
    CaptureMetadata, CommentScope, Endianness, Error, Format, Interface, ReaderOptions,
    TimestampPrecision, TimestampResolution,
};
use super::pcapng::{
    parse_comments, parse_enhanced_packet, parse_interface_description, parse_interface_statistics,
    parse_name_resolution, parse_obsolete_packet, parse_simple_packet, read_pcapng_block_header,
    read_section_header_after_type, read_section_header_with_length, validate_pcapng_block_length,
};
use super::wire::{
    PCAPNG_ENHANCED_PACKET_BLOCK, PCAPNG_INTERFACE_DESCRIPTION_BLOCK,
    PCAPNG_INTERFACE_STATISTICS_BLOCK, PCAPNG_NAME_RESOLUTION_BLOCK, PCAPNG_PACKET_BLOCK,
    PCAPNG_SECTION_HEADER, PCAPNG_SIMPLE_PACKET_BLOCK, decode_u32, read_exact_or_eof,
    read_exact_vec,
};

pub(super) enum ReaderState {
    Pcap {
        endianness: Endianness,
        precision: TimestampPrecision,
        snap_len: u32,
        link_type: LinkType,
    },
    PcapNg {
        endianness: Endianness,
        interfaces: Vec<Interface>,
        interface_base: u32,
        remaining_in_section: Option<u64>,
    },
}

/// A streaming capture reader over any [`Read`] implementation.
///
/// Construction consumes only the container header.  Each call to
/// [`next_frame`](Self::next_frame) then reads at most one packet plus any
/// intervening metadata blocks.
pub struct Reader<R> {
    inner: R,
    state: ReaderState,
    interfaces: Vec<Interface>,
    max_size: usize,
    max_interfaces: usize,
    pub(super) max_total_interfaces: usize,
    max_metadata_blocks_per_frame: usize,
    max_metadata_records: usize,
    metadata: CaptureMetadata,
    frames_read: u64,
    scratch: Vec<u8>,
    finished: bool,
}

impl<R: Read> Reader<R> {
    /// Opens a capture with the default resource limits.
    pub fn new(inner: R) -> Result<Self, Error> {
        Self::with_options(inner, ReaderOptions::default())
    }

    /// Opens a capture with explicit resource limits.
    pub fn with_options(mut inner: R, options: ReaderOptions) -> Result<Self, Error> {
        let ReaderOptions {
            max_size,
            max_interfaces_per_section: max_interfaces,
            max_total_interfaces,
            max_metadata_blocks_per_frame,
            max_metadata_records,
        } = options;
        let mut scratch = Vec::new();
        let mut section_comments = Vec::new();
        let mut magic = [0_u8; 4];
        if !read_exact_or_eof(&mut inner, &mut magic, "capture magic")? {
            return Err(Error::EmptyInput);
        }

        let state = match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => read_pcap_header(
                &mut inner,
                Endianness::Little,
                TimestampPrecision::Microseconds,
            )?,
            [0xa1, 0xb2, 0xc3, 0xd4] => read_pcap_header(
                &mut inner,
                Endianness::Big,
                TimestampPrecision::Microseconds,
            )?,
            [0x4d, 0x3c, 0xb2, 0xa1] => read_pcap_header(
                &mut inner,
                Endianness::Little,
                TimestampPrecision::Nanoseconds,
            )?,
            [0xa1, 0xb2, 0x3c, 0x4d] => {
                read_pcap_header(&mut inner, Endianness::Big, TimestampPrecision::Nanoseconds)?
            }
            PCAPNG_SECTION_HEADER => {
                let header = read_section_header_after_type(&mut inner, max_size, &mut scratch)?;
                section_comments = header.comments;
                ReaderState::PcapNg {
                    endianness: header.endianness,
                    interfaces: Vec::new(),
                    interface_base: 0,
                    remaining_in_section: header.length,
                }
            }
            unknown_magic => {
                return Err(Error::UnrecognizedFormat {
                    magic: unknown_magic,
                });
            }
        };

        let interfaces = match &state {
            ReaderState::Pcap {
                precision,
                snap_len,
                link_type,
                ..
            } => vec![Interface {
                link_type: *link_type,
                snap_len: *snap_len,
                timestamp_resolution: match precision {
                    TimestampPrecision::Microseconds => TimestampResolution::Decimal(6),
                    TimestampPrecision::Nanoseconds => TimestampResolution::Decimal(9),
                },
                timestamp_offset: 0,
            }],
            ReaderState::PcapNg { .. } => Vec::new(),
        };
        if interfaces.len() > max_total_interfaces {
            return Err(Error::TotalInterfaceLimit {
                limit: max_total_interfaces,
            });
        }

        let mut reader = Self {
            inner,
            state,
            interfaces,
            max_size,
            max_interfaces,
            max_total_interfaces,
            max_metadata_blocks_per_frame,
            max_metadata_records,
            metadata: CaptureMetadata::default(),
            frames_read: 0,
            scratch,
            finished: false,
        };
        // Routed through the same retention path as every later record, so the
        // opening section header cannot place more comments in memory than
        // `max_metadata_records` allows.
        reader.retain_metadata(section_comments, |metadata| &mut metadata.comments);
        Ok(reader)
    }

    /// Returns the detected capture format.
    pub fn format(&self) -> Format {
        match self.state {
            ReaderState::Pcap { .. } => Format::Pcap,
            ReaderState::PcapNg { .. } => Format::PcapNg,
        }
    }

    /// Returns the capture byte order.
    pub fn endianness(&self) -> Endianness {
        match self.state {
            ReaderState::Pcap { endianness, .. } | ReaderState::PcapNg { endianness, .. } => {
                endianness
            }
        }
    }

    /// Returns the configured packet/block limit.
    pub fn size_limit(&self) -> usize {
        self.max_size
    }

    /// Interface metadata parsed so far.
    ///
    /// Classic PCAP exposes its single global interface immediately. PCAPNG
    /// descriptions are appended while [`next_frame`](Self::next_frame)
    /// advances the stream, before any frame that references them is returned.
    pub fn interfaces(&self) -> &[Interface] {
        &self.interfaces
    }

    /// Non-frame metadata parsed so far.
    ///
    /// Comments, name-resolution records, and interface statistics accumulate
    /// while [`next_frame`](Self::next_frame) advances the stream, bounded by
    /// [`ReaderOptions::max_metadata_records`].
    pub fn metadata(&self) -> &CaptureMetadata {
        &self.metadata
    }

    /// Retains one metadata record unless the configured bound is reached.
    fn retain_metadata<T>(
        &mut self,
        records: Vec<T>,
        select: fn(&mut CaptureMetadata) -> &mut Vec<T>,
    ) {
        for record in records {
            let retained = self.metadata.comments.len()
                + self.metadata.name_records.len()
                + self.metadata.interface_statistics.len();
            if retained >= self.max_metadata_records {
                self.metadata.dropped = self.metadata.dropped.saturating_add(1);
                continue;
            }
            select(&mut self.metadata).push(record);
        }
    }

    /// Reads the next frame, or `None` after a clean end of file.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, Error> {
        if self.finished {
            return Ok(None);
        }

        let result = match &mut self.state {
            ReaderState::Pcap {
                endianness,
                precision,
                snap_len,
                link_type,
            } => read_next_pcap_frame(
                &mut self.inner,
                *endianness,
                *precision,
                *snap_len,
                *link_type,
                self.max_size,
            ),
            ReaderState::PcapNg { .. } => self.next_pcapng_frame(),
        };

        match result {
            Ok(frame) => {
                if frame.is_none() {
                    self.finished = true;
                }
                Ok(frame)
            }
            Err(error) => {
                self.finished = true;
                Err(error)
            }
        }
    }

    fn next_pcapng_frame(&mut self) -> Result<Option<Frame>, Error> {
        let mut metadata_blocks = 0usize;
        loop {
            let (section_endianness, section_interface_base, remaining_in_section) =
                match &self.state {
                    ReaderState::PcapNg {
                        endianness,
                        interface_base,
                        remaining_in_section,
                        ..
                    } => (*endianness, *interface_base, *remaining_in_section),
                    ReaderState::Pcap { .. } => unreachable!("state checked by caller"),
                };

            if let Some(remaining) = remaining_in_section
                && remaining != 0
                && remaining < 12
            {
                return Err(Error::SectionRemainderTooSmall { remaining });
            }
            let Some(raw_header) = read_pcapng_block_header(&mut self.inner)? else {
                if let Some(remaining) = remaining_in_section.filter(|remaining| *remaining != 0) {
                    return Err(Error::SectionEndedEarly { remaining });
                }
                return Ok(None);
            };

            if raw_header[..4] == PCAPNG_SECTION_HEADER {
                if let Some(remaining) = remaining_in_section.filter(|remaining| *remaining != 0) {
                    return Err(Error::SectionHeaderBeforeBoundary { remaining });
                }
                metadata_blocks = metadata_blocks.saturating_add(1);
                if metadata_blocks > self.max_metadata_blocks_per_frame {
                    return Err(Error::MetadataBlockLimit {
                        limit: self.max_metadata_blocks_per_frame,
                    });
                }
                let header = read_section_header_with_length(
                    &mut self.inner,
                    raw_header[4..8].try_into().expect("four-byte slice"),
                    self.max_size,
                    &mut self.scratch,
                )?;
                self.retain_metadata(header.comments, |metadata| &mut metadata.comments);
                match &mut self.state {
                    ReaderState::PcapNg {
                        endianness,
                        interfaces,
                        interface_base,
                        remaining_in_section,
                    } => {
                        *interface_base = interface_base
                            .checked_add(u32::try_from(interfaces.len()).map_err(|_| {
                                Error::InterfaceLimit {
                                    limit: self.max_interfaces,
                                }
                            })?)
                            .ok_or(Error::InterfaceLimit {
                                limit: self.max_interfaces,
                            })?;
                        *endianness = header.endianness;
                        interfaces.clear();
                        *remaining_in_section = header.length;
                    }
                    ReaderState::Pcap { .. } => unreachable!("state checked by caller"),
                }
                continue;
            }

            let block_type = decode_u32(section_endianness, &raw_header[..4]);
            let block_length = decode_u32(section_endianness, &raw_header[4..8]);
            validate_pcapng_block_length(block_length, self.max_size)?;
            if let Some(remaining) = remaining_in_section
                && u64::from(block_length) > remaining
            {
                return Err(Error::BlockCrossesSectionBoundary {
                    block_length,
                    remaining,
                });
            }
            let remaining =
                usize::try_from(block_length).map_err(|_| Error::InvalidBlockLength {
                    length: block_length,
                })? - 8;
            read_exact_vec(
                &mut self.inner,
                &mut self.scratch,
                remaining,
                "pcapng block",
            )?;

            let body_length = self.scratch.len() - 4;
            let trailing_length = decode_u32(section_endianness, &self.scratch[body_length..]);
            if trailing_length != block_length {
                return Err(Error::BlockLengthMismatch {
                    leading: block_length,
                    trailing: trailing_length,
                });
            }
            let body = &self.scratch[..body_length];

            if let ReaderState::PcapNg {
                remaining_in_section: Some(remaining),
                ..
            } = &mut self.state
            {
                *remaining -= u64::from(block_length);
            }

            if !matches!(
                block_type,
                PCAPNG_ENHANCED_PACKET_BLOCK | PCAPNG_PACKET_BLOCK | PCAPNG_SIMPLE_PACKET_BLOCK
            ) {
                metadata_blocks = metadata_blocks.saturating_add(1);
                if metadata_blocks > self.max_metadata_blocks_per_frame {
                    return Err(Error::MetadataBlockLimit {
                        limit: self.max_metadata_blocks_per_frame,
                    });
                }
            }

            match block_type {
                PCAPNG_INTERFACE_DESCRIPTION_BLOCK => {
                    let description = parse_interface_description(body, section_endianness)?;
                    let interface = u32::try_from(self.interfaces.len()).unwrap_or(u32::MAX);
                    let comments = parse_comments(
                        &body[8..],
                        section_endianness,
                        "pcapng interface options",
                        CommentScope::Interface { interface },
                    )?;
                    self.retain_metadata(comments, |metadata| &mut metadata.comments);
                    match &mut self.state {
                        ReaderState::PcapNg { interfaces, .. } => {
                            if interfaces.len() >= self.max_interfaces {
                                return Err(Error::InterfaceLimit {
                                    limit: self.max_interfaces,
                                });
                            }
                            if self.interfaces.len() >= self.max_total_interfaces {
                                return Err(Error::TotalInterfaceLimit {
                                    limit: self.max_total_interfaces,
                                });
                            }
                            interfaces.push(description);
                            self.interfaces.push(description);
                        }
                        ReaderState::Pcap { .. } => unreachable!("state checked by caller"),
                    }
                }
                PCAPNG_ENHANCED_PACKET_BLOCK => {
                    let interfaces = match &self.state {
                        ReaderState::PcapNg { interfaces, .. } => interfaces,
                        ReaderState::Pcap { .. } => unreachable!("state checked by caller"),
                    };
                    let frame = parse_enhanced_packet(
                        body,
                        section_endianness,
                        interfaces,
                        section_interface_base,
                        self.max_size,
                    )?;
                    // Packet comments are retained after the frame parses, so
                    // a malformed record still fails on the record itself.
                    let captured = usize::try_from(frame.captured_length()).unwrap_or(usize::MAX);
                    if let Some(options) = body.get(20 + captured.next_multiple_of(4)..) {
                        let comments = parse_comments(
                            options,
                            section_endianness,
                            "pcapng packet options",
                            CommentScope::Frame {
                                sequence: self.frames_read,
                            },
                        )?;
                        self.retain_metadata(comments, |metadata| &mut metadata.comments);
                    }
                    self.frames_read = self.frames_read.saturating_add(1);
                    return Ok(Some(frame));
                }
                PCAPNG_NAME_RESOLUTION_BLOCK => {
                    let records = parse_name_resolution(body, section_endianness)?;
                    self.retain_metadata(records, |metadata| &mut metadata.name_records);
                }
                PCAPNG_INTERFACE_STATISTICS_BLOCK => {
                    let mut statistics = parse_interface_statistics(body, section_endianness)?;
                    statistics.interface = section_interface_base
                        .checked_add(statistics.interface)
                        .ok_or(Error::InterfaceLimit { limit: usize::MAX })?;
                    self.retain_metadata(vec![statistics], |metadata| {
                        &mut metadata.interface_statistics
                    });
                }
                PCAPNG_PACKET_BLOCK => {
                    let interfaces = match &self.state {
                        ReaderState::PcapNg { interfaces, .. } => interfaces,
                        ReaderState::Pcap { .. } => unreachable!("state checked by caller"),
                    };
                    let frame = parse_obsolete_packet(
                        body,
                        section_endianness,
                        interfaces,
                        section_interface_base,
                        self.max_size,
                    )?;
                    let captured = usize::try_from(frame.captured_length()).unwrap_or(usize::MAX);
                    if let Some(options) = body.get(20 + captured.next_multiple_of(4)..) {
                        let comments = parse_comments(
                            options,
                            section_endianness,
                            "pcapng packet options",
                            CommentScope::Frame {
                                sequence: self.frames_read,
                            },
                        )?;
                        self.retain_metadata(comments, |metadata| &mut metadata.comments);
                    }
                    // Every returned frame advances the stream position that
                    // `CommentScope::Frame` names, not only enhanced packets.
                    self.frames_read = self.frames_read.saturating_add(1);
                    return Ok(Some(frame));
                }
                PCAPNG_SIMPLE_PACKET_BLOCK => {
                    let interfaces = match &self.state {
                        ReaderState::PcapNg { interfaces, .. } => interfaces,
                        ReaderState::Pcap { .. } => unreachable!("state checked by caller"),
                    };
                    let frame = parse_simple_packet(
                        body,
                        section_endianness,
                        interfaces,
                        section_interface_base,
                        self.max_size,
                    )?;
                    self.frames_read = self.frames_read.saturating_add(1);
                    return Ok(Some(frame));
                }
                _ => {
                    // Metadata and extension blocks are length-delimited, so an
                    // unknown block can be skipped without guessing its layout.
                }
            }
        }
    }

    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Iterator for Reader<R> {
    type Item = Result<Frame, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_frame() {
            Ok(Some(frame)) => Some(Ok(frame)),
            Ok(None) => None,
            Err(error) => {
                self.finished = true;
                Some(Err(error))
            }
        }
    }
}
