use std::io::Read;

use crate::capture::{Frame, LinkType};

use super::classic::{PcapFrameOptions, read_next_pcap_frame, read_pcap_header};
use super::models::{
    Endianness, Error, Format, Interface, ReaderLimits, TimestampPrecision, TimestampResolution,
};
use super::pcapng::{
    parse_enhanced_packet, parse_interface_description, parse_obsolete_packet, parse_simple_packet,
    read_pcapng_block_header, read_section_header_after_type, read_section_header_with_length,
    stream_unknown_block, validate_pcapng_block_length,
};
use super::wire::{
    PCAP_GLOBAL_HEADER_LEN, PCAPNG_ENHANCED_PACKET_BLOCK, PCAPNG_INTERFACE_DESCRIPTION_BLOCK,
    PCAPNG_PACKET_BLOCK, PCAPNG_SECTION_HEADER, PCAPNG_SIMPLE_PACKET_BLOCK, decode_u32,
    read_exact_counted, read_exact_or_eof,
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
        remaining_section_bytes: Option<u64>,
    },
}

/// A streaming capture reader over any [`Read`] implementation.
///
/// Construction consumes only the container header. Each call to
/// [`next_frame`](Self::next_frame) reads at most one packet plus bounded
/// intervening metadata.
pub struct Reader<R> {
    inner: R,
    state: ReaderState,
    interfaces: Vec<Interface>,
    limits: ReaderLimits,
    pub(super) max_total_interfaces: usize,
    total_wire_bytes: u64,
    metadata_blocks_before_frame: usize,
    metadata_bytes_before_frame: u64,
    finished: bool,
}

impl<R: Read> Reader<R> {
    /// Opens a capture with the default reader limits.
    pub fn new(inner: R) -> Result<Self, Error> {
        Self::with_reader_limits(inner, ReaderLimits::default())
    }

    /// Opens a capture with a caller-provided packet/block size limit.
    pub fn with_limit(inner: R, max_size: usize) -> Result<Self, Error> {
        Self::with_reader_limits(
            inner,
            ReaderLimits {
                max_block_bytes: max_size,
                ..ReaderLimits::default()
            },
        )
    }

    /// Opens a capture with caller-provided packet/block and interface limits.
    pub fn with_limits(inner: R, max_size: usize, max_interfaces: usize) -> Result<Self, Error> {
        Self::with_reader_limits(
            inner,
            ReaderLimits {
                max_block_bytes: max_size,
                max_interfaces_per_section: max_interfaces,
                ..ReaderLimits::default()
            },
        )
    }

    pub fn with_resource_limits(
        inner: R,
        max_size: usize,
        max_interfaces: usize,
        max_metadata_blocks_per_frame: usize,
    ) -> Result<Self, Error> {
        Self::with_reader_limits(
            inner,
            ReaderLimits {
                max_block_bytes: max_size,
                max_interfaces_per_section: max_interfaces,
                max_metadata_blocks_before_frame: max_metadata_blocks_per_frame,
                ..ReaderLimits::default()
            },
        )
    }

    /// Opens a capture with independent per-section and aggregate retained
    /// interface limits.
    pub fn with_all_resource_limits(
        inner: R,
        max_size: usize,
        max_interfaces: usize,
        max_total_interfaces: usize,
        max_metadata_blocks_per_frame: usize,
    ) -> Result<Self, Error> {
        Self::with_reader_limits(
            inner,
            ReaderLimits {
                max_block_bytes: max_size,
                max_interfaces_per_section: max_interfaces,
                max_total_interfaces,
                max_metadata_blocks_before_frame: max_metadata_blocks_per_frame,
                ..ReaderLimits::default()
            },
        )
    }

    /// Opens a capture with independent block, interface, metadata, and total
    /// wire-byte limits.
    pub fn with_reader_limits(mut inner: R, limits: ReaderLimits) -> Result<Self, Error> {
        let mut magic = [0_u8; 4];
        if !read_exact_or_eof(&mut inner, &mut magic, "capture magic")? {
            return Err(Error::EmptyInput);
        }

        let total_wire_bytes;
        let mut metadata_blocks_before_frame = 0usize;
        let mut metadata_bytes_before_frame = 0_u64;
        let state = match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => {
                total_wire_bytes = checked_wire_total(
                    0,
                    PCAP_GLOBAL_HEADER_LEN as u64,
                    limits.max_total_wire_bytes,
                )?;
                read_pcap_header(
                    &mut inner,
                    Endianness::Little,
                    TimestampPrecision::Microseconds,
                )?
            }
            [0xa1, 0xb2, 0xc3, 0xd4] => {
                total_wire_bytes = checked_wire_total(
                    0,
                    PCAP_GLOBAL_HEADER_LEN as u64,
                    limits.max_total_wire_bytes,
                )?;
                read_pcap_header(
                    &mut inner,
                    Endianness::Big,
                    TimestampPrecision::Microseconds,
                )?
            }
            [0x4d, 0x3c, 0xb2, 0xa1] => {
                total_wire_bytes = checked_wire_total(
                    0,
                    PCAP_GLOBAL_HEADER_LEN as u64,
                    limits.max_total_wire_bytes,
                )?;
                read_pcap_header(
                    &mut inner,
                    Endianness::Little,
                    TimestampPrecision::Nanoseconds,
                )?
            }
            [0xa1, 0xb2, 0x3c, 0x4d] => {
                total_wire_bytes = checked_wire_total(
                    0,
                    PCAP_GLOBAL_HEADER_LEN as u64,
                    limits.max_total_wire_bytes,
                )?;
                read_pcap_header(&mut inner, Endianness::Big, TimestampPrecision::Nanoseconds)?
            }
            PCAPNG_SECTION_HEADER => {
                if limits.max_metadata_blocks_before_frame == 0 {
                    return Err(Error::MetadataBlockLimit { limit: 0 });
                }
                let section = read_section_header_after_type(
                    &mut inner,
                    limits.max_block_bytes,
                    0,
                    limits.max_total_wire_bytes,
                    0,
                    limits.max_metadata_bytes_before_frame,
                )?;
                total_wire_bytes = u64::from(section.block_length);
                metadata_blocks_before_frame = 1;
                metadata_bytes_before_frame = u64::from(section.block_length);
                ReaderState::PcapNg {
                    endianness: section.endianness,
                    interfaces: Vec::new(),
                    interface_base: 0,
                    remaining_section_bytes: section.remaining_section_bytes,
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
        if interfaces.len() > limits.max_total_interfaces {
            return Err(Error::TotalInterfaceLimit {
                limit: limits.max_total_interfaces,
            });
        }

        Ok(Self {
            inner,
            state,
            interfaces,
            limits,
            max_total_interfaces: limits.max_total_interfaces,
            total_wire_bytes,
            metadata_blocks_before_frame,
            metadata_bytes_before_frame,
            finished: false,
        })
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
        self.limits.max_block_bytes
    }

    /// Returns all configured reader limits.
    pub fn reader_limits(&self) -> ReaderLimits {
        self.limits
    }

    /// Interface metadata parsed so far.
    pub fn interfaces(&self) -> &[Interface] {
        &self.interfaces
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
                &mut self.total_wire_bytes,
                PcapFrameOptions {
                    endianness: *endianness,
                    precision: *precision,
                    snap_len: *snap_len,
                    link_type: *link_type,
                    max_size: self.limits.max_block_bytes,
                    max_total_wire_bytes: self.limits.max_total_wire_bytes,
                },
            ),
            ReaderState::PcapNg { .. } => self.next_pcapng_frame(),
        };

        match result {
            Ok(frame) => {
                if frame.is_some() {
                    self.metadata_blocks_before_frame = 0;
                    self.metadata_bytes_before_frame = 0;
                } else {
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

    /// Alias for [`next_frame`](Self::next_frame).
    pub fn read_frame(&mut self) -> Result<Option<Frame>, Error> {
        self.next_frame()
    }

    fn next_pcapng_frame(&mut self) -> Result<Option<Frame>, Error> {
        loop {
            let (section_endianness, section_remaining) = match &self.state {
                ReaderState::PcapNg {
                    endianness,
                    remaining_section_bytes,
                    ..
                } => (*endianness, *remaining_section_bytes),
                ReaderState::Pcap { .. } => unreachable!("state checked by caller"),
            };

            let Some(raw_header) = read_pcapng_block_header(&mut self.inner)? else {
                return match section_remaining {
                    Some(remaining) if remaining != 0 => Err(Error::TruncatedSection { remaining }),
                    _ => Ok(None),
                };
            };

            if raw_header[..4] == PCAPNG_SECTION_HEADER {
                if let Some(remaining) = section_remaining
                    && remaining != 0
                {
                    return Err(Error::PrematureSectionHeader { remaining });
                }
                let next_metadata_blocks = self.checked_metadata_block_count()?;
                let section = read_section_header_with_length(
                    &mut self.inner,
                    raw_header[4..8].try_into().expect("four-byte slice"),
                    self.limits.max_block_bytes,
                    self.total_wire_bytes,
                    self.limits.max_total_wire_bytes,
                    self.metadata_bytes_before_frame,
                    self.limits.max_metadata_bytes_before_frame,
                )?;
                let next_wire = checked_wire_total(
                    self.total_wire_bytes,
                    u64::from(section.block_length),
                    self.limits.max_total_wire_bytes,
                )?;
                let next_metadata_bytes = checked_metadata_bytes(
                    self.metadata_bytes_before_frame,
                    u64::from(section.block_length),
                    self.limits.max_metadata_bytes_before_frame,
                )?;
                match &mut self.state {
                    ReaderState::PcapNg {
                        endianness,
                        interfaces,
                        interface_base,
                        remaining_section_bytes,
                    } => {
                        *interface_base = interface_base
                            .checked_add(u32::try_from(interfaces.len()).map_err(|_| {
                                Error::InterfaceLimit {
                                    limit: self.limits.max_interfaces_per_section,
                                }
                            })?)
                            .ok_or(Error::AccountingOverflow {
                                resource: "global interface identifiers",
                            })?;
                        *endianness = section.endianness;
                        *remaining_section_bytes = section.remaining_section_bytes;
                        interfaces.clear();
                    }
                    ReaderState::Pcap { .. } => unreachable!("state checked by caller"),
                }
                self.total_wire_bytes = next_wire;
                self.metadata_blocks_before_frame = next_metadata_blocks;
                self.metadata_bytes_before_frame = next_metadata_bytes;
                continue;
            }

            if section_remaining == Some(0) {
                return Err(Error::DataAfterSectionEnd);
            }
            let block_type = decode_u32(section_endianness, &raw_header[..4]);
            let block_length = decode_u32(section_endianness, &raw_header[4..8]);
            validate_pcapng_block_length(block_length, self.limits.max_block_bytes)?;
            if let Some(remaining) = section_remaining
                && u64::from(block_length) > remaining
            {
                return Err(Error::SectionBoundary {
                    declared: u64::from(block_length),
                    remaining,
                });
            }
            let next_wire = checked_wire_total(
                self.total_wire_bytes,
                u64::from(block_length),
                self.limits.max_total_wire_bytes,
            )?;
            let is_packet = matches!(
                block_type,
                PCAPNG_ENHANCED_PACKET_BLOCK | PCAPNG_PACKET_BLOCK | PCAPNG_SIMPLE_PACKET_BLOCK
            );
            let next_metadata = if is_packet {
                None
            } else {
                Some((
                    self.checked_metadata_block_count()?,
                    checked_metadata_bytes(
                        self.metadata_bytes_before_frame,
                        u64::from(block_length),
                        self.limits.max_metadata_bytes_before_frame,
                    )?,
                ))
            };

            let body_length =
                usize::try_from(block_length).map_err(|_| Error::InvalidBlockLength {
                    length: block_length,
                })? - 12;
            let known = matches!(
                block_type,
                PCAPNG_INTERFACE_DESCRIPTION_BLOCK
                    | PCAPNG_ENHANCED_PACKET_BLOCK
                    | PCAPNG_PACKET_BLOCK
                    | PCAPNG_SIMPLE_PACKET_BLOCK
            );
            let body = if known {
                let mut body = vec![0_u8; body_length];
                read_exact_counted(&mut self.inner, &mut body, "pcapng block body")?;
                let mut footer = [0_u8; 4];
                read_exact_counted(&mut self.inner, &mut footer, "pcapng block footer")?;
                let trailing_length = decode_u32(section_endianness, &footer);
                if trailing_length != block_length {
                    return Err(Error::BlockLengthMismatch {
                        leading: block_length,
                        trailing: trailing_length,
                    });
                }
                Some(body)
            } else {
                stream_unknown_block(
                    &mut self.inner,
                    body_length,
                    section_endianness,
                    block_length,
                )?;
                None
            };

            self.total_wire_bytes = next_wire;
            if let ReaderState::PcapNg {
                remaining_section_bytes: Some(remaining),
                ..
            } = &mut self.state
            {
                *remaining -= u64::from(block_length);
            }
            if let Some((blocks, bytes)) = next_metadata {
                self.metadata_blocks_before_frame = blocks;
                self.metadata_bytes_before_frame = bytes;
            }

            match block_type {
                PCAPNG_INTERFACE_DESCRIPTION_BLOCK => {
                    let description = parse_interface_description(
                        body.as_deref().expect("known block body"),
                        section_endianness,
                    )?;
                    match &mut self.state {
                        ReaderState::PcapNg { interfaces, .. } => {
                            if interfaces.len() >= self.limits.max_interfaces_per_section {
                                return Err(Error::InterfaceLimit {
                                    limit: self.limits.max_interfaces_per_section,
                                });
                            }
                            if self.interfaces.len() >= self.limits.max_total_interfaces {
                                return Err(Error::TotalInterfaceLimit {
                                    limit: self.limits.max_total_interfaces,
                                });
                            }
                            interfaces.push(description);
                            self.interfaces.push(description);
                        }
                        ReaderState::Pcap { .. } => unreachable!("state checked by caller"),
                    }
                }
                PCAPNG_ENHANCED_PACKET_BLOCK | PCAPNG_PACKET_BLOCK | PCAPNG_SIMPLE_PACKET_BLOCK => {
                    let (interfaces, interface_base) = match &self.state {
                        ReaderState::PcapNg {
                            interfaces,
                            interface_base,
                            ..
                        } => (interfaces.as_slice(), *interface_base),
                        ReaderState::Pcap { .. } => unreachable!("state checked by caller"),
                    };
                    let body = body.as_deref().expect("known block body");
                    let frame = match block_type {
                        PCAPNG_ENHANCED_PACKET_BLOCK => parse_enhanced_packet(
                            body,
                            section_endianness,
                            interfaces,
                            interface_base,
                            self.limits.max_block_bytes,
                        ),
                        PCAPNG_PACKET_BLOCK => parse_obsolete_packet(
                            body,
                            section_endianness,
                            interfaces,
                            interface_base,
                            self.limits.max_block_bytes,
                        ),
                        PCAPNG_SIMPLE_PACKET_BLOCK => parse_simple_packet(
                            body,
                            section_endianness,
                            interfaces,
                            interface_base,
                            self.limits.max_block_bytes,
                        ),
                        _ => unreachable!("packet block checked above"),
                    }?;
                    return Ok(Some(frame));
                }
                _ => {}
            }
        }
    }

    fn checked_metadata_block_count(&self) -> Result<usize, Error> {
        let actual =
            self.metadata_blocks_before_frame
                .checked_add(1)
                .ok_or(Error::AccountingOverflow {
                    resource: "metadata block count",
                })?;
        if actual > self.limits.max_metadata_blocks_before_frame {
            return Err(Error::MetadataBlockLimit {
                limit: self.limits.max_metadata_blocks_before_frame,
            });
        }
        Ok(actual)
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

fn checked_wire_total(current: u64, addition: u64, limit: u64) -> Result<u64, Error> {
    let actual = current
        .checked_add(addition)
        .ok_or(Error::AccountingOverflow {
            resource: "total wire bytes",
        })?;
    if actual > limit {
        return Err(Error::TotalWireByteLimit { actual, limit });
    }
    Ok(actual)
}

fn checked_metadata_bytes(current: u64, addition: u64, limit: u64) -> Result<u64, Error> {
    let actual = current
        .checked_add(addition)
        .ok_or(Error::AccountingOverflow {
            resource: "metadata bytes",
        })?;
    if actual > limit {
        return Err(Error::MetadataByteLimit { actual, limit });
    }
    Ok(actual)
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
