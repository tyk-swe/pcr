// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! PCAPNG block decoding and section/interface state.

use std::io::Read;

use bytes::Bytes;

use super::super::{
    error::Error,
    model::{
        CaptureRecord, Endianness, Format, Interface, MetadataBlockKind, PacketBlockKind,
        ReaderOptions, RecordKind, Section,
    },
    wire::{
        PCAPNG_CUSTOM_BLOCK, PCAPNG_CUSTOM_BLOCK_NO_COPY, PCAPNG_ENHANCED_PACKET_BLOCK,
        PCAPNG_INTERFACE_DESCRIPTION_BLOCK, PCAPNG_INTERFACE_STATISTICS_BLOCK,
        PCAPNG_NAME_RESOLUTION_BLOCK, PCAPNG_PACKET_BLOCK, PCAPNG_SECTION_HEADER,
        PCAPNG_SIMPLE_PACKET_BLOCK, align_to_usize, decode_u32, read_exact_vec,
    },
};
use super::interface::parse_interface_description;
use super::options::parse_options;
use super::packet::{parse_enhanced_packet, parse_obsolete_packet, parse_simple_packet};
use super::section::{
    SectionHeader, read_pcapng_block_header, read_section_header_with_length,
    validate_pcapng_block_length,
};

pub(in crate::pcap) struct PcapNgState {
    endianness: Endianness,
    interfaces: Vec<Interface>,
    interface_base: u32,
    section_index: u64,
    remaining_in_section: Option<u64>,
    metadata_blocks: usize,
    metadata_bytes: usize,
}

impl PcapNgState {
    pub(in crate::pcap) fn new(header: SectionHeader) -> Self {
        Self {
            endianness: header.endianness,
            interfaces: Vec::new(),
            interface_base: 0,
            section_index: 0,
            remaining_in_section: header.length,
            metadata_blocks: 0,
            metadata_bytes: 0,
        }
    }

    pub(in crate::pcap) fn endianness(&self) -> Endianness {
        self.endianness
    }

    fn start_section(
        &mut self,
        header: &SectionHeader,
        max_interfaces: usize,
    ) -> Result<(), Error> {
        let section_interfaces =
            u32::try_from(self.interfaces.len()).map_err(|_| Error::InterfaceLimit {
                limit: max_interfaces,
            })?;
        self.interface_base =
            self.interface_base
                .checked_add(section_interfaces)
                .ok_or(Error::InterfaceLimit {
                    limit: max_interfaces,
                })?;
        self.section_index = self
            .section_index
            .checked_add(1)
            .ok_or(Error::InterfaceLimit {
                limit: max_interfaces,
            })?;
        self.endianness = header.endianness;
        self.interfaces.clear();
        self.remaining_in_section = header.length;
        Ok(())
    }

    fn commit_block(&mut self, block_length: u32) {
        if let Some(remaining) = &mut self.remaining_in_section {
            *remaining -= u64::from(block_length);
        }
    }

    fn account_metadata(&mut self, length: usize, options: &ReaderOptions) -> Result<(), Error> {
        self.metadata_blocks = self.metadata_blocks.saturating_add(1);
        if self.metadata_blocks > options.max_metadata_blocks_per_frame {
            return Err(Error::MetadataBlockLimit {
                limit: options.max_metadata_blocks_per_frame,
            });
        }
        self.metadata_bytes = self
            .metadata_bytes
            .checked_add(length)
            .filter(|actual| *actual <= options.max_metadata_bytes_per_frame)
            .ok_or(Error::MetadataByteLimit {
                limit: options.max_metadata_bytes_per_frame,
            })?;
        Ok(())
    }

    fn reset_metadata(&mut self) {
        self.metadata_blocks = 0;
        self.metadata_bytes = 0;
    }

    fn add_interface(
        &mut self,
        all_interfaces: &mut Vec<Interface>,
        description: Interface,
        options: &ReaderOptions,
    ) -> Result<u32, Error> {
        if self.interfaces.len() >= options.max_interfaces_per_section {
            return Err(Error::InterfaceLimit {
                limit: options.max_interfaces_per_section,
            });
        }
        if all_interfaces.len() >= options.max_total_interfaces {
            return Err(Error::TotalInterfaceLimit {
                limit: options.max_total_interfaces,
            });
        }
        let global_id =
            u32::try_from(all_interfaces.len()).map_err(|_| Error::TotalInterfaceLimit {
                limit: options.max_total_interfaces,
            })?;
        self.interfaces.push(description.clone());
        all_interfaces.push(description);
        Ok(global_id)
    }
}

fn raw_block(header: &[u8; 8], tail: &[u8], length: usize) -> Result<Bytes, Error> {
    let mut raw = Vec::new();
    raw.try_reserve_exact(length)
        .map_err(|_| Error::AllocationFailed {
            kind: "pcapng source block",
            requested: length,
        })?;
    raw.extend_from_slice(header);
    raw.extend_from_slice(tail);
    Ok(Bytes::from(raw))
}

fn packet_options(block_type: u32, body: &[u8], endianness: Endianness) -> Result<&[u8], Error> {
    if block_type == PCAPNG_SIMPLE_PACKET_BLOCK {
        return Ok(&[]);
    }
    let captured_length = decode_u32(endianness, &body[12..16])?;
    let offset = 20_usize
        .checked_add(align_to_usize(captured_length as usize)?)
        .ok_or(Error::InvalidData {
            format: Format::PcapNg,
            reason: "packet options offset overflow",
        })?;
    body.get(offset..).ok_or(Error::InvalidData {
        format: Format::PcapNg,
        reason: "packet options begin beyond the block body",
    })
}

pub(in crate::pcap) fn read_next_pcapng_record<R: Read>(
    reader: &mut R,
    state: &mut PcapNgState,
    all_interfaces: &mut Vec<Interface>,
    options: &ReaderOptions,
    scratch: &mut Vec<u8>,
) -> Result<Option<CaptureRecord>, Error> {
    let remaining_in_section = state.remaining_in_section;
    if let Some(remaining) = remaining_in_section
        && remaining != 0
        && remaining < 12
    {
        return Err(Error::SectionRemainderTooSmall { remaining });
    }
    let Some(raw_header) = read_pcapng_block_header(reader)? else {
        if let Some(remaining) = remaining_in_section.filter(|remaining| *remaining != 0) {
            return Err(Error::SectionEndedEarly { remaining });
        }
        return Ok(None);
    };

    if raw_header[..4] == PCAPNG_SECTION_HEADER {
        if let Some(remaining) = remaining_in_section.filter(|remaining| *remaining != 0) {
            return Err(Error::SectionHeaderBeforeBoundary { remaining });
        }
        let header = read_section_header_with_length(
            reader,
            raw_header[4..8].try_into().expect("four-byte slice"),
            options.max_size,
            Some((state.metadata_bytes, options.max_metadata_bytes_per_frame)),
            scratch,
        )?;
        state.account_metadata(header.block_length, options)?;
        state.start_section(&header, options.max_interfaces_per_section)?;
        return Ok(Some(CaptureRecord {
            kind: RecordKind::Metadata(MetadataBlockKind::Section(Section {
                index: state.section_index,
                endianness: header.endianness,
                major: header.major,
                minor: header.minor,
                length: header.length,
                options: header.options,
                raw: header.raw.clone(),
            })),
            frame: None,
            format: Format::PcapNg,
            raw: header.raw,
        }));
    }

    let section_endianness = state.endianness;
    let block_type = decode_u32(section_endianness, &raw_header[..4])?;
    let block_length = decode_u32(section_endianness, &raw_header[4..8])?;
    validate_pcapng_block_length(block_length, options.max_size)?;
    if let Some(remaining) = remaining_in_section
        && u64::from(block_length) > remaining
    {
        return Err(Error::BlockCrossesSectionBoundary {
            block_length,
            remaining,
        });
    }
    let block_length_usize =
        usize::try_from(block_length).map_err(|_| Error::InvalidBlockLength {
            length: block_length,
        })?;
    let is_packet = matches!(
        block_type,
        PCAPNG_ENHANCED_PACKET_BLOCK | PCAPNG_PACKET_BLOCK | PCAPNG_SIMPLE_PACKET_BLOCK
    );
    if !is_packet {
        state.account_metadata(block_length_usize, options)?;
    }
    read_exact_vec(reader, scratch, block_length_usize - 8, "pcapng block")?;
    let body_length = scratch.len() - 4;
    let trailing_length = decode_u32(section_endianness, &scratch[body_length..])?;
    if trailing_length != block_length {
        return Err(Error::BlockLengthMismatch {
            leading: block_length,
            trailing: trailing_length,
        });
    }
    let body = &scratch[..body_length];
    state.commit_block(block_length);
    let raw = raw_block(&raw_header, scratch, block_length_usize)?;
    let section = state.section_index;

    let (kind, frame) = match block_type {
        PCAPNG_INTERFACE_DESCRIPTION_BLOCK => {
            let description = parse_interface_description(body, section_endianness)?;
            let parsed_options =
                parse_options(&body[8..], section_endianness, "pcapng interface options")?;
            let local_id =
                u32::try_from(state.interfaces.len()).map_err(|_| Error::InterfaceLimit {
                    limit: options.max_interfaces_per_section,
                })?;
            let global_id = state.add_interface(all_interfaces, description.clone(), options)?;
            (
                RecordKind::Metadata(MetadataBlockKind::InterfaceDescription {
                    section,
                    local_id,
                    global_id,
                    interface: description,
                    options: parsed_options,
                }),
                None,
            )
        }
        PCAPNG_ENHANCED_PACKET_BLOCK | PCAPNG_PACKET_BLOCK | PCAPNG_SIMPLE_PACKET_BLOCK => {
            let frame = match block_type {
                PCAPNG_ENHANCED_PACKET_BLOCK => parse_enhanced_packet(
                    body,
                    section_endianness,
                    &state.interfaces,
                    state.interface_base,
                    options.max_size,
                )?,
                PCAPNG_PACKET_BLOCK => parse_obsolete_packet(
                    body,
                    section_endianness,
                    &state.interfaces,
                    state.interface_base,
                    options.max_size,
                )?,
                _ => parse_simple_packet(
                    body,
                    section_endianness,
                    &state.interfaces,
                    state.interface_base,
                    options.max_size,
                )?,
            };
            let local_interface = if block_type == PCAPNG_SIMPLE_PACKET_BLOCK {
                0
            } else if block_type == PCAPNG_PACKET_BLOCK {
                u32::from(super::super::wire::decode_u16(
                    section_endianness,
                    &body[..2],
                )?)
            } else {
                decode_u32(section_endianness, &body[..4])?
            };
            let parsed_options = parse_options(
                packet_options(block_type, body, section_endianness)?,
                section_endianness,
                "pcapng packet options",
            )?;
            state.reset_metadata();
            (
                RecordKind::Packet {
                    block: match block_type {
                        PCAPNG_ENHANCED_PACKET_BLOCK => PacketBlockKind::Enhanced,
                        PCAPNG_PACKET_BLOCK => PacketBlockKind::Obsolete,
                        _ => PacketBlockKind::Simple,
                    },
                    section: Some(section),
                    interface_id: Some(local_interface),
                    options: parsed_options,
                },
                Some(frame),
            )
        }
        PCAPNG_NAME_RESOLUTION_BLOCK => (
            RecordKind::Metadata(MetadataBlockKind::NameResolution { section }),
            None,
        ),
        PCAPNG_INTERFACE_STATISTICS_BLOCK => {
            if body.len() < 4 {
                return Err(Error::InvalidData {
                    format: Format::PcapNg,
                    reason: "interface statistics block is shorter than four bytes",
                });
            }
            let interface_id = decode_u32(section_endianness, &body[..4])?;
            if interface_id as usize >= state.interfaces.len() {
                return Err(Error::UndefinedInterface {
                    interface: interface_id,
                    available: state.interfaces.len(),
                });
            }
            (
                RecordKind::Metadata(MetadataBlockKind::InterfaceStatistics {
                    section,
                    interface_id,
                }),
                None,
            )
        }
        PCAPNG_CUSTOM_BLOCK | PCAPNG_CUSTOM_BLOCK_NO_COPY => (
            RecordKind::Metadata(MetadataBlockKind::Custom {
                section,
                block_type,
            }),
            None,
        ),
        _ => (
            RecordKind::Metadata(MetadataBlockKind::Unknown {
                section,
                block_type,
            }),
            None,
        ),
    };
    Ok(Some(CaptureRecord {
        kind,
        frame,
        format: Format::PcapNg,
        raw,
    }))
}
