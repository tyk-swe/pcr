// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! PCAPNG block decoding and section/interface state.

use std::io::Read;

use crate::Frame;

use super::super::{
    error::Error,
    model::{Endianness, Interface, ReaderOptions},
    wire::{
        PCAPNG_ENHANCED_PACKET_BLOCK, PCAPNG_INTERFACE_DESCRIPTION_BLOCK, PCAPNG_PACKET_BLOCK,
        PCAPNG_SECTION_HEADER, PCAPNG_SIMPLE_PACKET_BLOCK, decode_u32, read_exact_vec,
    },
};
use super::interface::parse_interface_description;
use super::packet::{parse_enhanced_packet, parse_obsolete_packet, parse_simple_packet};
use super::section::{
    SectionHeader, read_pcapng_block_header, read_section_header_with_length,
    validate_pcapng_block_length,
};

pub(in crate::pcap) struct PcapNgState {
    endianness: Endianness,
    interfaces: Vec<Interface>,
    interface_base: u32,
    remaining_in_section: Option<u64>,
}

impl PcapNgState {
    pub(in crate::pcap) fn new(header: SectionHeader) -> Self {
        Self {
            endianness: header.endianness,
            interfaces: Vec::new(),
            interface_base: 0,
            remaining_in_section: header.length,
        }
    }

    pub(in crate::pcap) fn endianness(&self) -> Endianness {
        self.endianness
    }

    pub(in crate::pcap) fn interfaces(&self) -> &[Interface] {
        &self.interfaces
    }

    pub(in crate::pcap) fn interface_base(&self) -> u32 {
        self.interface_base
    }

    pub(in crate::pcap) fn remaining_in_section(&self) -> Option<u64> {
        self.remaining_in_section
    }

    pub(in crate::pcap) fn start_section(
        &mut self,
        header: SectionHeader,
        max_interfaces: usize,
    ) -> Result<(), Error> {
        let section_interfaces =
            u32::try_from(self.interfaces.len()).map_err(|_| Error::InterfaceLimit {
                limit: max_interfaces,
            })?;
        let interface_base =
            self.interface_base
                .checked_add(section_interfaces)
                .ok_or(Error::InterfaceLimit {
                    limit: max_interfaces,
                })?;
        self.endianness = header.endianness;
        self.interfaces.clear();
        self.interface_base = interface_base;
        self.remaining_in_section = header.length;
        Ok(())
    }

    pub(in crate::pcap) fn commit_block(&mut self, block_length: u32) {
        if let Some(remaining) = &mut self.remaining_in_section {
            *remaining -= u64::from(block_length);
        }
    }

    pub(in crate::pcap) fn add_interface(
        &mut self,
        all_interfaces: &mut Vec<Interface>,
        description: Interface,
        max_interfaces: usize,
        max_total_interfaces: usize,
    ) -> Result<(), Error> {
        if self.interfaces.len() >= max_interfaces {
            return Err(Error::InterfaceLimit {
                limit: max_interfaces,
            });
        }
        if all_interfaces.len() >= max_total_interfaces {
            return Err(Error::TotalInterfaceLimit {
                limit: max_total_interfaces,
            });
        }
        self.interfaces.push(description);
        all_interfaces.push(description);
        Ok(())
    }
}

pub(in crate::pcap) fn read_next_pcapng_frame<R: Read>(
    reader: &mut R,
    state: &mut PcapNgState,
    all_interfaces: &mut Vec<Interface>,
    options: &ReaderOptions,
    scratch: &mut Vec<u8>,
) -> Result<Option<Frame>, Error> {
    let ReaderOptions {
        max_size,
        max_interfaces_per_section: max_interfaces,
        max_total_interfaces,
        max_metadata_blocks_per_frame,
        max_metadata_bytes_per_frame,
    } = *options;
    let mut metadata_blocks = 0usize;
    let mut metadata_bytes = 0usize;
    loop {
        let section_endianness = state.endianness();
        let section_interface_base = state.interface_base();
        let remaining_in_section = state.remaining_in_section();

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
            metadata_blocks = metadata_blocks.saturating_add(1);
            if metadata_blocks > max_metadata_blocks_per_frame {
                return Err(Error::MetadataBlockLimit {
                    limit: max_metadata_blocks_per_frame,
                });
            }
            let header = read_section_header_with_length(
                reader,
                raw_header[4..8].try_into().expect("four-byte slice"),
                max_size,
                Some((metadata_bytes, max_metadata_bytes_per_frame)),
                scratch,
            )?;
            metadata_bytes = metadata_bytes
                .checked_add(header.block_length)
                .expect("section header metadata sum was validated");
            state.start_section(header, max_interfaces)?;
            continue;
        }

        let block_type = decode_u32(section_endianness, &raw_header[..4]);
        let block_length = decode_u32(section_endianness, &raw_header[4..8]);
        validate_pcapng_block_length(block_length, max_size)?;
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
            metadata_blocks = metadata_blocks.saturating_add(1);
            if metadata_blocks > max_metadata_blocks_per_frame {
                return Err(Error::MetadataBlockLimit {
                    limit: max_metadata_blocks_per_frame,
                });
            }
            metadata_bytes = metadata_bytes
                .checked_add(block_length_usize)
                .filter(|actual| *actual <= max_metadata_bytes_per_frame)
                .ok_or(Error::MetadataByteLimit {
                    limit: max_metadata_bytes_per_frame,
                })?;
        }
        let remaining = block_length_usize - 8;
        read_exact_vec(reader, scratch, remaining, "pcapng block")?;

        let body_length = scratch.len() - 4;
        let trailing_length = decode_u32(section_endianness, &scratch[body_length..]);
        if trailing_length != block_length {
            return Err(Error::BlockLengthMismatch {
                leading: block_length,
                trailing: trailing_length,
            });
        }
        let body = &scratch[..body_length];

        state.commit_block(block_length);

        match block_type {
            PCAPNG_INTERFACE_DESCRIPTION_BLOCK => {
                let description = parse_interface_description(body, section_endianness)?;
                state.add_interface(
                    all_interfaces,
                    description,
                    max_interfaces,
                    max_total_interfaces,
                )?;
            }
            PCAPNG_ENHANCED_PACKET_BLOCK => {
                return parse_enhanced_packet(
                    body,
                    section_endianness,
                    state.interfaces(),
                    section_interface_base,
                    max_size,
                )
                .map(Some);
            }
            PCAPNG_PACKET_BLOCK => {
                return parse_obsolete_packet(
                    body,
                    section_endianness,
                    state.interfaces(),
                    section_interface_base,
                    max_size,
                )
                .map(Some);
            }
            PCAPNG_SIMPLE_PACKET_BLOCK => {
                return parse_simple_packet(
                    body,
                    section_endianness,
                    state.interfaces(),
                    section_interface_base,
                    max_size,
                )
                .map(Some);
            }
            _ => {
                // Metadata and extension blocks are length-delimited, so an
                // unknown block can be skipped without guessing its layout.
            }
        }
    }
}
