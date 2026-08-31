// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! PCAPNG block decoding and section/interface state.

use std::io::Read;

use super::section::{SectionHeader, read_pcapng_block_header, read_section_header_with_length};
use crate::analysis::pcap::{
    error::Error,
    model::{
        CaptureRecord, Endianness, Format, Interface, MetadataBlockKind, ReaderOptions, RecordKind,
        Section,
    },
    wire::PCAPNG_SECTION_HEADER,
};

mod framing;
mod record;

pub(in crate::analysis::pcap) struct PcapNgState {
    endianness: Endianness,
    interfaces: Vec<Interface>,
    interface_base: u32,
    section_index: u64,
    remaining_in_section: Option<u64>,
    metadata_blocks: usize,
    metadata_bytes: usize,
}

impl PcapNgState {
    pub(in crate::analysis::pcap) fn new(header: SectionHeader) -> Self {
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

    pub(in crate::analysis::pcap) fn endianness(&self) -> Endianness {
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
            *remaining = remaining.saturating_sub(u64::from(block_length));
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

fn read_section_record<R: Read>(
    reader: &mut R,
    raw_header: [u8; 8],
    state: &mut PcapNgState,
    options: &ReaderOptions,
    scratch: &mut Vec<u8>,
) -> Result<CaptureRecord, Error> {
    if let Some(remaining) = state
        .remaining_in_section
        .filter(|remaining| *remaining != 0)
    {
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
    Ok(CaptureRecord {
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
    })
}

pub(in crate::analysis::pcap) fn read_next_pcapng_record<R: Read>(
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
        return read_section_record(reader, raw_header, state, options, scratch).map(Some);
    }
    let block = framing::read(reader, raw_header, state, options, scratch)?;
    record::decode(block, state, all_interfaces, options).map(Some)
}
