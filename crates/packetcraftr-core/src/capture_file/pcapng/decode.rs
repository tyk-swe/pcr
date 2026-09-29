// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Read;

use super::section::{SectionHeader, read_pcapng_block_header, read_section_header_with_length};
use crate::capture_file::{
    error::Error,
    format::{Endianness, Format},
    header::{Interface, Section},
    limits::ReaderLimits,
    record::{CaptureRecord, MetadataBlockKind, RecordKind},
    wire::PCAPNG_SECTION_HEADER,
};

mod framing;
mod record;

pub(in crate::capture_file) struct PcapNgState {
    endianness: Endianness,
    interface_base: u32,
    section_index: u64,
    remaining_in_section: Option<u64>,
    metadata_blocks: usize,
    metadata_bytes: usize,
}

impl PcapNgState {
    pub(in crate::capture_file) fn new(header: SectionHeader) -> Self {
        Self {
            endianness: header.endianness,
            interface_base: 0,
            section_index: 0,
            remaining_in_section: header.length,
            metadata_blocks: 0,
            metadata_bytes: 0,
        }
    }

    pub(in crate::capture_file) fn endianness(&self) -> Endianness {
        self.endianness
    }

    fn section_interfaces<'a>(&self, all_interfaces: &'a [Interface]) -> &'a [Interface] {
        all_interfaces
            .get(self.interface_base as usize..)
            .unwrap_or_default()
    }

    fn start_section(
        &mut self,
        header: &SectionHeader,
        all_interfaces: &[Interface],
        max_interfaces: usize,
    ) -> Result<(), Error> {
        self.interface_base =
            u32::try_from(all_interfaces.len()).map_err(|_| Error::InterfaceLimit {
                limit: max_interfaces,
            })?;
        self.section_index = self
            .section_index
            .checked_add(1)
            .ok_or(Error::InterfaceLimit {
                limit: max_interfaces,
            })?;
        self.endianness = header.endianness;
        self.remaining_in_section = header.length;
        Ok(())
    }

    fn commit_block(&mut self, block_length: u32) {
        if let Some(remaining) = &mut self.remaining_in_section {
            *remaining = remaining.saturating_sub(u64::from(block_length));
        }
    }

    fn account_metadata(&mut self, length: usize, limits: &ReaderLimits) -> Result<(), Error> {
        self.metadata_blocks = self.metadata_blocks.saturating_add(1);
        if self.metadata_blocks > limits.max_metadata_blocks_per_frame {
            return Err(Error::MetadataBlockLimit {
                limit: limits.max_metadata_blocks_per_frame,
            });
        }
        self.metadata_bytes = self
            .metadata_bytes
            .checked_add(length)
            .filter(|actual| *actual <= limits.max_metadata_bytes_per_frame)
            .ok_or(Error::MetadataByteLimit {
                limit: limits.max_metadata_bytes_per_frame,
            })?;
        Ok(())
    }

    fn reset_metadata(&mut self) {
        self.metadata_blocks = 0;
        self.metadata_bytes = 0;
    }

    fn add_interface(
        &self,
        all_interfaces: &mut Vec<Interface>,
        description: Interface,
        limits: &ReaderLimits,
    ) -> Result<u32, Error> {
        if self.section_interfaces(all_interfaces).len() >= limits.max_interfaces_per_section {
            return Err(Error::InterfaceLimit {
                limit: limits.max_interfaces_per_section,
            });
        }
        if all_interfaces.len() >= limits.max_total_interfaces {
            return Err(Error::TotalInterfaceLimit {
                limit: limits.max_total_interfaces,
            });
        }
        let global_id =
            u32::try_from(all_interfaces.len()).map_err(|_| Error::TotalInterfaceLimit {
                limit: limits.max_total_interfaces,
            })?;
        all_interfaces.push(description);
        Ok(global_id)
    }
}

fn read_section_record<R: Read>(
    reader: &mut R,
    raw_header: [u8; 8],
    state: &mut PcapNgState,
    all_interfaces: &[Interface],
    limits: &ReaderLimits,
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
        limits.max_size,
        Some((state.metadata_bytes, limits.max_metadata_bytes_per_frame)),
        scratch,
    )?;
    state.account_metadata(header.block_length, limits)?;
    state.start_section(&header, all_interfaces, limits.max_interfaces_per_section)?;
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

pub(in crate::capture_file) fn read_next_pcapng_record<R: Read>(
    reader: &mut R,
    state: &mut PcapNgState,
    all_interfaces: &mut Vec<Interface>,
    limits: &ReaderLimits,
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
        return read_section_record(reader, raw_header, state, all_interfaces, limits, scratch)
            .map(Some);
    }
    let block = framing::read(reader, raw_header, state, limits, scratch)?;
    record::decode(block, state, all_interfaces, limits).map(Some)
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::capture_file::format::TimestampResolution;
    use crate::frame::LinkType;

    fn section() -> SectionHeader {
        SectionHeader {
            endianness: Endianness::Little,
            major: 1,
            minor: 0,
            length: None,
            options: Vec::new(),
            block_length: 28,
            raw: Bytes::new(),
        }
    }

    fn interface(link_type: u32) -> Interface {
        Interface {
            link_type: LinkType(link_type),
            snap_len: 0,
            timestamp_resolution: TimestampResolution::Decimal(6),
            timestamp_offset: 0,
        }
    }

    fn add(state: &PcapNgState, all: &mut Vec<Interface>, link_type: u32) -> Result<u32, Error> {
        let limits = ReaderLimits {
            max_interfaces_per_section: 2,
            max_total_interfaces: 4,
            ..ReaderLimits::default()
        };
        state.add_interface(all, interface(link_type), &limits)
    }

    #[test]
    fn each_section_counts_and_exposes_only_its_own_interfaces() {
        let mut all = Vec::new();
        let mut state = PcapNgState::new(section());
        assert!(matches!(add(&state, &mut all, 1), Ok(0)));
        assert!(matches!(add(&state, &mut all, 2), Ok(1)));
        assert!(matches!(
            add(&state, &mut all, 3),
            Err(Error::InterfaceLimit { limit: 2 })
        ));

        state.start_section(&section(), &all, 2).unwrap();
        assert!(state.section_interfaces(&all).is_empty());
        assert!(matches!(add(&state, &mut all, 3), Ok(2)));
        assert!(matches!(add(&state, &mut all, 4), Ok(3)));
        assert_eq!(state.section_interfaces(&all), [interface(3), interface(4)]);
        assert!(matches!(
            add(&state, &mut all, 5),
            Err(Error::InterfaceLimit { limit: 2 })
        ));

        state.start_section(&section(), &all, 2).unwrap();
        assert!(matches!(
            add(&state, &mut all, 5),
            Err(Error::TotalInterfaceLimit { limit: 4 })
        ));
        assert_eq!(all.len(), 4);
    }
}
