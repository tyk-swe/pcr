// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Pure PCAPNG block parsing.

pub(super) use interface::parse_interface_description;
pub(super) use packet::{parse_enhanced_packet, parse_obsolete_packet, parse_simple_packet};
pub(super) use section::{
    SectionHeader, read_pcapng_block_header, read_section_header_after_type,
    read_section_header_with_length, validate_pcapng_block_length,
};

mod interface;
mod options;
mod packet;
mod section;
