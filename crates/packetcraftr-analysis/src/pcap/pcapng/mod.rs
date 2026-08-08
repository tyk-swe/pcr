// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Pure PCAPNG block parsing, section state, and encoding.

pub(super) use decode::{PcapNgState, read_next_pcapng_frame};
pub(super) use encode::{
    select_interface, validate_new_interface, write_enhanced_packet, write_interface_description,
    write_section_header,
};
pub(super) use section::read_section_header_after_type;

mod decode;
mod encode;
mod interface;
mod options;
mod packet;
mod section;
