// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) use decode::{PcapNgState, read_next_pcapng_record};
pub(super) use encode::{
    interface_description_base_length, select_interface, validate_new_interface,
    write_enhanced_packet, write_interface_description, write_section_header,
};
pub(super) use packet::validate_rewritable_packet_flags;
pub(super) use section::{read_section_header_after_type, write_selected_section};

mod decode;
mod encode;
mod interface;
mod options;
mod packet;
mod section;
