// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) use decode::{PcapNgState, read_next_pcapng_record};
pub(super) use encode::{
    interface_description_base_length, next_interface_id, select_interface, validate_new_interface,
    write_enhanced_packet, write_interface_description, write_mapped_interface,
    write_mapped_packet, write_section_header, write_simple_packet,
};
pub(super) use options::{validate_copyable_option, validate_metadata_options};
pub(super) use packet::{
    PacketRead, simple_packet_captured_length, validate_rewritable_packet_flags,
};
pub(super) use section::{
    read_section_header_after_type, write_rewritten_section, write_selected_section,
};

mod decode;
mod encode;
mod interface;
mod options;
mod packet;
mod section;
