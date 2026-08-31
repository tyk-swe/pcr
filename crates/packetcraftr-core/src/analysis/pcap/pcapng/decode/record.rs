// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Interpretation of validated PCAPNG block bodies.

use crate::frame::Frame;
use bytes::Bytes;

use super::PcapNgState;
use super::framing::{FramedBlock, packet_block_kind};
use crate::analysis::pcap::pcapng::{
    interface::parse_interface_description,
    options::parse_options,
    packet::{parse_enhanced_packet, parse_obsolete_packet, parse_simple_packet},
};
use crate::analysis::pcap::{
    error::Error,
    model::{
        CaptureRecord, Format, Interface, MetadataBlockKind, PacketBlockKind, ReaderOptions,
        RecordKind,
    },
    wire::{
        PCAPNG_CUSTOM_BLOCK, PCAPNG_CUSTOM_BLOCK_NO_COPY, PCAPNG_INTERFACE_DESCRIPTION_BLOCK,
        PCAPNG_INTERFACE_STATISTICS_BLOCK, PCAPNG_NAME_RESOLUTION_BLOCK, decode_u32,
    },
};

pub(super) fn decode(
    block: FramedBlock<'_>,
    state: &mut PcapNgState,
    all_interfaces: &mut Vec<Interface>,
    options: &ReaderOptions,
) -> Result<CaptureRecord, Error> {
    match block.block_type {
        PCAPNG_INTERFACE_DESCRIPTION_BLOCK => {
            decode_interface(block.body, block.raw, state, all_interfaces, options)
        }
        block_type => match packet_block_kind(block_type) {
            Some(kind) => decode_packet(kind, block.body, block.raw, state, options),
            None => decode_metadata(block_type, block.body, block.raw, state),
        },
    }
}

fn decode_interface(
    body: &[u8],
    raw: Bytes,
    state: &mut PcapNgState,
    all_interfaces: &mut Vec<Interface>,
    options: &ReaderOptions,
) -> Result<CaptureRecord, Error> {
    let description = parse_interface_description(body, state.endianness)?;
    let option_bytes = body.get(8..).ok_or(Error::InvalidData {
        format: Format::PcapNg,
        reason: "interface description block is shorter than 8 bytes",
    })?;
    let parsed_options = parse_options(option_bytes, state.endianness, "pcapng interface options")?;
    let local_id = u32::try_from(state.interfaces.len()).map_err(|_| Error::InterfaceLimit {
        limit: options.max_interfaces_per_section,
    })?;
    let global_id = state.add_interface(all_interfaces, description.clone(), options)?;
    Ok(record(
        RecordKind::Metadata(MetadataBlockKind::InterfaceDescription {
            section: state.section_index,
            local_id,
            global_id,
            interface: description,
            options: parsed_options,
        }),
        None,
        raw,
    ))
}

fn decode_packet(
    kind: PacketBlockKind,
    body: &[u8],
    raw: Bytes,
    state: &mut PcapNgState,
    options: &ReaderOptions,
) -> Result<CaptureRecord, Error> {
    let parse = match kind {
        PacketBlockKind::Enhanced => parse_enhanced_packet,
        PacketBlockKind::Obsolete => parse_obsolete_packet,
        // A classic-PCAP record never reaches this decoder.
        PacketBlockKind::Simple | PacketBlockKind::Classic => parse_simple_packet,
    };
    let parsed = parse(
        body,
        state.endianness,
        &state.interfaces,
        state.interface_base,
        options.max_size,
    )?;
    let parsed_options = parse_options(parsed.options, state.endianness, "pcapng packet options")?;
    state.reset_metadata();
    Ok(record(
        RecordKind::Packet {
            block: kind,
            section: Some(state.section_index),
            interface_id: Some(parsed.interface_id),
            options: parsed_options,
        },
        Some(parsed.frame),
        raw,
    ))
}

fn decode_metadata(
    block_type: u32,
    body: &[u8],
    raw: Bytes,
    state: &PcapNgState,
) -> Result<CaptureRecord, Error> {
    let section = state.section_index;
    let kind = match block_type {
        PCAPNG_NAME_RESOLUTION_BLOCK => MetadataBlockKind::NameResolution { section },
        PCAPNG_INTERFACE_STATISTICS_BLOCK => {
            if body.len() < 4 {
                return Err(Error::InvalidData {
                    format: Format::PcapNg,
                    reason: "interface statistics block is shorter than four bytes",
                });
            }
            let interface_id = decode_u32(state.endianness, body)?;
            if interface_id as usize >= state.interfaces.len() {
                return Err(Error::UndefinedInterface {
                    interface: interface_id,
                    available: state.interfaces.len(),
                });
            }
            MetadataBlockKind::InterfaceStatistics {
                section,
                interface_id,
            }
        }
        PCAPNG_CUSTOM_BLOCK | PCAPNG_CUSTOM_BLOCK_NO_COPY => MetadataBlockKind::Custom {
            section,
            block_type,
        },
        _ => MetadataBlockKind::Unknown {
            section,
            block_type,
        },
    };
    Ok(record(RecordKind::Metadata(kind), None, raw))
}

fn record(kind: RecordKind, frame: Option<Frame>, raw: Bytes) -> CaptureRecord {
    CaptureRecord {
        kind,
        frame,
        format: Format::PcapNg,
        raw,
    }
}
