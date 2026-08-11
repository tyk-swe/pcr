// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Interpretation of validated PCAPNG block bodies.

use crate::frame::Frame;
use bytes::Bytes;

use super::super::super::{
    error::Error,
    model::{
        CaptureRecord, Endianness, Format, Interface, MetadataBlockKind, PacketBlockKind,
        ReaderOptions, RecordKind,
    },
    wire::{
        PCAPNG_CUSTOM_BLOCK, PCAPNG_CUSTOM_BLOCK_NO_COPY, PCAPNG_ENHANCED_PACKET_BLOCK,
        PCAPNG_INTERFACE_DESCRIPTION_BLOCK, PCAPNG_INTERFACE_STATISTICS_BLOCK,
        PCAPNG_NAME_RESOLUTION_BLOCK, PCAPNG_PACKET_BLOCK, PCAPNG_SIMPLE_PACKET_BLOCK,
        align_to_usize, decode_u16, decode_u32,
    },
};
use super::super::{
    interface::parse_interface_description,
    options::parse_options,
    packet::{parse_enhanced_packet, parse_obsolete_packet, parse_simple_packet},
};
use super::PcapNgState;
use super::framing::{FramedBlock, is_packet_block};

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
        block_type if is_packet_block(block_type) => {
            decode_packet(block_type, block.body, block.raw, state, options)
        }
        block_type => decode_metadata(block_type, block.body, block.raw, state),
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
    let parsed_options = parse_options(&body[8..], state.endianness, "pcapng interface options")?;
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
    block_type: u32,
    body: &[u8],
    raw: Bytes,
    state: &mut PcapNgState,
    options: &ReaderOptions,
) -> Result<CaptureRecord, Error> {
    let frame = match block_type {
        PCAPNG_ENHANCED_PACKET_BLOCK => parse_enhanced_packet(
            body,
            state.endianness,
            &state.interfaces,
            state.interface_base,
            options.max_size,
        )?,
        PCAPNG_PACKET_BLOCK => parse_obsolete_packet(
            body,
            state.endianness,
            &state.interfaces,
            state.interface_base,
            options.max_size,
        )?,
        _ => parse_simple_packet(
            body,
            state.endianness,
            &state.interfaces,
            state.interface_base,
            options.max_size,
        )?,
    };
    let interface_id = match block_type {
        PCAPNG_SIMPLE_PACKET_BLOCK => 0,
        PCAPNG_PACKET_BLOCK => u32::from(decode_u16(state.endianness, &body[..2])?),
        _ => decode_u32(state.endianness, &body[..4])?,
    };
    let parsed_options = parse_options(
        packet_options(block_type, body, state.endianness)?,
        state.endianness,
        "pcapng packet options",
    )?;
    state.reset_metadata();
    Ok(record(
        RecordKind::Packet {
            block: match block_type {
                PCAPNG_ENHANCED_PACKET_BLOCK => PacketBlockKind::Enhanced,
                PCAPNG_PACKET_BLOCK => PacketBlockKind::Obsolete,
                _ => PacketBlockKind::Simple,
            },
            section: Some(state.section_index),
            interface_id: Some(interface_id),
            options: parsed_options,
        },
        Some(frame),
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
            let interface_id = decode_u32(state.endianness, &body[..4])?;
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

fn record(kind: RecordKind, frame: Option<Frame>, raw: Bytes) -> CaptureRecord {
    CaptureRecord {
        kind,
        frame,
        format: Format::PcapNg,
        raw,
    }
}
