// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::frame::Frame;
use bytes::Bytes;

use super::PcapNgState;
use super::framing::{FramedBlock, packet_block_kind};
use crate::capture_file::pcapng::{
    interface::parse_interface_description,
    packet::{PacketRead, parse_simple_packet, parse_timestamped_packet},
};
use crate::capture_file::{
    error::Error,
    format::Format,
    header::Interface,
    limits::ReaderLimits,
    record::{CaptureRecord, MetadataBlockKind, PacketBlockKind, RecordKind},
    wire::{
        PCAPNG_CUSTOM_BLOCK, PCAPNG_CUSTOM_BLOCK_NO_COPY, PCAPNG_INTERFACE_DESCRIPTION_BLOCK,
        PCAPNG_INTERFACE_STATISTICS_BLOCK, PCAPNG_NAME_RESOLUTION_BLOCK, decode_u32,
    },
};

pub(super) fn decode(
    block: FramedBlock,
    state: &mut PcapNgState,
    all_interfaces: &mut Vec<Interface>,
    limits: &ReaderLimits,
    read: PacketRead,
) -> Result<CaptureRecord, Error> {
    match block.block_type {
        PCAPNG_INTERFACE_DESCRIPTION_BLOCK => {
            decode_interface(&block.body, block.raw, state, all_interfaces, limits)
        }
        block_type => match packet_block_kind(block_type) {
            Some(kind) => decode_packet(
                kind,
                &block.body,
                block.raw,
                state,
                all_interfaces,
                limits,
                read,
            ),
            None => decode_metadata(block_type, &block.body, block.raw, state, all_interfaces),
        },
    }
}

fn decode_interface(
    body: &[u8],
    raw: Bytes,
    state: &PcapNgState,
    all_interfaces: &mut Vec<Interface>,
    limits: &ReaderLimits,
) -> Result<CaptureRecord, Error> {
    let (description, options) =
        parse_interface_description(body, state.endianness, limits.max_options_per_block)?;
    let local_id = u32::try_from(state.section_interfaces(all_interfaces).len()).map_err(|_| {
        Error::InterfaceLimit {
            limit: limits.max_interfaces_per_section,
        }
    })?;
    let global_id = state.add_interface(all_interfaces, description.clone(), limits)?;
    Ok(record(
        RecordKind::Metadata(MetadataBlockKind::InterfaceDescription {
            section: state.section_index,
            local_id,
            global_id,
            interface: description,
            options,
        }),
        None,
        raw,
    ))
}

fn decode_packet(
    kind: PacketBlockKind,
    body: &Bytes,
    raw: Bytes,
    state: &mut PcapNgState,
    all_interfaces: &[Interface],
    limits: &ReaderLimits,
    read: PacketRead,
) -> Result<CaptureRecord, Error> {
    let interfaces = state.section_interfaces(all_interfaces);
    let parsed = match kind {
        PacketBlockKind::Enhanced | PacketBlockKind::Obsolete => parse_timestamped_packet(
            body,
            state.endianness,
            interfaces,
            state.interface_base,
            limits,
            kind == PacketBlockKind::Obsolete,
            read,
        ),
        // A classic-PCAP record never reaches this decoder.
        PacketBlockKind::Simple | PacketBlockKind::Classic => parse_simple_packet(
            body,
            state.endianness,
            interfaces,
            state.interface_base,
            limits.max_size,
        ),
    }?;
    state.reset_metadata();
    Ok(CaptureRecord {
        kind: RecordKind::Packet {
            block: kind,
            section: Some(state.section_index),
            interface_id: Some(parsed.interface_id),
            options: parsed.options,
        },
        frame: Some(parsed.frame),
        packet_declares_fcs: parsed.declares_fcs,
        format: Format::PcapNg,
        raw,
    })
}

fn decode_metadata(
    block_type: u32,
    body: &[u8],
    raw: Bytes,
    state: &PcapNgState,
    all_interfaces: &[Interface],
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
            let available = state.section_interfaces(all_interfaces).len();
            if interface_id as usize >= available {
                return Err(Error::UndefinedInterface {
                    interface: interface_id,
                    available,
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
        packet_declares_fcs: false,
        format: Format::PcapNg,
        raw,
    }
}
