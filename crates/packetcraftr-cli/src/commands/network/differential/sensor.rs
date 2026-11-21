// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::Path;

use bytes::Bytes;
use packetcraftr::differential as lib;
use packetcraftr_core::error::{Classification, Kind};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::headers::LinkHeader;

use crate::command_options::OfflineCaptureLimitsArgs;
use crate::errors::CliError;

pub(crate) struct SensorCapture {
    pub(crate) frames: u64,
    pub(crate) observations: Vec<lib::SensorObservation>,
}

pub(crate) fn read_sensor_capture(
    invocation: &crate::invocation::Invocation,
    path: &Path,
    limits: OfflineCaptureLimitsArgs,
) -> Result<SensorCapture, CliError> {
    let max_frames = limits.max_frames;
    let max_bytes = limits.max_bytes;
    let limits = limits.limits()?;
    let mut reader =
        crate::input::open_capture(&invocation.control, &invocation.output, path, limits)?;
    let mut frames = 0_u64;
    let mut bytes = 0_u64;
    let mut observations = Vec::new();
    let mut assembler = FragmentAssembler::default();
    while let Some(frame) = reader.next_frame().map_err(CliError::classified)? {
        frames = frames.checked_add(1).ok_or_else(|| {
            CliError::new(Kind::Internal, "sensor capture frame count overflowed")
        })?;
        bytes = bytes
            .checked_add(u64::try_from(frame.bytes().len()).unwrap_or(u64::MAX))
            .ok_or_else(|| CliError::new(Kind::Internal, "sensor capture byte count overflowed"))?;
        if frames > max_frames || bytes > max_bytes {
            return Err(CliError::from_classification(
                Classification::new(
                    packetcraftr_core::error::Code::CliCaptureLimit,
                    Kind::Usage,
                    Some("narrow the sensor capture or raise the capture limits"),
                ),
                format!("sensor capture exceeds its limits at {frames} frames and {bytes} bytes"),
                Vec::new(),
            ));
        }
        observations.extend(observations_from_frame(&frame, &mut assembler));
    }
    Ok(SensorCapture {
        frames,
        observations,
    })
}

fn observations_from_frame(
    frame: &Frame,
    assembler: &mut FragmentAssembler,
) -> Vec<lib::SensorObservation> {
    let Some((key, datagram)) = assembler.push(frame) else {
        return Vec::new();
    };
    let Some(payload) = udp_payload(&datagram) else {
        return Vec::new();
    };
    let Some(probe) = lib::canary::parse_probe(payload) else {
        return Vec::new();
    };
    vec![lib::SensorObservation {
        variant_index: probe.variant_index,
        attempt_seq: probe.attempt_seq,
        source: std::net::SocketAddr::new(
            std::net::IpAddr::V4(key.source),
            u16::from_be_bytes([datagram[0], datagram[1]]),
        ),
        destination: std::net::SocketAddr::new(
            std::net::IpAddr::V4(key.destination),
            u16::from_be_bytes([datagram[2], datagram[3]]),
        ),
        payload_sha256: lib::hex(&probe.payload_sha256),
    }]
}

fn udp_payload(datagram: &[u8]) -> Option<&[u8]> {
    if datagram.len() < 8 {
        return None;
    }
    let declared = usize::from(u16::from_be_bytes([datagram[4], datagram[5]]));
    let end = if declared >= 8 {
        declared.min(datagram.len())
    } else {
        datagram.len()
    };
    Some(&datagram[8..end])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FragmentKey {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    identification: u16,
}

#[derive(Default)]
struct Assembly {
    chunks: BTreeMap<usize, Bytes>,
    total: Option<usize>,
    contiguous: usize,
    stored: usize,
    last_seen: u64,
}

#[derive(Default)]
struct FragmentAssembler {
    assemblies: BTreeMap<FragmentKey, Assembly>,
    tick: u64,
}

const MAX_ASSEMBLIES: usize = 128;
const MAX_DATAGRAM_BYTES: usize = 65_535;

impl FragmentAssembler {
    fn push(&mut self, frame: &Frame) -> Option<(FragmentKey, Bytes)> {
        let piece = ipv4_piece(frame)?;
        if piece.payload.is_empty() {
            return None;
        }
        if piece.offset == 0 && !piece.more {
            return Some((piece.key, piece.payload));
        }
        self.tick = self.tick.saturating_add(1);
        if !self.assemblies.contains_key(&piece.key) && self.assemblies.len() >= MAX_ASSEMBLIES {
            let oldest = self
                .assemblies
                .iter()
                .min_by_key(|(_, assembly)| assembly.last_seen)
                .map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                self.assemblies.remove(&oldest);
            }
        }
        let tick = self.tick;
        let assembly = self.assemblies.entry(piece.key).or_default();
        assembly.last_seen = tick;
        let piece_end = piece.offset.saturating_add(piece.payload.len());
        if assembly
            .chunks
            .iter()
            .any(|(offset, chunk)| piece.offset < offset + chunk.len() && *offset < piece_end)
        {
            return None;
        }
        if assembly
            .total
            .is_some_and(|total| piece_end > total || (piece.more && piece_end == total))
        {
            return None;
        }
        if piece_end > MAX_DATAGRAM_BYTES
            || assembly.stored.saturating_add(piece.payload.len()) > MAX_DATAGRAM_BYTES
        {
            self.assemblies.remove(&piece.key);
            return None;
        }
        if !piece.more {
            if assembly
                .chunks
                .iter()
                .any(|(offset, chunk)| offset + chunk.len() > piece_end)
            {
                return None;
            }
            assembly.total = Some(piece_end);
        }
        assembly.stored += piece.payload.len();
        assembly.chunks.insert(piece.offset, piece.payload);
        while let Some(chunk) = assembly.chunks.get(&assembly.contiguous) {
            assembly.contiguous += chunk.len();
        }
        if assembly.total != Some(assembly.contiguous) {
            return None;
        }
        let assembly = self.assemblies.remove(&piece.key)?;
        let mut datagram = Vec::with_capacity(assembly.contiguous);
        for chunk in assembly.chunks.into_values() {
            datagram.extend_from_slice(&chunk);
        }
        Some((piece.key, Bytes::from(datagram)))
    }
}

struct FragmentPiece {
    key: FragmentKey,
    offset: usize,
    more: bool,
    payload: Bytes,
}

fn ip_offset(frame: &Frame) -> Option<usize> {
    let bytes = frame.bytes();
    if let Ok(Some(link)) = LinkHeader::walk(frame.link_type, bytes) {
        if matches!(link.announced_ip_version(), Some(6)) {
            return None;
        }
        return link.carries_ip().then(|| link.network_offset());
    }
    match frame.link_type {
        LinkType::LINUX_SLL => (bytes.len() >= 16
            && u16::from_be_bytes([bytes[14], bytes[15]]) == 0x0800)
            .then_some(16),
        _ => None,
    }
}

fn ipv4_piece(frame: &Frame) -> Option<FragmentPiece> {
    let offset = ip_offset(frame)?;
    let ip = frame.bytes().get(offset..)?;
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(ip[0] & 0x0f) * 4;
    if header_len < 20 || ip.len() < header_len || ip[9] != 17 {
        return None;
    }
    let declared = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    let end = if declared >= header_len {
        declared.min(ip.len())
    } else {
        ip.len()
    };
    let flags_fragment = u16::from_be_bytes([ip[6], ip[7]]);
    Some(FragmentPiece {
        key: FragmentKey {
            source: Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]),
            destination: Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]),
            protocol: ip[9],
            identification: u16::from_be_bytes([ip[4], ip[5]]),
        },
        offset: usize::from(flags_fragment & 0x1fff) * 8,
        more: flags_fragment & 0x2000 != 0,
        payload: Bytes::copy_from_slice(&ip[header_len..end]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip_frame(fragment_offset: u16, more: bool, chunk: &[u8]) -> Frame {
        ip_frame_id(7, fragment_offset, more, chunk)
    }

    fn ip_frame_id(identification: u16, fragment_offset: u16, more: bool, chunk: &[u8]) -> Frame {
        let total = 20 + chunk.len();
        let mut bytes = vec![0_u8; 14 + total];
        bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        let ip = &mut bytes[14..];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        ip[4..6].copy_from_slice(&identification.to_be_bytes());
        let field = (u16::from(more) << 13) | (fragment_offset / 8);
        ip[6..8].copy_from_slice(&field.to_be_bytes());
        ip[8] = 64;
        ip[9] = 17;
        ip[12..16].copy_from_slice(&[192, 0, 2, 1]);
        ip[16..20].copy_from_slice(&[198, 51, 100, 2]);
        ip[20..].copy_from_slice(chunk);
        Frame::new(None, LinkType::ETHERNET, bytes).unwrap()
    }

    fn tagged_ip_frame(tags: usize, chunk: &[u8]) -> Frame {
        let total = 20 + chunk.len();
        let link_len = 14 + tags * 4;
        let mut bytes = vec![0_u8; link_len + total];
        bytes[12..14].copy_from_slice(&0x8100_u16.to_be_bytes());
        for tag in 0..tags {
            let tci = 14 + tag * 4;
            bytes[tci..tci + 2].copy_from_slice(&((tag as u16) + 1).to_be_bytes());
            let next: u16 = if tag + 1 == tags { 0x0800 } else { 0x8100 };
            bytes[tci + 2..tci + 4].copy_from_slice(&next.to_be_bytes());
        }
        let ip = &mut bytes[link_len..];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        ip[4..6].copy_from_slice(&7_u16.to_be_bytes());
        ip[8] = 64;
        ip[9] = 17;
        ip[12..16].copy_from_slice(&[192, 0, 2, 1]);
        ip[16..20].copy_from_slice(&[198, 51, 100, 2]);
        ip[20..].copy_from_slice(chunk);
        Frame::new(None, LinkType::ETHERNET, bytes).unwrap()
    }

    fn udp_datagram(payload: &[u8]) -> Vec<u8> {
        let mut datagram = Vec::new();
        datagram.extend_from_slice(&53210_u16.to_be_bytes());
        datagram.extend_from_slice(&40101_u16.to_be_bytes());
        datagram.extend_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
        datagram.extend_from_slice(&[0, 0]);
        datagram.extend_from_slice(payload);
        datagram
    }

    #[test]
    fn reassembles_fragmented_canary_probes() {
        let probe = lib::canary::build_probe(&[7_u8; lib::canary::TOKEN_LEN], 3, 9, 96);
        let datagram = udp_datagram(&probe);
        let mut assembler = FragmentAssembler::default();
        let first = ip_frame(0, true, &datagram[..24]);
        let second = ip_frame(24, false, &datagram[24..]);
        assert!(observations_from_frame(&second, &mut assembler).is_empty());
        let observations = observations_from_frame(&first, &mut assembler);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].variant_index, 3);
        assert_eq!(observations[0].attempt_seq, 9);
        assert_eq!(observations[0].source.to_string(), "192.0.2.1:53210");
        assert_eq!(
            observations[0].destination.to_string(),
            "198.51.100.2:40101"
        );
        assert_eq!(
            observations[0].payload_sha256,
            lib::hex(&lib::canary::payload_sha256(&probe))
        );
    }

    #[test]
    fn observations_survive_deeper_vlan_stacks() {
        let probe = lib::canary::build_probe(&[7_u8; lib::canary::TOKEN_LEN], 4, 11, 96);
        let frame = tagged_ip_frame(5, &udp_datagram(&probe));
        let observations = observations_from_frame(&frame, &mut FragmentAssembler::default());
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].variant_index, 4);
        assert_eq!(observations[0].attempt_seq, 11);
    }

    #[test]
    fn overlapping_fragments_do_not_corrupt_valid_assembly() {
        let probe = lib::canary::build_probe(&[7_u8; lib::canary::TOKEN_LEN], 3, 9, 96);
        let datagram = udp_datagram(&probe);
        let mut assembler = FragmentAssembler::default();
        let first = ip_frame(0, true, &datagram[..24]);
        let overlap = ip_frame(16, true, &[0_u8; 16]);
        let second = ip_frame(24, false, &datagram[24..]);
        assert!(observations_from_frame(&first, &mut assembler).is_empty());
        assert!(observations_from_frame(&overlap, &mut assembler).is_empty());
        let observations = observations_from_frame(&second, &mut assembler);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].variant_index, 3);
        assert_eq!(observations[0].attempt_seq, 9);
    }

    #[test]
    fn stale_fragment_assemblies_are_evicted_for_new_flows() {
        let mut assembler = FragmentAssembler::default();
        for id in 0..MAX_ASSEMBLIES as u16 {
            let frame = ip_frame_id(id, 0, true, &[0_u8; 8]);
            assert!(observations_from_frame(&frame, &mut assembler).is_empty());
        }
        let probe = lib::canary::build_probe(&[7_u8; lib::canary::TOKEN_LEN], 3, 9, 96);
        let datagram = udp_datagram(&probe);
        let first = ip_frame_id(999, 0, true, &datagram[..24]);
        let second = ip_frame_id(999, 24, false, &datagram[24..]);
        assert!(observations_from_frame(&first, &mut assembler).is_empty());
        let observations = observations_from_frame(&second, &mut assembler);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].variant_index, 3);
    }

    #[test]
    fn tampered_datagrams_are_not_observations() {
        let mut probe = lib::canary::build_probe(&[7_u8; lib::canary::TOKEN_LEN], 1, 2, 96);
        probe[40] ^= 0xFF;
        let frame = ip_frame(0, false, &udp_datagram(&probe));
        assert!(observations_from_frame(&frame, &mut FragmentAssembler::default()).is_empty());
    }
}
