// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Range;
use std::path::PathBuf;

use clap::Args;
use packetcraftr_core::capture_file;
use packetcraftr_core::decode::Dissector;
use packetcraftr_core::error::Kind;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::headers::{Ipv4Header, Ipv6Header, LinkHeader};
use packetcraftr_core::protocol::identity;
use packetcraftr_core::protocol::network::ip_protocol;
use packetcraftr_core::transform::{self, HeaderRewrite, RewriteLimits};

use crate::command_options::{DecodeArgs, OfflineCaptureLimitsArgs};
use crate::commands::{CommandExit, Generate};
use crate::errors::CliError;
use crate::output::contract::Format;
use crate::terminal::emit_stdout_document;

pub(crate) const AFTER_LONG_HELP: &str = r"Write a share-oriented PCAPNG copy with consistently pseudonymized outer Ethernet and IP addresses. IPv4 pseudonyms are sequential private addresses starting at 10.0.0.1, IPv6 pseudonyms are in 2001:db8::/32, and MAC pseudonyms are locally administered. Unspecified, loopback, multicast, and broadcast addresses are preserved. PCAPNG interface option metadata is dropped and frames whose outer IP header carries embedded addresses scrub cannot rewrite are refused. Protocol payloads are retained unless --truncate caps captured bytes per frame, so review payload disclosures separately before sharing. Existing destinations are refused.

Example:
  packetcraftr analyze scrub capture.pcapng --write scrubbed.pcapng --truncate 128";

#[derive(Debug, Args)]
pub(crate) struct Scrub {
    /// Input PCAP or PCAPNG path; - reads redirected stdin.
    path: PathBuf,
    /// New output PCAPNG path.
    #[arg(long)]
    write: PathBuf,
    /// Keep at most this many captured bytes of each scrubbed frame.
    #[arg(long, value_name = "BYTES", value_parser = clap::value_parser!(u64).range(1..))]
    truncate: Option<u64>,
    #[command(flatten)]
    decode: DecodeArgs,
    #[command(flatten)]
    limits: OfflineCaptureLimitsArgs,
}

#[derive(Default)]
struct Pseudonyms {
    ips: BTreeMap<IpAddr, IpAddr>,
    macs: BTreeMap<[u8; 6], [u8; 6]>,
}

fn preserved_ip(address: IpAddr) -> bool {
    address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || matches!(address, IpAddr::V4(v4) if v4.is_broadcast())
}

impl Pseudonyms {
    fn ip(&mut self, address: IpAddr) -> IpAddr {
        if preserved_ip(address) {
            return address;
        }
        if let Some(mapped) = self.ips.get(&address) {
            return *mapped;
        }
        let sequence = self.ips.len() as u32 + 1;
        let mapped = match address {
            IpAddr::V4(_) => {
                let octets = (0x0A00_0000_u32 + sequence).to_be_bytes();
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            IpAddr::V6(_) => {
                let mut octets =
                    Ipv6Addr::from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
                        .octets();
                octets[12..].copy_from_slice(&sequence.to_be_bytes());
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        };
        self.ips.insert(address, mapped);
        mapped
    }

    fn mac(&mut self, address: [u8; 6]) -> [u8; 6] {
        if address == [0; 6] || address[0] & 1 == 1 {
            return address;
        }
        if let Some(mapped) = self.macs.get(&address) {
            return *mapped;
        }
        let sequence = self.macs.len() as u32 + 1;
        let seq = sequence.to_be_bytes();
        let mapped = [0x02, 0x00, 0x00, seq[1], seq[2], seq[3]];
        self.macs.insert(address, mapped);
        mapped
    }
}

impl Generate for Scrub {
    fn generate(
        self,
        invocation: &crate::invocation::Invocation,
        format: Format,
    ) -> Result<CommandExit, CliError> {
        if format != Format::Text {
            return Err(CliError::new(
                Kind::Usage,
                format!("scrub prints text only, not --output {format}"),
            ));
        }
        if self.path == self.write {
            return Err(CliError::new(
                Kind::Usage,
                "--write must not name the input capture",
            ));
        }
        let capture_limits = self.limits.limits()?;
        let registry = self.decode.registry()?;
        let mut staged = crate::staged_output::StagedFile::stage(invocation, &self.write)?;
        let mut reader = crate::input::open_capture(
            &invocation.control,
            &invocation.output,
            &self.path,
            capture_limits,
        )?;
        let limits = capture_file::Limits {
            max_frames: capture_limits.max_frames(),
            max_bytes: capture_limits.max_bytes(),
        };
        let inner: Box<dyn std::io::Write> = Box::new(std::io::BufWriter::with_capacity(
            64 * 1024,
            staged.as_file_mut(),
        ));
        let mut writer = capture_file::Writer::pcapng_with_options(
            inner,
            capture_file::PcapNgOptions {
                max_size: capture_limits.reader_bounds().max_frame_bytes,
                max_interfaces: capture_file::DEFAULT_MAX_TOTAL_INTERFACES,
                stream_limits: limits,
                ..Default::default()
            },
        )
        .map_err(CliError::classified)?;
        let dissector = Dissector::new(registry);
        let mut pseudonyms = Pseudonyms::default();
        let report = capture_file::map_frames_with_interface_options(
            &mut reader,
            &mut writer,
            limits,
            0,
            |_, frame| {
                scrub_frame(
                    frame,
                    &dissector,
                    &mut pseudonyms,
                    capture_limits.reader_bounds().max_frame_bytes,
                )
                .map(|mut frame| {
                    if let Some(limit) = self.truncate {
                        frame = frame.truncated(limit as usize);
                    }
                    frame
                })
                .map_err(CliError::into_boundary_error)
            },
            |_, options| scrub_interface_options(options),
        )
        .map_err(CliError::classified)?;
        writer
            .into_inner()
            .flush()
            .map_err(|error| CliError::caused(Kind::Io, &error))?;
        staged.sync()?;
        staged.persist()?;
        emit_stdout_document(
            invocation,
            &format!(
                "frames={} mapped_ips={} mapped_macs={} payloads={} output={}\n",
                report.frames_read,
                pseudonyms.ips.len(),
                pseudonyms.macs.len(),
                match self.truncate {
                    Some(limit) => format!("truncated_to={limit}"),
                    None => "retained".to_owned(),
                },
                self.write.display(),
            ),
        )?;
        Ok(CommandExit::SUCCESS)
    }
}

fn scrub_interface_options(
    _options: Vec<capture_file::PcapNgOption>,
) -> Vec<capture_file::PcapNgOption> {
    Vec::new()
}

enum LinkPatch {
    Ip(usize),
    LinkOnly,
}

fn outer_ip(frame: &Frame) -> Option<&[u8]> {
    let link = LinkHeader::walk(frame.link_type, frame.bytes()).ok()??;
    link.carries_ip()
        .then(|| frame.bytes().get(link.network_offset()..))
        .flatten()
}

fn outer_ip_addresses(frame: &Frame) -> Option<(IpAddr, IpAddr)> {
    let link = LinkHeader::walk(frame.link_type, frame.bytes()).ok()??;
    let header = link.walk_ip(frame.bytes()).ok()??;
    header
        .addresses(frame.bytes().get(link.network_offset()..)?)
        .ok()
}

fn embedded_outer_addresses(ip: &[u8]) -> bool {
    match ip.first().map(|byte| byte >> 4) {
        Some(4) => match Ipv4Header::walk_prefix(ip) {
            Ok(header) => header.options(ip).any(|option| match option {
                Ok(option) if option.kind == 68 => ip
                    .get(option.range.start + 3)
                    .is_some_and(|flags| flags & 0x0f != 0),
                Ok(option) => matches!(option.kind, 7 | 131 | 137),
                Err(_) => header.header_length() > Ipv4Header::MIN_LENGTH,
            }),
            Err(_) => ip.len() >= 24 && usize::from(ip[0] & 0x0f) * 4 > Ipv4Header::MIN_LENGTH,
        },
        Some(6) => match Ipv6Header::walk_prefix(ip) {
            Ok(header) => header.extensions().iter().any(|extension| {
                extension.protocol() == ip_protocol::ROUTING
                    || extension
                        .options(ip)
                        .any(|option| matches!(option, Ok(option) if option.kind == 201))
            }),
            Err(_) => {
                ip.len() >= Ipv6Header::LENGTH
                    && matches!(
                        ip[6],
                        ip_protocol::HOP_BY_HOP
                            | ip_protocol::ROUTING
                            | ip_protocol::DESTINATION_OPTIONS
                    )
            }
        },
        _ => false,
    }
}

fn scrub_frame(
    frame: &Frame,
    dissector: &Dissector,
    pseudonyms: &mut Pseudonyms,
    max_output_bytes: usize,
) -> Result<Frame, CliError> {
    if outer_ip(frame).is_some_and(embedded_outer_addresses) {
        return Err(CliError::new(
            Kind::Policy,
            "scrub refuses an outer IP header with embedded addresses it cannot pseudonymize",
        ));
    }
    let decoded = match dissector
        .decode(frame.clone(), packetcraftr_core::decode::Options::default())
    {
        Ok(decoded) => decoded,
        Err(error) => {
            return fallback_patch(frame, pseudonyms).ok_or_else(|| CliError::classified(error));
        }
    };
    let mut patch = HeaderRewrite::default();
    if frame.link_type == LinkType::ETHERNET
        && let Some((source, destination)) =
            decoded.packet.iter().find_map(identity::link_addresses)
    {
        patch.source_mac = Some(pseudonyms.mac(source));
        patch.destination_mac = Some(pseudonyms.mac(destination));
    }
    if let Some((source, destination)) = outer_ip_addresses(frame) {
        patch.source_ip = Some(pseudonyms.ip(source));
        patch.destination_ip = Some(pseudonyms.ip(destination));
    }
    if patch.is_empty() {
        if let Some(patched) = fallback_patch(frame, pseudonyms) {
            return Ok(patched);
        }
        if decoded
            .packet
            .iter()
            .find_map(identity::network_endpoints)
            .is_some()
        {
            return Err(CliError::new(
                Kind::Policy,
                "scrub cannot pseudonymize IP addresses on this link type",
            ));
        }
        return Ok(frame.clone());
    }
    match transform::rewrite(frame, &patch, RewriteLimits { max_output_bytes }) {
        Ok(frame) => Ok(frame),
        Err(error) => fallback_patch(frame, pseudonyms).ok_or_else(|| CliError::classified(error)),
    }
}

fn fallback_patch(frame: &Frame, pseudonyms: &mut Pseudonyms) -> Option<Frame> {
    let finish = |bytes: Vec<u8>| {
        let mut patched = Frame::try_with_optional_timestamp(
            frame.timestamp,
            frame.link_type,
            packetcraftr_core::frame::Lengths {
                captured: frame.captured_length(),
                original: frame.original_length(),
            },
            bytes,
        )
        .ok()?;
        patched.interface = frame.interface;
        patched.direction = frame.direction;
        Some(patched)
    };
    let mut bytes = frame.bytes().to_vec();
    let ip_offset = match patch_link_bytes(&mut bytes, frame.link_type, pseudonyms)? {
        LinkPatch::Ip(offset) => offset,
        LinkPatch::LinkOnly => return finish(bytes),
    };
    if embedded_outer_addresses(bytes.get(ip_offset..)?) {
        return None;
    }
    let ip = bytes.get_mut(ip_offset..)?;
    match ip.first().map(|byte| byte >> 4) {
        Some(4) if ip.len() >= 20 => {
            let source = IpAddr::from(<[u8; 4]>::try_from(&ip[12..16]).ok()?);
            let destination = IpAddr::from(<[u8; 4]>::try_from(&ip[16..20]).ok()?);
            let mapped_source = pseudonyms.ip(source);
            let mapped_destination = pseudonyms.ip(destination);
            ip[12..16].copy_from_slice(&ipv4_bytes(mapped_source));
            ip[16..20].copy_from_slice(&ipv4_bytes(mapped_destination));
            adjust_transport_checksum(
                ip,
                (source, destination),
                (mapped_source, mapped_destination),
            );
            let header_len = usize::from(ip[0] & 0x0f) * 4;
            if header_len >= 20 && ip.len() >= header_len {
                ip[10] = 0;
                ip[11] = 0;
                let checksum = packetcraftr_core::protocol::checksum_parts(&[&ip[..header_len]]);
                ip[10..12].copy_from_slice(&checksum.to_be_bytes());
            }
        }
        Some(6) if ip.len() >= 40 => {
            let source = IpAddr::from(<[u8; 16]>::try_from(&ip[8..24]).ok()?);
            let destination = IpAddr::from(<[u8; 16]>::try_from(&ip[24..40]).ok()?);
            let mapped_source = pseudonyms.ip(source);
            let mapped_destination = pseudonyms.ip(destination);
            ip[8..24].copy_from_slice(&ipv6_bytes(mapped_source));
            ip[24..40].copy_from_slice(&ipv6_bytes(mapped_destination));
            adjust_transport_checksum(
                ip,
                (source, destination),
                (mapped_source, mapped_destination),
            );
        }
        _ => return None,
    }
    finish(bytes)
}

fn transport_checksum_field(ip: &[u8]) -> Option<(u8, Range<usize>)> {
    match ip.first().map(|byte| byte >> 4) {
        Some(4) => {
            let header = Ipv4Header::walk_prefix(ip).ok()?;
            if header
                .options(ip)
                .any(|option| matches!(option, Ok(option) if matches!(option.kind, 131 | 137)))
            {
                return None;
            }
            let checksum_offset: usize = match header.protocol() {
                ip_protocol::TCP => 16,
                ip_protocol::UDP => 6,
                _ => return None,
            };
            let fragment_offset = usize::from(header.flags_and_offset() & 0x1fff) * 8;
            let start = header
                .header_length()
                .checked_add(checksum_offset.checked_sub(fragment_offset)?)?;
            let field = start..start.checked_add(2)?;
            (field.end <= header.total_length() && field.end <= ip.len())
                .then_some((header.protocol(), field))
        }
        Some(6) => {
            let header = Ipv6Header::walk_prefix(ip).ok()?;
            if header.extensions().iter().any(|extension| {
                extension.protocol() == ip_protocol::ROUTING
                    || extension
                        .fragment_offset()
                        .is_some_and(|offset| offset != 0)
            }) {
                return None;
            }
            let (protocol, upper_layer_offset) = header.upper_layer();
            let checksum_offset: usize = match protocol {
                ip_protocol::TCP => 16,
                ip_protocol::UDP => 6,
                ip_protocol::ICMPV6 => 2,
                _ => return None,
            };
            let start = upper_layer_offset.checked_add(checksum_offset)?;
            let field = start..start.checked_add(2)?;
            (field.end <= header.datagram_length() && field.end <= ip.len())
                .then_some((protocol, field))
        }
        _ => None,
    }
}

fn ones_complement_add(left: u16, right: u16) -> u16 {
    let sum = u32::from(left) + u32::from(right);
    ((sum & 0xffff) + (sum >> 16)) as u16
}

fn adjusted_checksum(current: u16, old: (IpAddr, IpAddr), new: (IpAddr, IpAddr)) -> Option<u16> {
    let (old_bytes, new_bytes) = match (old, new) {
        (
            (IpAddr::V4(old_source), IpAddr::V4(old_destination)),
            (IpAddr::V4(new_source), IpAddr::V4(new_destination)),
        ) => {
            let mut old_bytes = old_source.octets().to_vec();
            old_bytes.extend_from_slice(&old_destination.octets());
            let mut new_bytes = new_source.octets().to_vec();
            new_bytes.extend_from_slice(&new_destination.octets());
            (old_bytes, new_bytes)
        }
        (
            (IpAddr::V6(old_source), IpAddr::V6(old_destination)),
            (IpAddr::V6(new_source), IpAddr::V6(new_destination)),
        ) => {
            let mut old_bytes = old_source.octets().to_vec();
            old_bytes.extend_from_slice(&old_destination.octets());
            let mut new_bytes = new_source.octets().to_vec();
            new_bytes.extend_from_slice(&new_destination.octets());
            (old_bytes, new_bytes)
        }
        _ => return None,
    };
    let mut accumulator = !current;
    for (old_word, new_word) in old_bytes
        .as_chunks::<2>()
        .0
        .iter()
        .zip(new_bytes.as_chunks::<2>().0.iter())
    {
        accumulator = ones_complement_add(accumulator, !u16::from_be_bytes(*old_word));
        accumulator = ones_complement_add(accumulator, u16::from_be_bytes(*new_word));
    }
    Some(!accumulator)
}

fn adjust_transport_checksum(ip: &mut [u8], old: (IpAddr, IpAddr), new: (IpAddr, IpAddr)) {
    if old == new {
        return;
    }
    let Some((protocol, field)) = transport_checksum_field(ip) else {
        return;
    };
    let current = u16::from_be_bytes([ip[field.start], ip[field.start + 1]]);
    if protocol == ip_protocol::UDP && current == 0 {
        return;
    }
    let Some(updated) = adjusted_checksum(current, old, new) else {
        return;
    };
    let updated = if protocol == ip_protocol::UDP && updated == 0 {
        0xffff
    } else {
        updated
    };
    ip[field].copy_from_slice(&updated.to_be_bytes());
}

fn ipv4_bytes(address: IpAddr) -> [u8; 4] {
    match address {
        IpAddr::V4(address) => address.octets(),
        IpAddr::V6(_) => [0; 4],
    }
}

fn ipv6_bytes(address: IpAddr) -> [u8; 16] {
    match address {
        IpAddr::V6(address) => address.octets(),
        IpAddr::V4(_) => [0; 16],
    }
}

fn patch_link_bytes(
    bytes: &mut [u8],
    link_type: LinkType,
    pseudonyms: &mut Pseudonyms,
) -> Option<LinkPatch> {
    if link_type.is_raw_ip() {
        return Some(LinkPatch::Ip(0));
    }
    match link_type {
        LinkType::ETHERNET => {
            let link = LinkHeader::walk(link_type, bytes).ok()??;
            if bytes.len() >= 14 {
                let destination = <[u8; 6]>::try_from(&bytes[0..6]).ok()?;
                let source = <[u8; 6]>::try_from(&bytes[6..12]).ok()?;
                bytes[0..6].copy_from_slice(&pseudonyms.mac(destination));
                bytes[6..12].copy_from_slice(&pseudonyms.mac(source));
            }
            if link.carries_ip() {
                Some(LinkPatch::Ip(link.network_offset()))
            } else {
                Some(LinkPatch::LinkOnly)
            }
        }
        LinkType::LINUX_SLL => {
            if bytes.len() < 16
                || !matches!(u16::from_be_bytes([bytes[14], bytes[15]]), 0x0800 | 0x86dd)
            {
                return None;
            }
            let address_len = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
            if address_len >= 6 && bytes.len() >= 12 {
                let source = <[u8; 6]>::try_from(&bytes[6..12]).ok()?;
                bytes[6..12].copy_from_slice(&pseudonyms.mac(source));
            }
            Some(LinkPatch::Ip(16))
        }
        LinkType::LINUX_SLL2 => {
            if bytes.len() < 20
                || !matches!(u16::from_be_bytes([bytes[0], bytes[1]]), 0x0800 | 0x86dd)
            {
                return None;
            }
            if usize::from(bytes[11]) >= 6 && bytes.len() >= 18 {
                let source = <[u8; 6]>::try_from(&bytes[12..18]).ok()?;
                bytes[12..18].copy_from_slice(&pseudonyms.mac(source));
                bytes[18..20].fill(0);
            }
            Some(LinkPatch::Ip(20))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::protocol::checksum_parts;

    const V4_SOURCE: [u8; 4] = [198, 51, 100, 9];
    const V4_DESTINATION: [u8; 4] = [203, 0, 113, 7];
    const V6_SOURCE: [u8; 16] = [0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
    const V6_DESTINATION: [u8; 16] = [0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];

    fn transport_checksum(
        source: IpAddr,
        destination: IpAddr,
        protocol: u8,
        segment: &[u8],
    ) -> u16 {
        let mut pseudo = Vec::new();
        match (source, destination) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                pseudo.extend_from_slice(&source.octets());
                pseudo.extend_from_slice(&destination.octets());
                pseudo.extend_from_slice(&[0, protocol]);
                pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                pseudo.extend_from_slice(&source.octets());
                pseudo.extend_from_slice(&destination.octets());
                pseudo.extend_from_slice(&(segment.len() as u32).to_be_bytes());
                pseudo.extend_from_slice(&[0, 0, 0, protocol]);
            }
            _ => unreachable!(),
        }
        checksum_parts(&[&pseudo, segment])
    }

    fn udp_segment(source: IpAddr, destination: IpAddr, payload: &[u8]) -> Vec<u8> {
        let mut segment = Vec::with_capacity(8 + payload.len());
        segment.extend_from_slice(&12_345_u16.to_be_bytes());
        segment.extend_from_slice(&53_u16.to_be_bytes());
        segment.extend_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
        segment.extend_from_slice(&[0, 0]);
        segment.extend_from_slice(payload);
        let checksum = transport_checksum(source, destination, 17, &segment);
        segment[6..8]
            .copy_from_slice(&(if checksum == 0 { 0xffff } else { checksum }).to_be_bytes());
        segment
    }

    fn tcp_segment(source: IpAddr, destination: IpAddr, payload: &[u8]) -> Vec<u8> {
        let mut segment = vec![0_u8; 20];
        segment[0..2].copy_from_slice(&12_345_u16.to_be_bytes());
        segment[2..4].copy_from_slice(&443_u16.to_be_bytes());
        segment[12] = 0x50;
        segment[13] = 0x18;
        segment[14..16].copy_from_slice(&4096_u16.to_be_bytes());
        segment.extend_from_slice(payload);
        let checksum = transport_checksum(source, destination, 6, &segment);
        segment[16..18].copy_from_slice(&checksum.to_be_bytes());
        segment
    }

    fn ipv4_frame(protocol: u8, chunk: &[u8], flags_and_offset: u16) -> Frame {
        let total = 20 + chunk.len();
        let mut bytes = vec![0_u8; total];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        bytes[4..6].copy_from_slice(&7_u16.to_be_bytes());
        bytes[6..8].copy_from_slice(&flags_and_offset.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = protocol;
        bytes[12..16].copy_from_slice(&V4_SOURCE);
        bytes[16..20].copy_from_slice(&V4_DESTINATION);
        let checksum = checksum_parts(&[&bytes[..20]]);
        bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
        bytes[20..].copy_from_slice(chunk);
        Frame::new(None, LinkType::RAW, bytes).unwrap()
    }

    fn ipv4_option_frame(kind: u8, segment: &[u8]) -> Frame {
        let total = 28 + segment.len();
        let mut bytes = vec![0_u8; total];
        bytes[0] = 0x47;
        bytes[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&V4_SOURCE);
        bytes[16..20].copy_from_slice(&V4_DESTINATION);
        bytes[20] = kind;
        bytes[21] = 7;
        bytes[22] = 4;
        bytes[23..27].copy_from_slice(&V4_SOURCE);
        let checksum = checksum_parts(&[&bytes[..28]]);
        bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
        bytes[28..].copy_from_slice(segment);
        Frame::new(None, LinkType::RAW, bytes).unwrap()
    }

    fn ipv4_addresses(ip: &[u8]) -> (IpAddr, IpAddr) {
        (
            IpAddr::from(<[u8; 4]>::try_from(&ip[12..16]).unwrap()),
            IpAddr::from(<[u8; 4]>::try_from(&ip[16..20]).unwrap()),
        )
    }

    fn assert_ipv4_header_checksum(ip: &[u8]) {
        assert_eq!(checksum_parts(&[&ip[..20]]), 0);
    }

    #[test]
    fn fallback_rewrites_keep_valid_ipv4_and_transport_checksums() {
        let source = IpAddr::from(V4_SOURCE);
        let destination = IpAddr::from(V4_DESTINATION);
        for (protocol, segment) in [
            (17_u8, udp_segment(source, destination, b"purple-team")),
            (6_u8, tcp_segment(source, destination, b"purple-team")),
        ] {
            let frame = ipv4_frame(protocol, &segment, 0);
            let patched = fallback_patch(&frame, &mut Pseudonyms::default()).unwrap();
            let ip = patched.bytes();
            assert_ipv4_header_checksum(ip);
            let (mapped_source, mapped_destination) = ipv4_addresses(ip);
            assert_ne!(mapped_source, source);
            assert_ne!(mapped_destination, destination);
            assert_eq!(
                transport_checksum(mapped_source, mapped_destination, protocol, &ip[20..]),
                0
            );
        }
    }

    #[test]
    fn fallback_adjusts_udp_checksum_from_the_first_fragment_only() {
        let segment = udp_segment(
            IpAddr::from(V4_SOURCE),
            IpAddr::from(V4_DESTINATION),
            &[7_u8; 24],
        );
        let frame = ipv4_frame(17, &segment[..16], 0x2000);
        let patched = fallback_patch(&frame, &mut Pseudonyms::default()).unwrap();
        let ip = patched.bytes();
        assert_ipv4_header_checksum(ip);
        let mut reassembled = ip[20..].to_vec();
        reassembled.extend_from_slice(&segment[16..]);
        let (source, destination) = ipv4_addresses(ip);
        assert_eq!(transport_checksum(source, destination, 17, &reassembled), 0);
    }

    #[test]
    fn fallback_adjusts_tcp_checksum_carried_by_a_later_fragment() {
        let segment = tcp_segment(
            IpAddr::from(V4_SOURCE),
            IpAddr::from(V4_DESTINATION),
            &[9_u8; 12],
        );
        let mut names = Pseudonyms::default();
        let first = fallback_patch(&ipv4_frame(6, &segment[..8], 0x2000), &mut names).unwrap();
        let second = fallback_patch(&ipv4_frame(6, &segment[8..], 1), &mut names).unwrap();
        assert_ipv4_header_checksum(first.bytes());
        assert_ipv4_header_checksum(second.bytes());
        let mut reassembled = first.bytes()[20..].to_vec();
        reassembled.extend_from_slice(&second.bytes()[20..]);
        let (source, destination) = ipv4_addresses(second.bytes());
        assert_eq!(transport_checksum(source, destination, 6, &reassembled), 0);
    }

    #[test]
    fn fallback_rewrites_keep_valid_ipv6_transport_checksums() {
        let source = IpAddr::from(V6_SOURCE);
        let destination = IpAddr::from(V6_DESTINATION);
        let segment = udp_segment(source, destination, &[5_u8; 24]);

        let mut plain = vec![0_u8; 40 + segment.len()];
        plain[0] = 0x60;
        plain[4..6].copy_from_slice(&(segment.len() as u16).to_be_bytes());
        plain[6] = 17;
        plain[7] = 64;
        plain[8..24].copy_from_slice(&V6_SOURCE);
        plain[24..40].copy_from_slice(&V6_DESTINATION);
        plain[40..].copy_from_slice(&segment);
        let patched = fallback_patch(
            &Frame::new(None, LinkType::RAW, plain).unwrap(),
            &mut Pseudonyms::default(),
        )
        .unwrap();
        let ip = patched.bytes();
        let (mapped_source, mapped_destination) = (
            IpAddr::from(<[u8; 16]>::try_from(&ip[8..24]).unwrap()),
            IpAddr::from(<[u8; 16]>::try_from(&ip[24..40]).unwrap()),
        );
        assert_eq!(
            transport_checksum(mapped_source, mapped_destination, 17, &ip[40..]),
            0
        );

        let first_chunk = &segment[..16];
        let mut fragmented = vec![0_u8; 48 + first_chunk.len()];
        fragmented[0] = 0x60;
        fragmented[4..6].copy_from_slice(&((8 + first_chunk.len()) as u16).to_be_bytes());
        fragmented[6] = 44;
        fragmented[7] = 64;
        fragmented[8..24].copy_from_slice(&V6_SOURCE);
        fragmented[24..40].copy_from_slice(&V6_DESTINATION);
        fragmented[40] = 17;
        fragmented[43] = 1;
        fragmented[44..48].copy_from_slice(&7_u32.to_be_bytes());
        fragmented[48..].copy_from_slice(first_chunk);
        let patched = fallback_patch(
            &Frame::new(None, LinkType::RAW, fragmented).unwrap(),
            &mut Pseudonyms::default(),
        )
        .unwrap();
        let ip = patched.bytes();
        let mut reassembled = ip[48..].to_vec();
        reassembled.extend_from_slice(&segment[16..]);
        let (mapped_source, mapped_destination) = (
            IpAddr::from(<[u8; 16]>::try_from(&ip[8..24]).unwrap()),
            IpAddr::from(<[u8; 16]>::try_from(&ip[24..40]).unwrap()),
        );
        assert_eq!(
            transport_checksum(mapped_source, mapped_destination, 17, &reassembled),
            0
        );
    }

    #[test]
    fn fallback_scrubs_deeply_tagged_ethernet_frames() {
        let segment = udp_segment(
            IpAddr::from(V4_SOURCE),
            IpAddr::from(V4_DESTINATION),
            b"tagged",
        );
        let raw = ipv4_frame(17, &segment, 0);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[2, 0, 0, 0, 0, 2]);
        bytes.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
        for tag in 0..5_u16 {
            bytes.extend_from_slice(&0x8100_u16.to_be_bytes());
            bytes.extend_from_slice(&(tag + 1).to_be_bytes());
        }
        bytes.extend_from_slice(&0x0800_u16.to_be_bytes());
        bytes.extend_from_slice(raw.bytes());
        let frame = Frame::new(None, LinkType::ETHERNET, bytes).unwrap();
        let patched = fallback_patch(&frame, &mut Pseudonyms::default()).unwrap();
        assert_eq!(&patched.bytes()[0..6], &[2, 0, 0, 0, 0, 1]);
        let ip = &patched.bytes()[34..];
        assert_ipv4_header_checksum(ip);
        let (source, destination) = ipv4_addresses(ip);
        assert_eq!(transport_checksum(source, destination, 17, &ip[20..]), 0);
    }

    #[test]
    fn scrub_pseudonymizes_outer_mac_on_encapsulated_ethernet() {
        let segment = udp_segment(
            IpAddr::from(V4_SOURCE),
            IpAddr::from(V4_DESTINATION),
            b"encapsulated",
        );
        let raw = ipv4_frame(17, &segment, 0);
        for (ether_type, prefix) in [
            (0x8864_u16, vec![0x11, 0, 0, 1, 0, 42, 0, 0x21]),
            (0x8847_u16, vec![0, 0, 0x11, 64]),
        ] {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&[2, 0, 0, 0, 0, 9]);
            bytes.extend_from_slice(&[2, 0, 0, 0, 0, 8]);
            bytes.extend_from_slice(&ether_type.to_be_bytes());
            bytes.extend_from_slice(&prefix);
            bytes.extend_from_slice(raw.bytes());
            let frame = Frame::new(None, LinkType::ETHERNET, bytes).unwrap();
            let dissector = Dissector::new(packetcraftr_core::protocol::builtin::registry());
            let scrubbed =
                scrub_frame(&frame, &dissector, &mut Pseudonyms::default(), 1_000_000).unwrap();
            assert!(matches!(
                &scrubbed.bytes()[0..6],
                [2, 0, 0, 0, 0, 1] | [2, 0, 0, 0, 0, 2]
            ));
            assert!(matches!(
                &scrubbed.bytes()[6..12],
                [2, 0, 0, 0, 0, 1] | [2, 0, 0, 0, 0, 2]
            ));
            assert_ne!(&scrubbed.bytes()[0..6], &scrubbed.bytes()[6..12]);
            let ip_offset = 14 + prefix.len();
            assert_eq!(&scrubbed.bytes()[ip_offset..], raw.bytes());
        }
    }

    #[test]
    fn scrub_refuses_outer_headers_with_embedded_addresses() {
        let segment = udp_segment(
            IpAddr::from(V4_SOURCE),
            IpAddr::from(V4_DESTINATION),
            b"routed",
        );
        let dissector = Dissector::new(packetcraftr_core::protocol::builtin::registry());
        for kind in [7_u8, 131] {
            let frame = ipv4_option_frame(kind, &segment);
            assert!(fallback_patch(&frame, &mut Pseudonyms::default()).is_none());
            assert!(
                scrub_frame(&frame, &dissector, &mut Pseudonyms::default(), 1_000_000).is_err()
            );
        }

        let segment = udp_segment(
            IpAddr::from(V6_SOURCE),
            IpAddr::from(V6_DESTINATION),
            b"routed",
        );
        let mut bytes = vec![0_u8; 64 + segment.len()];
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&((24 + segment.len()) as u16).to_be_bytes());
        bytes[6] = 43;
        bytes[7] = 64;
        bytes[8..24].copy_from_slice(&V6_SOURCE);
        bytes[24..40].copy_from_slice(&V6_DESTINATION);
        bytes[40] = 17;
        bytes[41] = 2;
        bytes[43] = 1;
        bytes[48..64].copy_from_slice(&V6_SOURCE);
        bytes[64..].copy_from_slice(&segment);
        let frame = Frame::new(None, LinkType::RAW, bytes).unwrap();
        assert!(fallback_patch(&frame, &mut Pseudonyms::default()).is_none());
        assert!(scrub_frame(&frame, &dissector, &mut Pseudonyms::default(), 1_000_000).is_err());
    }

    #[test]
    fn scrub_refuses_ip_on_unsupported_link_types() {
        let segment = udp_segment(
            IpAddr::from(V4_SOURCE),
            IpAddr::from(V4_DESTINATION),
            b"loopback-link",
        );
        let raw = ipv4_frame(17, &segment, 0);
        let mut bytes = vec![0, 0, 0, 2];
        bytes.extend_from_slice(raw.bytes());
        let frame = Frame::new(None, LinkType::LOOP, bytes).unwrap();
        let dissector = Dissector::new(packetcraftr_core::protocol::builtin::registry());
        assert!(scrub_frame(&frame, &dissector, &mut Pseudonyms::default(), 1_000_000).is_err());
    }

    #[test]
    fn scrub_drops_all_interface_option_metadata() {
        let options = [0_u16, 1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 15, 65_000]
            .into_iter()
            .map(|code| capture_file::PcapNgOption {
                code,
                value: bytes::Bytes::from_static(b"sensitive interface detail"),
            })
            .collect();
        assert!(scrub_interface_options(options).is_empty());
    }

    #[test]
    fn pseudonyms_are_stable_sequential_and_preserve_special_addresses() {
        let mut names = Pseudonyms::default();
        let one: IpAddr = "198.51.100.9".parse().unwrap();
        let two: IpAddr = "198.51.100.10".parse().unwrap();
        assert_eq!(names.ip(one).to_string(), "10.0.0.1");
        assert_eq!(names.ip(one).to_string(), "10.0.0.1");
        assert_eq!(names.ip(two).to_string(), "10.0.0.2");
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(names.ip(loopback), loopback);
        assert_eq!(names.mac([1, 2, 3, 4, 5, 6]), [1, 2, 3, 4, 5, 6]);
        assert_eq!(names.mac([2, 2, 3, 4, 5, 6]), [2, 0, 0, 0, 0, 1]);
        assert_eq!(names.mac([2, 2, 3, 4, 5, 6]), [2, 0, 0, 0, 0, 1]);
    }
}
