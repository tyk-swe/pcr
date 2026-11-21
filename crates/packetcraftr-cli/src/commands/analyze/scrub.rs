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
use packetcraftr_core::protocol::link::Arp;
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
    Arp(usize),
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
                            | ip_protocol::FRAGMENT
                            | ip_protocol::AH
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
    if frame.link_type == LinkType::ETHERNET
        && !frame.bytes().is_empty()
        && LinkHeader::walk(frame.link_type, frame.bytes()).is_err()
    {
        return Err(CliError::new(
            Kind::Policy,
            "scrub refuses an incomplete Ethernet header it cannot pseudonymize",
        ));
    }
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
    if decoded.packet.get::<Arp>().is_some() {
        return fallback_patch(frame, pseudonyms).ok_or_else(|| {
            CliError::new(
                Kind::Policy,
                "scrub refuses ARP frames it cannot pseudonymize",
            )
        });
    }
    let outer_addresses = outer_ip_addresses(frame);
    if outer_ip(frame).is_some() && outer_addresses.is_none() {
        return fallback_patch(frame, pseudonyms)
            .ok_or_else(|| CliError::new(Kind::Policy, "scrub cannot walk the outer IP header"));
    }
    let mut patch = HeaderRewrite::default();
    if frame.link_type == LinkType::ETHERNET
        && let Some((source, destination)) =
            decoded.packet.iter().find_map(identity::link_addresses)
    {
        patch.source_mac = Some(pseudonyms.mac(source));
        patch.destination_mac = Some(pseudonyms.mac(destination));
    }
    if let Some((source, destination)) = outer_addresses {
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
        LinkPatch::Arp(offset) => {
            {
                let arp = bytes.get_mut(offset..)?;
                if arp.len() < 28
                    || arp[0..2] != 1_u16.to_be_bytes()
                    || arp[2..4] != 0x0800_u16.to_be_bytes()
                    || arp[4] != 6
                    || arp[5] != 4
                {
                    return None;
                }
                let sender_mac = <[u8; 6]>::try_from(&arp[8..14]).ok()?;
                let sender_ip = IpAddr::from(<[u8; 4]>::try_from(&arp[14..18]).ok()?);
                let target_mac = <[u8; 6]>::try_from(&arp[18..24]).ok()?;
                let target_ip = IpAddr::from(<[u8; 4]>::try_from(&arp[24..28]).ok()?);
                arp[8..14].copy_from_slice(&pseudonyms.mac(sender_mac));
                arp[14..18].copy_from_slice(&ipv4_bytes(pseudonyms.ip(sender_ip)));
                arp[18..24].copy_from_slice(&pseudonyms.mac(target_mac));
                arp[24..28].copy_from_slice(&ipv4_bytes(pseudonyms.ip(target_ip)));
            }
            return finish(bytes);
        }
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
            let ether_type = match &link {
                LinkHeader::Ethernet(ethernet) => ethernet.ether_type(),
                LinkHeader::RawIp { .. } => 0,
            };
            if bytes.len() >= 14 {
                let destination = <[u8; 6]>::try_from(&bytes[0..6]).ok()?;
                let source = <[u8; 6]>::try_from(&bytes[6..12]).ok()?;
                bytes[0..6].copy_from_slice(&pseudonyms.mac(destination));
                bytes[6..12].copy_from_slice(&pseudonyms.mac(source));
            }
            if ether_type == 0x0806 {
                Some(LinkPatch::Arp(link.network_offset()))
            } else if link.carries_ip() {
                Some(LinkPatch::Ip(link.network_offset()))
            } else {
                Some(LinkPatch::LinkOnly)
            }
        }
        LinkType::LINUX_SLL => {
            if bytes.len() < 16 {
                return None;
            }
            let protocol = u16::from_be_bytes([bytes[14], bytes[15]]);
            if !matches!(protocol, 0x0800 | 0x86dd | 0x0806) {
                return None;
            }
            let address_len = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
            if address_len >= 6 && bytes.len() >= 12 {
                let source = <[u8; 6]>::try_from(&bytes[6..12]).ok()?;
                bytes[6..12].copy_from_slice(&pseudonyms.mac(source));
            }
            if protocol == 0x0806 {
                Some(LinkPatch::Arp(16))
            } else {
                Some(LinkPatch::Ip(16))
            }
        }
        LinkType::LINUX_SLL2 => {
            if bytes.len() < 20 {
                return None;
            }
            let protocol = u16::from_be_bytes([bytes[0], bytes[1]]);
            if !matches!(protocol, 0x0800 | 0x86dd | 0x0806) {
                return None;
            }
            if usize::from(bytes[11]) >= 6 && bytes.len() >= 18 {
                let source = <[u8; 6]>::try_from(&bytes[12..18]).ok()?;
                bytes[12..18].copy_from_slice(&pseudonyms.mac(source));
                bytes[18..20].fill(0);
            }
            if protocol == 0x0806 {
                Some(LinkPatch::Arp(20))
            } else {
                Some(LinkPatch::Ip(20))
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests;
