// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use clap::Args;
use packetcraftr_core::capture_file;
use packetcraftr_core::decode::Dissector;
use packetcraftr_core::error::Kind;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::identity;
use packetcraftr_core::transform::{self, HeaderRewrite, RewriteLimits};

use crate::command_options::{DecodeArgs, OfflineCaptureLimitsArgs};
use crate::commands::{CommandExit, Generate};
use crate::errors::CliError;
use crate::output::contract::Format;
use crate::terminal::emit_stdout_document;

pub(crate) const AFTER_LONG_HELP: &str = r"Write a share-oriented PCAPNG copy with consistently pseudonymized outer Ethernet and IP addresses. IPv4 pseudonyms are sequential private addresses starting at 10.0.0.1, IPv6 pseudonyms are in 2001:db8::/32, and MAC pseudonyms are locally administered. Unspecified, loopback, multicast, and broadcast addresses are preserved. Protocol payloads are retained unless --truncate caps captured bytes per frame, so review payload disclosures separately before sharing. Existing destinations are refused.

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
            |_, options| {
                options
                    .into_iter()
                    .filter(|option| !matches!(option.code, 2..=7))
                    .collect()
            },
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

fn scrub_frame(
    frame: &Frame,
    dissector: &Dissector,
    pseudonyms: &mut Pseudonyms,
    max_output_bytes: usize,
) -> Result<Frame, CliError> {
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
    if let Some((source, destination)) = decoded.packet.iter().find_map(identity::network_endpoints)
    {
        patch.source_ip = Some(pseudonyms.ip(source));
        patch.destination_ip = Some(pseudonyms.ip(destination));
    }
    if patch.is_empty() {
        return Ok(fallback_patch(frame, pseudonyms).unwrap_or_else(|| frame.clone()));
    }
    match transform::rewrite(frame, &patch, RewriteLimits { max_output_bytes }) {
        Ok(frame) => Ok(frame),
        Err(error) => fallback_patch(frame, pseudonyms).ok_or_else(|| CliError::classified(error)),
    }
}

fn fallback_patch(frame: &Frame, pseudonyms: &mut Pseudonyms) -> Option<Frame> {
    let mut bytes = frame.bytes().to_vec();
    let ip_offset = patch_link_bytes(&mut bytes, frame.link_type, pseudonyms)?;
    let ip = bytes.get_mut(ip_offset..)?;
    match ip.first().map(|byte| byte >> 4) {
        Some(4) if ip.len() >= 20 => {
            let source = IpAddr::from(<[u8; 4]>::try_from(&ip[12..16]).ok()?);
            let destination = IpAddr::from(<[u8; 4]>::try_from(&ip[16..20]).ok()?);
            ip[12..16].copy_from_slice(&ipv4_bytes(pseudonyms.ip(source)));
            ip[16..20].copy_from_slice(&ipv4_bytes(pseudonyms.ip(destination)));
            let header_len = usize::from(ip[0] & 0x0f) * 4;
            if header_len >= 20 && ip.len() >= header_len {
                ip[10] = 0;
                ip[11] = 0;
                let checksum = !packetcraftr_core::protocol::checksum_parts(&[&ip[..header_len]]);
                ip[10..12].copy_from_slice(&checksum.to_be_bytes());
            }
        }
        Some(6) if ip.len() >= 40 => {
            let source = IpAddr::from(<[u8; 16]>::try_from(&ip[8..24]).ok()?);
            let destination = IpAddr::from(<[u8; 16]>::try_from(&ip[24..40]).ok()?);
            ip[8..24].copy_from_slice(&ipv6_bytes(pseudonyms.ip(source)));
            ip[24..40].copy_from_slice(&ipv6_bytes(pseudonyms.ip(destination)));
        }
        _ => return None,
    }
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
) -> Option<usize> {
    if link_type.is_raw_ip() {
        return Some(0);
    }
    match link_type {
        LinkType::ETHERNET => {
            if bytes.len() >= 14 {
                let destination = <[u8; 6]>::try_from(&bytes[0..6]).ok()?;
                let source = <[u8; 6]>::try_from(&bytes[6..12]).ok()?;
                bytes[0..6].copy_from_slice(&pseudonyms.mac(destination));
                bytes[6..12].copy_from_slice(&pseudonyms.mac(source));
            }
            let mut type_offset = 12_usize;
            for _ in 0..4 {
                let ether_type =
                    u16::from_be_bytes([*bytes.get(type_offset)?, *bytes.get(type_offset + 1)?]);
                if matches!(ether_type, 0x0800 | 0x86dd) {
                    return Some(type_offset + 2);
                }
                if !matches!(ether_type, 0x8100 | 0x88a8) {
                    return None;
                }
                type_offset += 4;
            }
            None
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
            Some(16)
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
            Some(20)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
