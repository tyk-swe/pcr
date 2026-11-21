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
use crate::commands::Generate;
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
    ) -> Result<(), CliError> {
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
        let report = capture_file::map_frames(&mut reader, &mut writer, limits, 0, |_, frame| {
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
        })
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
        )
    }
}

fn scrub_frame(
    frame: &Frame,
    dissector: &Dissector,
    pseudonyms: &mut Pseudonyms,
    max_output_bytes: usize,
) -> Result<Frame, CliError> {
    let decoded = dissector
        .decode(frame.clone(), packetcraftr_core::decode::Options::default())
        .map_err(CliError::classified)?;
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
        return Ok(frame.clone());
    }
    transform::rewrite(frame, &patch, RewriteLimits { max_output_bytes })
        .map_err(CliError::classified)
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
