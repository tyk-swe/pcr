// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::SystemTime;

use clap::Args;
use packetcraftr_core::error::Kind;
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::registry::Registry;
use packetcraftr_core::{capture_file, protocol::builtin};

use crate::command_options::{CompressionArgs, Destination, parse_timestamp};
use crate::errors::CliError;

/// Capture-file options shared by commands that emit generated frames.
#[derive(Debug, Args)]
pub(crate) struct CaptureOutputArgs {
    /// Capture link-layer type for generated frames, by name or number:
    /// null (0), ethernet (1), bsd-raw (12), raw (101), loop (108),
    /// linux-sll (113), ipv4 (228), ipv6 (229), or linux-sll2 (276).
    /// Required for PCAP and PCAPNG output; the recipe's first layer must
    /// decode under the selected link type.
    #[arg(long, value_name = "NAME|NUMBER")]
    pub(crate) link_type: Option<String>,
    /// Fixed timestamp applied to every generated frame, as Unix seconds with
    /// optional fractional precision to nanoseconds. Defaults to the epoch so
    /// generated captures stay byte-deterministic.
    #[arg(long, value_name = "SECONDS")]
    pub(crate) timestamp: Option<String>,
    #[command(flatten)]
    pub(crate) compression: CompressionArgs<GeneratedCapture>,
}

pub(crate) struct CaptureOutput {
    pub(crate) link_type: LinkType,
    pub(crate) timestamp: SystemTime,
    format: capture_file::Format,
    compression: crate::command_options::Compression,
}

impl CaptureOutputArgs {
    pub(crate) fn resolve(
        self,
        format: crate::output::contract::Format,
    ) -> Result<Option<CaptureOutput>, CliError> {
        let compression = self.compression.for_output(format)?;
        let captures = match format {
            crate::output::contract::Format::Pcap => Some(capture_file::Format::Pcap),
            crate::output::contract::Format::PcapNg => Some(capture_file::Format::PcapNg),
            _ => None,
        };
        let Some(capture_format) = captures else {
            if self.link_type.is_some() {
                return Err(CliError::new(
                    Kind::Usage,
                    "--link-type requires PCAP or PCAPNG output",
                ));
            }
            if self.timestamp.is_some() {
                return Err(CliError::new(
                    Kind::Usage,
                    "--timestamp requires PCAP or PCAPNG output",
                ));
            }
            return Ok(None);
        };
        let link_type = self.link_type.ok_or_else(|| {
            CliError::new(
                Kind::Usage,
                "capture output requires --link-type naming the generated frames' link layer",
            )
        })?;
        let timestamp = self
            .timestamp
            .map(|source| parse_timestamp(&source))
            .transpose()?
            .unwrap_or(SystemTime::UNIX_EPOCH);
        Ok(Some(CaptureOutput {
            link_type: parse_link_type(&link_type)?,
            timestamp,
            format: capture_format,
            compression,
        }))
    }
}

impl CaptureOutput {
    pub(crate) fn validate_root(&self, packet: &Packet) -> Result<(), CliError> {
        let registry = builtin::registry();
        validate_link_type(&registry, packet, self.link_type)
    }

    /// Permissive builds can produce a malformed root even though
    /// the recipe's protocol name matched the selected link type.
    pub(crate) fn validate_wire(
        &self,
        built: &packetcraftr_core::build::BuiltPacket,
    ) -> Result<(), CliError> {
        let registry = builtin::registry();
        let root = registry
            .root_for_link_type(self.link_type)
            .expect("validate_root checked the registered capture root");
        let decoded = registry
            .codec(root.as_str())
            .expect("registered capture root has a codec")
            .decode(
                built.bytes.clone(),
                &packetcraftr_core::codec::LayerDecodeContext {
                    parent: None,
                    registry: &registry,
                    network: None,
                    discriminator: None,
                },
            )
            .map_err(|source| {
                CliError::new(
                    Kind::Usage,
                    format!(
                        "emitted bytes do not decode under link type {}: {source}",
                        self.link_type.0,
                    ),
                )
            })?;
        if built
            .packet
            .layer(0)
            .is_none_or(|first| first.protocol_id() != decoded.layer.protocol_id())
        {
            return Err(CliError::new(
                Kind::Usage,
                "emitted bytes decode to a different capture root than the recipe",
            ));
        }
        Ok(())
    }

    pub(crate) fn writer(
        &self,
        limits: capture_file::Limits,
    ) -> Result<capture_file::Writer<capture_file::compression::Output<std::io::Stdout>>, CliError>
    {
        let destination = self.compression.writer(std::io::stdout())?;
        self.writer_over(destination, limits)
    }

    fn writer_over<W: std::io::Write>(
        &self,
        destination: W,
        stream_limits: capture_file::Limits,
    ) -> Result<capture_file::Writer<W>, CliError> {
        let writer = match self.format {
            capture_file::Format::Pcap => capture_file::Writer::pcap_with_options(
                destination,
                self.link_type,
                capture_file::PcapOptions {
                    stream_limits,
                    ..capture_file::PcapOptions::default()
                },
            ),
            capture_file::Format::PcapNg => capture_file::Writer::pcapng_with_options(
                destination,
                capture_file::PcapNgOptions {
                    stream_limits,
                    ..capture_file::PcapNgOptions::default()
                },
            )
            .and_then(|mut writer| {
                writer.add_interface(self.link_type)?;
                Ok(writer)
            }),
        };
        writer.map_err(|source| {
            crate::rendering::stream_capture_error("initialize capture output failed", source)
        })
    }
}

fn validate_link_type(
    registry: &Registry,
    packet: &Packet,
    link_type: LinkType,
) -> Result<(), CliError> {
    let Some(root) = registry.root_for_link_type(link_type) else {
        return Err(CliError::new(
            Kind::Usage,
            format!("link type {} has no built-in decode root", link_type.0),
        ));
    };
    let first = packet
        .layer(0)
        .map(|layer| *layer.protocol_id())
        .ok_or_else(|| CliError::new(Kind::Usage, "the recipe has no layers"))?;
    let accepted = first == root
        || registry
            .codec(root.as_str())
            .is_some_and(|codec| codec.accepts_decoded_protocol(&first));
    if !accepted {
        return Err(CliError::new(
            Kind::Usage,
            format!(
                "link type {} decodes as {} but the recipe begins with {}",
                link_type.0,
                root.as_str(),
                first.as_str(),
            ),
        ));
    }
    Ok(())
}

fn parse_link_type(input: &str) -> Result<LinkType, CliError> {
    let normalized = input.trim().to_ascii_lowercase();
    let link_type = match normalized.as_str() {
        "null" | "bsd-null" => Some(LinkType::NULL),
        "ethernet" => Some(LinkType::ETHERNET),
        "bsd-raw" => Some(LinkType::BSD_RAW),
        "raw" => Some(LinkType::RAW),
        "loop" | "bsd-loop" => Some(LinkType::LOOP),
        "linux-sll" | "sll" => Some(LinkType::LINUX_SLL),
        "ipv4" | "ip" => Some(LinkType::IPV4),
        "ipv6" => Some(LinkType::IPV6),
        "linux-sll2" | "sll2" => Some(LinkType::LINUX_SLL2),
        _ => normalized.parse::<u32>().ok().map(LinkType),
    };
    link_type.ok_or_else(|| {
        CliError::new(
            Kind::Usage,
            format!("unknown link type {input:?}; use a capture-root name or a decimal number"),
        )
    })
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct GeneratedCapture;

impl Destination for GeneratedCapture {
    const HELP: &'static str = "Compress binary capture output";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_accepts_more_frames_than_the_default_stream_limit() {
        let count = capture_file::DEFAULT_MAX_STREAM_FRAMES + 1;
        for format in [capture_file::Format::Pcap, capture_file::Format::PcapNg] {
            let output = CaptureOutput {
                link_type: LinkType::IPV4,
                timestamp: SystemTime::UNIX_EPOCH,
                format,
                compression: crate::command_options::Compression::None,
            };
            let mut writer = output
                .writer_over(
                    Vec::new(),
                    capture_file::Limits {
                        max_frames: count,
                        max_bytes: count,
                    },
                )
                .expect("writer opens");
            let frame = packetcraftr_core::frame::Frame::new(
                SystemTime::UNIX_EPOCH,
                LinkType::IPV4,
                vec![1_u8],
            )
            .expect("valid fixture frame");
            for _ in 0..count {
                writer
                    .write_frame(&frame)
                    .unwrap_or_else(|error| panic!("{format:?}: {error}"));
            }
            assert_eq!(writer.frames_written(), count, "{format:?}");
        }
    }

    #[test]
    fn link_types_resolve_names_and_numbers() {
        assert_eq!(parse_link_type("ethernet").unwrap(), LinkType::ETHERNET);
        assert_eq!(parse_link_type("RAW").unwrap(), LinkType::RAW);
        assert_eq!(parse_link_type("228").unwrap(), LinkType::IPV4);
        assert!(parse_link_type("fddi").is_err());
        assert!(parse_link_type("12x").is_err());
    }
}
