// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Arguments that write generated packets to a capture stream.

use std::time::{Duration, SystemTime};

use clap::Args;
use packetcraftr_core::error::Kind;
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::registry::Registry;
use packetcraftr_core::{analysis::pcap, protocol::builtin};

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
    /// Compress binary capture output.
    #[arg(long, value_enum, default_value_t = super::Compression::None)]
    pub(crate) compression: super::Compression,
}

/// The validated capture-stream destination for generated frames.
pub(crate) struct CaptureOutput {
    pub(crate) link_type: LinkType,
    pub(crate) timestamp: SystemTime,
    compression: super::Compression,
}

impl CaptureOutputArgs {
    /// Validates capture-only arguments against the selected format, returning
    /// the destination when the output is a capture stream.
    pub(crate) fn resolve(
        self,
        format: packetcraftr_cli::output::contract::Format,
    ) -> Result<Option<CaptureOutput>, CliError> {
        self.compression.validate(format)?;
        let captures = matches!(
            format,
            packetcraftr_cli::output::contract::Format::Pcap
                | packetcraftr_cli::output::contract::Format::PcapNg
        );
        if !captures {
            if self.link_type.is_some() {
                return Err(CliError::new(
                    Kind::Cli,
                    "--link-type requires PCAP or PCAPNG output",
                ));
            }
            if self.timestamp.is_some() {
                return Err(CliError::new(
                    Kind::Cli,
                    "--timestamp requires PCAP or PCAPNG output",
                ));
            }
            return Ok(None);
        }
        let link_type = self.link_type.ok_or_else(|| {
            CliError::new(
                Kind::Cli,
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
            compression: self.compression,
        }))
    }
}

impl CaptureOutput {
    /// Confirms the recipe's first layer decodes under the selected link type.
    pub(crate) fn validate_root(&self, packet: &Packet) -> Result<(), CliError> {
        let registry = builtin::registry();
        validate_link_type(&registry, packet, self.link_type)
    }

    /// Confirms that the emitted header actually decodes under this root.
    /// Permissive builds can otherwise produce a malformed root even though
    /// the recipe's protocol name matched the selected link type.
    pub(crate) fn validate_wire(
        &self,
        built: &packetcraftr_core::build::BuiltPacket,
    ) -> Result<(), CliError> {
        let registry = builtin::registry();
        let root = registry
            .root_for_link_type(self.link_type.0)
            .expect("validate_root checked the registered capture root");
        let decoded = registry
            .codec(root.as_str())
            .expect("registered capture root has a codec")
            .decode(
                &built.bytes,
                &packetcraftr_core::codec::LayerDecodeContext {
                    parent: None,
                    registry: &registry,
                    allow_trailing_padding: false,
                    network: None,
                    discriminator: None,
                },
            )
            .map_err(|source| {
                CliError::new(
                    Kind::Cli,
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
                Kind::Cli,
                "emitted bytes decode to a different capture root than the recipe",
            ));
        }
        Ok(())
    }

    /// Opens the bounded streaming writer on stdout under compression.
    pub(crate) fn writer(
        &self,
        format: packetcraftr_cli::output::contract::Format,
    ) -> Result<pcap::Writer<pcap::compression::Output<std::io::Stdout>>, CliError> {
        let destination = self.compression.writer(std::io::stdout())?;
        let format = match format {
            packetcraftr_cli::output::contract::Format::Pcap => pcap::Format::Pcap,
            packetcraftr_cli::output::contract::Format::PcapNg => pcap::Format::PcapNg,
            _ => unreachable!("capture output resolves only capture formats"),
        };
        pcap::Writer::new(destination, format, self.link_type).map_err(|source| {
            crate::rendering::stream_capture_error("initialize capture output failed", source)
        })
    }
}

/// Confirms `link_type` names a registered decode root the packet's first
/// layer satisfies — either directly, or through a decode-only dispatch root
/// such as `raw_ip`.
fn validate_link_type(
    registry: &Registry,
    packet: &Packet,
    link_type: LinkType,
) -> Result<(), CliError> {
    let Some(root) = registry.root_for_link_type(link_type.0) else {
        return Err(CliError::new(
            Kind::Cli,
            format!("link type {} has no built-in decode root", link_type.0),
        ));
    };
    let first = packet
        .layer(0)
        .map(|layer| *layer.protocol_id())
        .ok_or_else(|| CliError::new(Kind::Cli, "the recipe has no layers"))?;
    let accepted = first == root
        || registry
            .codec(root.as_str())
            .is_some_and(|codec| codec.accepts_decoded_protocol(&first));
    if !accepted {
        return Err(CliError::new(
            Kind::Cli,
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
            Kind::Cli,
            format!("unknown link type {input:?}; use a capture-root name or a decimal number"),
        )
    })
}

/// Parses a non-negative Unix timestamp in decimal seconds, carrying up to
/// nanosecond fractional precision without rounding.
pub(crate) fn parse_timestamp(input: &str) -> Result<SystemTime, CliError> {
    let invalid = || {
        CliError::new(
            Kind::Cli,
            format!(
                "invalid timestamp {input:?}; use non-negative Unix seconds with optional nanosecond fraction"
            ),
        )
    };
    let input = input.trim();
    let (seconds, fraction) = input.split_once('.').unwrap_or((input, ""));
    if seconds.is_empty()
        || !seconds.bytes().all(|byte| byte.is_ascii_digit())
        || (input.contains('.') && fraction.is_empty())
        || fraction.contains('.')
    {
        return Err(invalid());
    }
    let seconds = seconds.parse::<u64>().map_err(|_| invalid())?;
    let nanos = if fraction.is_empty() {
        0
    } else {
        if fraction.len() > 9 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid());
        }
        let mut digits = fraction.to_owned();
        digits.extend(std::iter::repeat_n('0', 9 - fraction.len()));
        digits.parse::<u32>().map_err(|_| invalid())?
    };
    let offset = Duration::new(seconds, nanos);
    let timestamp = SystemTime::UNIX_EPOCH
        .checked_add(offset)
        .ok_or_else(invalid)?;
    // SystemTime may be coarser than Duration (100 ns on Windows). Never
    // silently move an inclusive bound or a generated frame's timestamp.
    if timestamp.duration_since(SystemTime::UNIX_EPOCH).ok() != Some(offset) {
        return Err(CliError::new(
            Kind::Cli,
            format!("timestamp {input:?} has precision this platform cannot represent exactly"),
        ));
    }
    Ok(timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_types_resolve_names_and_numbers() {
        assert_eq!(parse_link_type("ethernet").unwrap(), LinkType::ETHERNET);
        assert_eq!(parse_link_type("RAW").unwrap(), LinkType::RAW);
        assert_eq!(parse_link_type("228").unwrap(), LinkType::IPV4);
        assert!(parse_link_type("fddi").is_err());
        assert!(parse_link_type("12x").is_err());
    }

    #[test]
    fn timestamps_parse_decimal_seconds() {
        let epoch = parse_timestamp("0").unwrap();
        assert_eq!(epoch, SystemTime::UNIX_EPOCH);
        let stamped = parse_timestamp("1700000000.5").unwrap();
        assert_eq!(
            stamped,
            SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 500_000_000)
        );
        assert!(parse_timestamp("-1").is_err());
        assert!(parse_timestamp("1.0000000001").is_err());
        assert!(parse_timestamp("soon").is_err());
        assert!(parse_timestamp("+1").is_err());
        assert!(parse_timestamp("1.").is_err());
    }

    #[test]
    fn timestamps_are_exact_or_rejected_on_coarser_platforms() {
        for (input, nanos) in [("1.123456700", 123_456_700), ("1.123456789", 123_456_789)] {
            let offset = Duration::new(1, nanos);
            let representable = (SystemTime::UNIX_EPOCH + offset)
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                == offset;
            match parse_timestamp(input) {
                Ok(timestamp) => {
                    assert!(representable);
                    assert_eq!(
                        timestamp.duration_since(SystemTime::UNIX_EPOCH).unwrap(),
                        offset
                    );
                }
                Err(error) => {
                    assert!(!representable);
                    assert!(error.message.contains("cannot represent exactly"));
                }
            }
        }
    }
}
