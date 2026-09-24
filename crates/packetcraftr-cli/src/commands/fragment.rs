// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    command_options::{PacketBudgetArgs, RecipeArgs},
    errors::CliError,
    rendering::{StreamEncoder, emit_aggregate, write_capture_file, write_plain_line},
};
use packetcraftr_cli::output::{self, contract::CaptureFormat};
use packetcraftr_core::{
    self as core,
    frame::{Frame, LinkType},
    protocol::BuiltinProtocol,
};

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Compress binary capture output; independent of the input's detected format.
    #[arg(long, value_enum, default_value_t = crate::command_options::Compression::None)]
    pub(crate) compression: crate::command_options::Compression,

    #[command(flatten)]
    pub(crate) recipe: RecipeArgs,
    /// IP MTU, excluding the link header. Fragmentation is always explicit.
    #[arg(long)]
    pub(crate) mtu: usize,
    /// Fragment identification; required when splitting IPv6.
    #[arg(long)]
    pub(crate) identification: Option<u32>,
    /// Maximum fragments produced from the datagram; at most 8192.
    #[arg(long, default_value_t = 1024)]
    pub(crate) max_fragments: usize,
    /// Maximum bytes across all produced fragment frames.
    #[arg(long, default_value_t = 256 * 1024 * 1024)]
    pub(crate) max_output_bytes: usize,
    #[command(flatten)]
    pub(crate) budget: PacketBudgetArgs,
}

pub(crate) fn run(
    args: Args,
    format: CaptureFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    args.compression.validate(format.as_format())?;
    let registry = core::protocol::builtin::registry();
    let packet = crate::input::read_recipe(args.recipe, &registry, args.budget.max_layers)?;
    crate::cancellation::check()?;
    let root = packet.layer(0).and_then(BuiltinProtocol::of);
    let link_type = match root {
        Some(BuiltinProtocol::Ethernet) => LinkType::ETHERNET,
        Some(BuiltinProtocol::Ipv4) => LinkType::IPV4,
        Some(BuiltinProtocol::Ipv6) => LinkType::IPV6,
        _ => {
            return Err(CliError::classified(core::transform::Error::Unsupported(
                "recipe must begin with Ethernet or IP",
            )));
        }
    };
    let built = core::build::Builder::new(registry)
        .build(
            packet,
            Default::default(),
            args.budget.build_options(core::codec::Mode::Strict),
        )
        .map_err(CliError::classified)?;
    let frame =
        Frame::new(std::time::UNIX_EPOCH, link_type, built.bytes).map_err(CliError::classified)?;
    let frames = core::transform::fragment(
        &frame,
        core::transform::FragmentOptions {
            mtu: args.mtu,
            identification: args.identification,
            max_fragments: args.max_fragments,
            max_output_bytes: args.max_output_bytes,
        },
    )
    .map_err(CliError::classified)?;
    crate::cancellation::check()?;
    if matches!(format, CaptureFormat::Pcap | CaptureFormat::PcapNg) {
        return write_capture_file(
            if format == CaptureFormat::Pcap {
                core::analysis::pcap::Format::Pcap
            } else {
                core::analysis::pcap::Format::PcapNg
            },
            frames,
            args.compression,
        );
    }
    let summary = output::fragment::Complete {
        mtu: args.mtu,
        fragments: frames.len() as u64,
        bytes: frames.iter().map(|frame| frame.bytes().len() as u64).sum(),
    };
    let mut records = Vec::new();
    for (index, frame) in frames.into_iter().enumerate() {
        crate::cancellation::check()?;
        let record = output::fragment::Fragment {
            fragment_index: index as u64,
            frame: output::frame::Captured::try_from_frame(frame).map_err(CliError::classified)?,
        };
        match format {
            CaptureFormat::Json => records.push(record),
            CaptureFormat::Ndjson => stream.emit_data(record, Vec::new())?,
            CaptureFormat::Hex => write_plain_line(format_args!("{}", record.frame.bytes_hex()))?,
            CaptureFormat::Text => write_plain_line(format_args!(
                "fragment {index}: {} bytes {}",
                record.frame.captured_length,
                record.frame.bytes_hex()
            ))?,
            CaptureFormat::Pcap | CaptureFormat::PcapNg => {
                return Err(CliError::new(
                    core::error::Kind::Internal,
                    "capture output returned before fragment rendering",
                ));
            }
        }
    }
    match format {
        CaptureFormat::Json => emit_aggregate(
            output::contract::Command::Fragment,
            output::fragment::Report {
                summary,
                fragments: records,
            },
            built.diagnostics,
        ),
        CaptureFormat::Ndjson => stream
            .complete(summary, built.diagnostics)
            .map_err(Into::into),
        CaptureFormat::Text | CaptureFormat::Hex | CaptureFormat::Pcap | CaptureFormat::PcapNg => {
            Ok(())
        }
    }
}
