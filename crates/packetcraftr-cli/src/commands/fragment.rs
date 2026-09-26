// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `fragment`: builds one IPv4 or IPv6 recipe and splits it into bounded
//! fragments at an explicit MTU.

pub(super) mod arguments;
mod rendering;

use self::arguments::Args;
use crate::output::{self, contract::CaptureFormat};
use crate::{
    errors::CliError,
    rendering::{StreamEncoder, emit_aggregate, write_capture_file, write_hex_line},
};
use packetcraftr_core::{
    self as core,
    frame::{Frame, LinkType},
    protocol::BuiltinProtocol,
};

impl super::Spec for Args {
    type Format = crate::output::contract::CaptureFormat;
    const CANCELLATION: bool = true;

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [
            max_fragments: Count @ Operation,
            max_output_bytes: Bytes @ ResultRetention,
        ]);
        self.budget.resources(settings);
    }

    fn run(
        self,
        format: Self::Format,
        stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format, stream).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(crate) fn run(
    args: Args,
    format: CaptureFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let compression = args.compression.for_output(format.as_format())?;
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
                core::transform::Unsupported::PacketRoot,
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
                core::capture_file::Format::Pcap
            } else {
                core::capture_file::Format::PcapNg
            },
            frames,
            compression,
        );
    }
    let summary = output::fragment::Complete::from((args.mtu, frames.as_slice()));
    let mut records = Vec::new();
    for (index, frame) in frames.into_iter().enumerate() {
        crate::cancellation::check()?;
        let record = output::fragment::Fragment::try_from((index as u64, frame))
            .map_err(CliError::classified)?;
        match format {
            CaptureFormat::Json => records.push(record),
            CaptureFormat::Ndjson => stream.emit_data(record, Vec::new())?,
            CaptureFormat::Hex => write_hex_line(record.frame.bytes())?,
            CaptureFormat::Text => rendering::render_fragment(&record)?,
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
            output::fragment::Report::from((summary, records)),
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
