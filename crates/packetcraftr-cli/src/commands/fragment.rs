// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;

use self::arguments::Args;
use crate::output::{self, contract::Format};
use crate::{
    errors::CliError,
    rendering::{
        StreamEncoder, emit_aggregate, write_capture_file, write_hex_line, write_stdout_line,
    },
};
use packetcraftr_core::{self as core, frame::Frame};

impl super::Spec for Args {
    const FORMATS: &'static [crate::output::contract::Format] = &[
        crate::output::contract::Format::Text,
        crate::output::contract::Format::Json,
        crate::output::contract::Format::Ndjson,
        crate::output::contract::Format::Hex,
        crate::output::contract::Format::Pcap,
        crate::output::contract::Format::PcapNg,
    ];
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
        format: Format,
        stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format, stream).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(crate) fn run(args: Args, format: Format, stream: &StreamEncoder) -> Result<(), CliError> {
    let compression = args.compression.for_output(format)?;
    let registry = core::protocol::builtin::registry();
    let packet = crate::input::read_recipe(args.recipe, &registry, args.budget.max_layers)?;
    crate::cancellation::check()?;
    let link_type = core::transform::fragment_link_type(&packet).map_err(CliError::classified)?;
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
    if matches!(format, Format::Pcap | Format::PcapNg) {
        return write_capture_file(
            if format == Format::Pcap {
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
            Format::Json => records.push(record),
            Format::Ndjson => stream.emit_data(record, Vec::new())?,
            Format::Hex => write_hex_line(record.frame.bytes())?,
            Format::Text => write_stdout_line(format_args!(
                "fragment {}: {} bytes {}",
                record.fragment_index,
                record.frame.captured_length,
                record.frame.bytes_hex()
            ))?,
            Format::Pcap | Format::PcapNg => {
                return Err(CliError::new(
                    core::error::Kind::Internal,
                    "capture output returned before fragment rendering",
                ));
            }
            other => other.unreachable(),
        }
    }
    match format {
        Format::Json => emit_aggregate(
            output::contract::Command::Fragment,
            output::fragment::Report::from((summary, records)),
            built.diagnostics,
        ),
        Format::Ndjson => stream
            .complete(summary, built.diagnostics)
            .map_err(Into::into),
        Format::Text | Format::Hex | Format::Pcap | Format::PcapNg => Ok(()),
        other => other.unreachable(),
    }
}
