// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use self::arguments::Args;
use crate::input::open_capture_with_compression;
use crate::output::{self, contract::Format};

use packetcraftr_core::capture_file::inspect;

use crate::errors::CliError;
use crate::rendering::StreamEncoder;

impl super::Spec for Args {
    const FORMATS: &'static [Format] = &[Format::Text, Format::Json, Format::Ndjson];
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        self.limits.resources(settings);
    }

    fn run(
        self,
        invocation: &crate::invocation::Invocation,
    ) -> Result<super::CommandExit, CliError> {
        let format = invocation.format;
        let stream = &invocation.output;
        run(invocation, self, format, stream).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(crate) fn run(
    invocation: &crate::invocation::Invocation,
    args: Args,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    args.limits.validate()?;
    let (mut reader, compression_format) =
        open_capture_with_compression(invocation, &args.path, args.limits.reader)?;
    let report =
        inspect::inspect(&mut reader, args.limits.stream_limits()).map_err(CliError::classified)?;
    invocation.check()?;
    let compression: output::info::Compression = compression_format.into();
    let report =
        output::info::Report::try_from((report, compression)).map_err(CliError::classified)?;
    match format {
        Format::Json => crate::rendering::emit_aggregate(
            invocation,
            output::contract::Command::Info,
            report,
            Vec::new(),
        ),
        Format::Ndjson => stream.complete(report, Vec::new()).map_err(Into::into),
        Format::Text => rendering::render(invocation, &report),
        other => other.unreachable(),
    }
}
