// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod rendering;

use crate::output::contract::Format;

use packetcraftr_core::error::Classification;
use packetcraftr_core::error::Kind;
use packetcraftr_core::protocol::BuiltinProtocol;

use crate::output;

use crate::errors::CliError;
use crate::rendering::emit_aggregate;

pub(crate) const AFTER_LONG_HELP: &str = r"Examples:
  packetcraftr protocols
  packetcraftr protocols ipv4
  packetcraftr --output json protocols IP4";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Built-in protocol name or alias to describe.
    #[arg(value_name = "PROTOCOL")]
    pub(crate) protocol: Option<String>,
}

impl super::Spec for Args {
    const FORMATS: &'static [crate::output::contract::Format] = &[
        crate::output::contract::Format::Text,
        crate::output::contract::Format::Json,
    ];
    const CANCELLATION: bool = false;

    fn run(
        self,
        format: Format,
        _stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(super) fn run(arguments: Args, format: Format) -> Result<(), CliError> {
    match arguments.protocol {
        Some(name) => describe_protocol(&name, format),
        None => list_protocols(format),
    }
}

fn list_protocols(format: Format) -> Result<(), CliError> {
    let result = output::protocols::ListResult::from(BuiltinProtocol::ALL);
    crate::rendering::render_aggregate_rows(
        output::contract::Command::Protocols,
        format,
        &result,
        &result.protocols,
        rendering::protocol_line,
    )
}

fn describe_protocol(name: &str, format: Format) -> Result<(), CliError> {
    let protocol = BuiltinProtocol::ALL
        .iter()
        .copied()
        .find(|protocol| {
            protocol.as_str().eq_ignore_ascii_case(name)
                || protocol
                    .aliases()
                    .iter()
                    .any(|alias| alias.eq_ignore_ascii_case(name))
        })
        .ok_or_else(|| unknown_protocol(name))?;
    let registry = packetcraftr_core::protocol::builtin::registry();
    let detail = output::protocols::Detail::try_from((registry.as_ref(), protocol))
        .map_err(CliError::classified)?;
    match format {
        Format::Text => rendering::render_detail(&detail),
        Format::Json => emit_aggregate(
            output::contract::Command::Protocols,
            output::protocols::DetailResult::from(detail),
            Vec::new(),
        ),
        other => other.unreachable(),
    }
}

fn unknown_protocol(name: &str) -> CliError {
    CliError::from_classification(
        Classification::new(
            "cli.protocol",
            Kind::Usage,
            Some("run `packetcraftr protocols` to list built-in protocols"),
        ),
        format!("unknown built-in protocol '{name}'"),
        Vec::new(),
    )
}
