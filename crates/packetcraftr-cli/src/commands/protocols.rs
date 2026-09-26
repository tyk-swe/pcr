// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use crate::output::contract::AggregateFormat;

use packetcraftr_core::error::Classification;
use packetcraftr_core::error::Kind;
use packetcraftr_core::protocol::BuiltinProtocol;

use crate::output;

use self::arguments::Args;
use crate::errors::CliError;
use crate::rendering::emit_aggregate;

impl super::Spec for Args {
    type Format = crate::output::contract::AggregateFormat;
    const CANCELLATION: bool = false;

    fn run(
        self,
        format: Self::Format,
        _stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(super) fn run(arguments: Args, format: AggregateFormat) -> Result<(), CliError> {
    match arguments.protocol {
        Some(name) => describe_protocol(&name, format),
        None => list_protocols(format),
    }
}

fn list_protocols(format: AggregateFormat) -> Result<(), CliError> {
    let result = output::protocols::ListResult::from(BuiltinProtocol::ALL);
    super::render_aggregate_rows(
        output::contract::Command::Protocols,
        format,
        &result,
        &result.protocols,
        rendering::protocol_line,
    )
}

fn describe_protocol(name: &str, format: AggregateFormat) -> Result<(), CliError> {
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
        AggregateFormat::Text => rendering::render_detail(&detail),
        AggregateFormat::Json => emit_aggregate(
            output::contract::Command::Protocols,
            output::protocols::DetailResult::from(detail),
            Vec::new(),
        ),
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
