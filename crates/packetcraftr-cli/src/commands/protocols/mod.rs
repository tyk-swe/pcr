// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;

use packetcraftr::{
    core::error::{Classification, Kind},
    core::protocol::support,
    output,
};

use self::arguments::Args;
use super::super::errors::CliError;
use super::super::rendering::{emit_aggregate, write_stdout_line};
use super::format::AggregateFormat;
use super::registry;

pub(super) fn run(arguments: Args, format: output::contract::Format) -> Result<(), CliError> {
    let format = AggregateFormat::narrow(output::contract::Command::Protocols, format)?;
    match arguments.protocol {
        Some(name) => describe_protocol(&name, format),
        None => list_protocols(format),
    }
}

fn list_protocols(format: AggregateFormat) -> Result<(), CliError> {
    let result = output::protocols::ListResult {
        protocols: support::BUILTIN_PROTOCOLS
            .iter()
            .map(output::protocols::Summary::from)
            .collect(),
    };
    match format {
        AggregateFormat::Text => {
            for protocol in &result.protocols {
                write_stdout_line(format_args!(
                    "{} aliases=[{}] build={} dissect={} exact_round_trip={} matcher={} decode_only={}",
                    protocol.protocol,
                    protocol.aliases.join(", "),
                    protocol.build,
                    protocol.dissect,
                    protocol.exact_round_trip,
                    protocol.matcher,
                    protocol.decode_only
                ))?;
            }
            Ok(())
        }
        AggregateFormat::Json => {
            emit_aggregate(output::contract::Command::Protocols, result, Vec::new())
        }
    }
}

fn describe_protocol(name: &str, format: AggregateFormat) -> Result<(), CliError> {
    let support = support::BUILTIN_PROTOCOLS
        .iter()
        .find(|support| {
            support.protocol.eq_ignore_ascii_case(name)
                || support
                    .aliases
                    .iter()
                    .any(|alias| alias.eq_ignore_ascii_case(name))
        })
        .ok_or_else(|| unknown_protocol(name))?;
    let registry = registry()?;
    let fields = registry
        .schema(support.protocol)
        .map(|schema| {
            schema
                .fields
                .iter()
                .map(output::protocols::Field::from)
                .collect()
        })
        .unwrap_or_default();
    let bindings = registry
        .parent_bindings(support.protocol)
        .into_iter()
        .map(|(parent, discriminator)| output::protocols::Binding {
            parent: parent.as_str().to_owned(),
            discriminator: discriminator.0,
        })
        .collect();
    let detail =
        output::protocols::Detail::new(output::protocols::Summary::from(support), fields, bindings);
    match format {
        AggregateFormat::Text => render_detail(&detail),
        AggregateFormat::Json => emit_aggregate(
            output::contract::Command::Protocols,
            output::protocols::DetailResult { protocol: detail },
            Vec::new(),
        ),
    }
}

fn render_detail(protocol: &output::protocols::Detail) -> Result<(), CliError> {
    write_stdout_line(format_args!("protocol: {}", protocol.protocol))?;
    write_stdout_line(format_args!("aliases: [{}]", protocol.aliases.join(", ")))?;
    write_stdout_line(format_args!("build: {}", protocol.build))?;
    write_stdout_line(format_args!("dissect: {}", protocol.dissect))?;
    write_stdout_line(format_args!(
        "exact_round_trip: {}",
        protocol.exact_round_trip
    ))?;
    write_stdout_line(format_args!("matcher: {}", protocol.matcher))?;
    write_stdout_line(format_args!("decode_only: {}", protocol.decode_only))?;
    write_stdout_line(format_args!("bindings:"))?;
    for binding in &protocol.bindings {
        write_stdout_line(format_args!(
            "  {} discriminator={}",
            binding.parent, binding.discriminator
        ))?;
    }
    write_stdout_line(format_args!("fields:"))?;
    for field in &protocol.fields {
        write_stdout_line(format_args!(
            "  {} kind={} required={} derived={} description={}",
            field.name,
            field.kind.as_str(),
            field.required,
            field.derived,
            field.description
        ))?;
    }
    Ok(())
}

fn unknown_protocol(name: &str) -> CliError {
    CliError::from_classification(
        Classification::new(
            "cli.protocol",
            Kind::Cli,
            Some("run `packetcraftr protocols` to list built-in protocols"),
        ),
        format!("unknown built-in protocol '{name}'"),
        Vec::new(),
    )
}
