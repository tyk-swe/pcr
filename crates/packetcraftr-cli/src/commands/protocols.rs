// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Offline built-in protocol discovery.

use packetcraftr_model::error::{Classification, Kind};
use packetcraftr_output as output;
use packetcraftr_protocols::support;

use super::super::arguments::ProtocolsArgs;
use super::super::errors::CliError;
use super::super::rendering::{emit_json, write_stdout_line};
use super::super::runtime::default_catalog_arc;

pub(crate) fn run_protocols(
    arguments: ProtocolsArgs,
    format: output::contract::Format,
) -> Result<(), CliError> {
    match arguments.protocol {
        Some(name) => describe_protocol(&name, format),
        None => list_protocols(format),
    }
}

fn list_protocols(format: output::contract::Format) -> Result<(), CliError> {
    let result = output::protocols::ListResult {
        protocols: support::BUILTIN_PROTOCOLS
            .iter()
            .map(output::protocols::Summary::from)
            .collect(),
    };
    match format {
        output::contract::Format::Text => {
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
        output::contract::Format::Json => emit_json(&output::envelope::Aggregate::success(
            output::contract::Command::Protocols,
            result,
            Vec::new(),
        )),
        _ => unreachable!("protocols format is checked before command dispatch"),
    }
}

fn describe_protocol(name: &str, format: output::contract::Format) -> Result<(), CliError> {
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
    let catalog = default_catalog_arc()?;
    let descriptor = catalog.descriptor_named(support.protocol).ok_or_else(|| {
        CliError::new(
            70,
            format!(
                "built-in catalog invariant failed: protocol {} is absent",
                support.protocol
            ),
        )
    })?;
    if descriptor.protocol.as_str() != support.protocol {
        return Err(CliError::new(
            70,
            format!(
                "built-in catalog invariant failed: {} resolved to {}",
                support.protocol, descriptor.protocol
            ),
        ));
    }
    let fields = descriptor
        .schema
        .fields
        .iter()
        .map(output::protocols::Field::from)
        .collect();
    let detail = output::protocols::Detail::new(output::protocols::Summary::from(support), fields);
    match format {
        output::contract::Format::Text => render_detail(&detail),
        output::contract::Format::Json => emit_json(&output::envelope::Aggregate::success(
            output::contract::Command::Protocols,
            output::protocols::DetailResult { protocol: detail },
            Vec::new(),
        )),
        _ => unreachable!("protocols format is checked before command dispatch"),
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
