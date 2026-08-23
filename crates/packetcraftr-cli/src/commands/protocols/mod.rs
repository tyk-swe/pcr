// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;

use packetcraftr::{core::protocol::support, output};

use self::arguments::Args;
use super::super::rendering::{emit_aggregate, write_stdout_line};
use super::registry;
use crate::error::UNKNOWN_PROTOCOL;
use packetcraftr::BoundaryError;

pub(super) fn run(arguments: Args, format: output::contract::Format) -> Result<(), BoundaryError> {
    match arguments.protocol {
        Some(name) => describe_protocol(&name, format),
        None => list_protocols(format),
    }
}

fn list_protocols(format: output::contract::Format) -> Result<(), BoundaryError> {
    let result = output::protocols::List {
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
        output::contract::Format::Json => {
            emit_aggregate(output::contract::Command::Protocols, result, Vec::new())
        }
        _ => unreachable!("protocols format is checked before command dispatch"),
    }
}

fn describe_protocol(name: &str, format: output::contract::Format) -> Result<(), BoundaryError> {
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
    let detail =
        output::protocols::Protocol::new(output::protocols::Summary::from(support), fields);
    match format {
        output::contract::Format::Text => render_detail(&detail),
        output::contract::Format::Json => emit_aggregate(
            output::contract::Command::Protocols,
            output::protocols::Detail { protocol: detail },
            Vec::new(),
        ),
        _ => unreachable!("protocols format is checked before command dispatch"),
    }
}

fn render_detail(protocol: &output::protocols::Protocol) -> Result<(), BoundaryError> {
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

fn unknown_protocol(name: &str) -> BoundaryError {
    BoundaryError::new(
        format!("unknown built-in protocol '{name}'"),
        UNKNOWN_PROTOCOL,
        Vec::new(),
    )
}
