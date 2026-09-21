// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Recipe source selection, document parsing, and payload-file application.

use std::path::{Path, PathBuf};

use packetcraftr_core as core;
use packetcraftr_core::error::Kind;
use packetcraftr_core::packet::Packet;

use super::{InputKind, read_bounded_file, read_bounded_file_allow_empty, read_stdin_bounded};
use crate::command_options::RecipeArgs;
use crate::errors::CliError;

pub(crate) fn read_recipe(
    arguments: RecipeArgs,
    registry: &core::registry::Registry,
    max_layers: usize,
) -> Result<Packet, CliError> {
    let RecipeArgs {
        packet,
        packet_file,
        payload_file,
    } = arguments;

    let mut packet = resolve_recipe(packet, packet_file, registry, max_layers)?;
    if let Some(spec) = payload_file {
        apply_payload_file(&mut packet, &spec)?;
    }
    Ok(packet)
}

fn resolve_recipe(
    packet: Option<String>,
    packet_file: Option<PathBuf>,
    registry: &core::registry::Registry,
    max_layers: usize,
) -> Result<Packet, CliError> {
    let (input, path) = match (packet, packet_file) {
        (Some(expression), None) => return parse_expression(&expression, registry, max_layers),
        (None, Some(path)) => {
            let bytes = read_bounded_file(
                &path,
                core::document::DEFAULT_MAX_DOCUMENT_BYTES,
                InputKind::Recipe,
            )?;
            let input = String::from_utf8(bytes).map_err(|source| {
                CliError::new(Kind::Cli, format!("packet document is not UTF-8: {source}"))
            })?;
            (input, Some(path))
        }
        (None, None) => {
            let bytes = read_stdin_bounded(
                core::document::DEFAULT_MAX_DOCUMENT_BYTES,
                InputKind::Recipe,
            )?;
            let input = String::from_utf8(bytes).map_err(|source| {
                CliError::new(Kind::Cli, format!("stdin recipe is not UTF-8: {source}"))
            })?;
            (input, None)
        }
        (Some(_), Some(_)) => unreachable!("clap enforces recipe source conflicts"),
    };
    let trimmed = input.trim_start();
    let format = path
        .as_deref()
        .and_then(document_format_from_path)
        .or_else(|| {
            trimmed
                .starts_with('{')
                .then_some(core::document::Format::Json)
        })
        .or_else(|| {
            (trimmed.starts_with("schema:") || trimmed.starts_with("---"))
                .then_some(core::document::Format::Yaml)
        });
    let parse_document = |format| {
        core::document::Packet::parse_with_limits(
            &input,
            format,
            &core::document::DocumentLimits {
                max_layers,
                ..core::document::DocumentLimits::DEFAULT
            },
        )
    };
    if let Some(format) = format {
        return parse_document(format)
            .and_then(|document| document.to_packet(registry, max_layers))
            .map_err(CliError::classified);
    }
    let mut expression_error = match parse_expression(&input, registry, max_layers) {
        Ok(packet) => return Ok(packet),
        Err(error) => error,
    };
    match parse_document(core::document::Format::Yaml) {
        Ok(document) => document
            .to_packet(registry, max_layers)
            .map_err(CliError::classified),
        Err(error) => {
            expression_error.causes.push(error.to_string());
            Err(expression_error)
        }
    }
}

/// Sets a bytes-typed recipe field from file contents. The field must exist,
/// hold bytes, and be empty in the recipe so an embedded value is never
/// silently replaced; the file reads under the packet input ceiling so saved
/// documents stay self-contained once the value lands in the packet.
fn apply_payload_file(packet: &mut Packet, spec: &str) -> Result<(), CliError> {
    let syntax = || {
        CliError::new(
            Kind::Cli,
            "--payload-file requires LAYER.FIELD=PATH with a zero-based layer index",
        )
    };
    let (selector, path) = spec.split_once('=').ok_or_else(syntax)?;
    let (layer, field) = selector.trim().split_once('.').ok_or_else(syntax)?;
    let layer_index = layer.parse::<usize>().map_err(|_| syntax())?;
    let field = field.trim().to_ascii_lowercase();
    if field.is_empty() {
        return Err(syntax());
    }
    let packet_len = packet.len();
    let layer = packet.layer_mut(layer_index).ok_or_else(|| {
        CliError::new(
            Kind::Cli,
            format!(
                "--payload-file layer index {layer_index} is outside the recipe's {packet_len} layers"
            ),
        )
    })?;
    let current = layer.field_path(&field).ok_or_else(|| {
        CliError::new(
            Kind::Cli,
            format!("--payload-file field {field} is unknown on layer {layer_index}"),
        )
    })?;
    let core::field::FieldValue::Bytes(current) = current else {
        return Err(CliError::new(
            Kind::Cli,
            format!("--payload-file field {field} on layer {layer_index} is not bytes-typed"),
        ));
    };
    if !current.is_empty() {
        return Err(CliError::new(
            Kind::Cli,
            format!(
                "--payload-file field {field} on layer {layer_index} already holds recipe bytes"
            ),
        ));
    }
    let bytes = read_bounded_file_allow_empty(
        Path::new(path),
        core::document::DEFAULT_MAX_DOCUMENT_BYTES,
        InputKind::Recipe,
    )?;
    layer
        .set_field_path(&field, core::field::FieldValue::Bytes(bytes.into()))
        .map_err(|source| {
            CliError::new(
                Kind::Cli,
                format!(
                    "could not set --payload-file field {field} on layer {layer_index}: {source}"
                ),
            )
        })
}

fn parse_expression(
    input: &str,
    registry: &core::registry::Registry,
    max_layers: usize,
) -> Result<Packet, CliError> {
    core::expression::parse(
        input,
        registry,
        core::expression::Options {
            max_layers,
            ..core::expression::Options::default()
        },
    )
    .map_err(CliError::classified)
}

fn document_format_from_path(path: &Path) -> Option<core::document::Format> {
    match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
        "json" => Some(core::document::Format::Json),
        "yaml" | "yml" => Some(core::document::Format::Yaml),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_extensions_are_case_insensitive_and_explicit() {
        use packetcraftr_core::document::Format;

        for (path, expected) in [
            ("packet.json", Some(Format::Json)),
            ("packet.JSON", Some(Format::Json)),
            ("packet.yaml", Some(Format::Yaml)),
            ("packet.yml", Some(Format::Yaml)),
            ("packet.txt", None),
            ("packet", None),
        ] {
            assert_eq!(
                document_format_from_path(Path::new(path)),
                expected,
                "{path}"
            );
        }
    }
}
