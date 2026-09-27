// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Packet recipes and bounded payload-file injection.

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
    let (input, declared) = match (packet, packet_file) {
        (Some(expression), None) => return parse_expression(&expression, registry, max_layers),
        (None, Some(path)) => {
            let bytes = read_bounded_file(
                &path,
                core::document::DEFAULT_MAX_DOCUMENT_BYTES,
                InputKind::Recipe,
            )?;
            let input = String::from_utf8(bytes).map_err(|source| {
                CliError::new(
                    Kind::Usage,
                    format!("packet document is not UTF-8: {source}"),
                )
            })?;
            (input, core::document::Format::from_path(&path))
        }
        (None, None) => {
            let bytes = read_stdin_bounded(
                core::document::DEFAULT_MAX_DOCUMENT_BYTES,
                InputKind::Recipe,
            )?;
            let input = String::from_utf8(bytes).map_err(|source| {
                CliError::new(Kind::Usage, format!("stdin recipe is not UTF-8: {source}"))
            })?;
            (input, None)
        }
        (Some(_), Some(_)) => unreachable!("clap enforces recipe source conflicts"),
    };
    core::document::recipe::parse(&input, declared, registry, max_layers)
        .map_err(CliError::classified)
}

/// Loads a file into an existing, empty bytes-typed recipe field under the
/// packet input ceiling. Saved documents retain the bytes, independent of the
/// file.
fn apply_payload_file(packet: &mut Packet, spec: &str) -> Result<(), CliError> {
    let (target, path) = spec
        .split_once('=')
        .ok_or_else(|| CliError::new(Kind::Usage, PAYLOAD_FILE_SYNTAX))?;
    let target = target.parse::<core::document::payload::Target>()?;
    target.inject(packet, || {
        read_bounded_file_allow_empty(
            Path::new(path),
            core::document::DEFAULT_MAX_DOCUMENT_BYTES,
            InputKind::Recipe,
        )
        .map(Into::into)
    })
}

const PAYLOAD_FILE_SYNTAX: &str = "--payload-file requires LAYER.FIELD=PATH";

/// A refused `--payload-file`: the option is the outer context, and the
/// library's refusal stays the typed source with its own text.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
struct PayloadFile {
    message: &'static str,
    #[source]
    source: core::document::payload::Error,
}

impl From<core::document::payload::Error> for CliError {
    fn from(source: core::document::payload::Error) -> Self {
        let classification = core::error::Classified::classification(&source);
        let message = match source {
            core::document::payload::Error::Syntax => PAYLOAD_FILE_SYNTAX,
            _ => "--payload-file cannot fill its recipe field",
        };
        let error = PayloadFile { message, source };
        Self::from_classification(
            classification,
            error.to_string(),
            core::error::source_chain(&error),
        )
    }
}

fn parse_expression(
    input: &str,
    registry: &core::registry::Registry,
    max_layers: usize,
) -> Result<Packet, CliError> {
    core::expression::parse(
        input,
        registry,
        core::expression::Limits {
            max_layers,
            ..core::expression::Limits::default()
        },
    )
    .map_err(CliError::classified)
}
