// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod capture_output;
mod normalize;
mod projection;
mod records;
mod rendering;
mod selection;
use crate::output::contract::ReadFormat;

use std::io;
use std::sync::Arc;

use packetcraftr_core::error::Classification;
use packetcraftr_core::error::Kind;

use self::arguments::Args;
use crate::errors::CliError;
use crate::input::open_capture;
use crate::rendering::{FieldTree, StreamEncoder, finish_compressed_output};

use capture_output::CaptureOutput;
use selection::{Selection, prepare_decoding};

impl super::Spec for Args {
    type Format = crate::output::contract::ReadFormat;
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [max_projection_bytes: Bytes @ ResultRetention]);
        self.limits.resources(settings);
        self.tree.resources(settings);
    }

    fn run(
        self,
        format: Self::Format,
        stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format, stream).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(super) fn run(
    arguments: Args,
    format: ReadFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let compression = arguments.compression.for_output(format.as_format())?;
    if !arguments.fields.is_empty() {
        return projection::run(arguments, format.as_format(), stream);
    }
    if matches!(format, ReadFormat::Json | ReadFormat::Csv | ReadFormat::Tsv) {
        return Err(crate::rendering::missing_fields_error());
    }
    let Args {
        fields: _,
        max_projection_bytes: _,
        compression: _,
        path,
        limits,
        epoch,
        selection,
        filter,
        normalize,
        dissect,
        tree,
        decode,
    } = arguments;
    limits.validate()?;
    let bounds = epoch.resolve()?;
    let selection = selection.resolve()?;
    validate_dissect_format(dissect, format)?;
    if tree.tree && !dissect {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.tree_requires_dissect",
                Kind::Usage,
                Some("add --dissect to show each frame's layers as a tree"),
            ),
            "--tree requires --dissect",
            Vec::new(),
        ));
    }
    tree.validate_format(format == ReadFormat::Text, format)?;
    let capture_output = CaptureOutput::resolve(normalize, format)?;
    let registry = decode.registry()?;
    let decoding = prepare_decoding(
        filter.as_deref(),
        dissect,
        &registry,
        limits.reader.max_frame_bytes,
    )?;
    let mut tree = tree
        .tree
        .then(|| FieldTree::new(Arc::clone(&registry), tree.max_tree_bytes));
    let mut reader = open_capture(&path, limits.reader)?;
    let selection = Selection {
        bounds,
        frames: &selection,
        decoding: decoding.as_ref(),
    };
    if let Some(output) = capture_output {
        output.validate_input(reader.format())?;
        let stdout = io::stdout();
        let mut destination = compression.writer(stdout.lock())?;
        let result = output.write(&mut reader, limits, selection, &mut destination);
        return finish_compressed_output(result, destination);
    }
    records::run(
        &mut reader,
        limits,
        selection,
        format,
        stream,
        tree.as_mut(),
    )
}

fn validate_dissect_format(dissect: bool, format: ReadFormat) -> Result<(), CliError> {
    if dissect && !matches!(format, ReadFormat::Text | ReadFormat::Ndjson) {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.dissect_unsupported_format",
                Kind::Usage,
                Some("use --output text or --output ndjson to show the layer stack"),
            ),
            format!("--dissect has no effect on {format} output"),
            Vec::new(),
        ));
    }
    Ok(())
}
