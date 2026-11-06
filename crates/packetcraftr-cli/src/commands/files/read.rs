// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(in crate::commands) mod arguments;
mod capture_output;
mod normalize;
pub(in crate::commands) mod output;
mod projection;
mod records;
mod rendering;
mod selection;
use crate::output::contract::Format;

use std::io;
use std::sync::Arc;

use packetcraftr_core::error::Classification;
use packetcraftr_core::error::Kind;

use self::arguments::Args;
use crate::errors::CliError;
use crate::input::open_capture;
use crate::invocation::StreamEncoder;
use crate::rendering::{FieldTree, finish_compressed_output};

use capture_output::CaptureOutput;
use selection::{Selection, prepare_decoding};

use crate::output::contract::PublishedType;

impl crate::commands::Spec for Args {
    const PUBLISHED: &'static [PublishedType] = &[
        PublishedType {
            definition: "projectionAggregateSuccess",
            command: "read",
            rust_types: &["crate::output::projection::Report"],
            events: &[],
            example: "examples/documents/output-read-fields-success.json",
        },
        PublishedType {
            definition: "readSuccess",
            command: "read",
            rust_types: &[
                "crate::commands::files::read::output::Event",
                "crate::output::frame::Record",
            ],
            events: &["complete", "frame"],
            example: "examples/documents/output-read-complete.json",
        },
        PublishedType {
            definition: "projectionStreamSuccess",
            command: "read",
            rust_types: &[
                "crate::output::projection::Complete",
                "crate::output::projection::RowEvent",
            ],
            events: &["complete", "fields"],
            example: "examples/documents/output-read-fields-complete.json",
        },
    ];
    const FORMATS: &'static [crate::output::contract::Format] = &[
        crate::output::contract::Format::Text,
        crate::output::contract::Format::Json,
        crate::output::contract::Format::Ndjson,
        crate::output::contract::Format::Hex,
        crate::output::contract::Format::Pcap,
        crate::output::contract::Format::PcapNg,
    ];
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [max_projection_bytes: Bytes @ ResultRetention]);
        self.limits.resources(settings);
        self.tree.resources(settings);
    }

    fn run(
        self,
        invocation: &crate::invocation::Invocation,
    ) -> Result<crate::commands::CommandExit, CliError> {
        let format = invocation.format;
        let stream = &invocation.output;
        run(invocation, self, format, stream).map(|()| crate::commands::CommandExit::SUCCESS)
    }
}

pub(super) fn run(
    invocation: &crate::invocation::Invocation,
    arguments: Args,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let compression = arguments.compression.for_output(format)?;
    if !arguments.fields.is_empty() {
        return projection::run(invocation, arguments, format, stream);
    }
    if matches!(format, Format::Json) {
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
    let limits = limits.limits()?;
    let bounds = epoch.resolve()?;
    let selection = selection.resolve()?;
    validate_dissect_format(dissect, format)?;
    if tree.tree && !dissect {
        return Err(CliError::from_classification(
            Classification::new(
                packetcraftr_core::error::Code::CliTreeRequiresDissect,
                Kind::Usage,
                Some("add --dissect to show each frame's layers as a tree"),
            ),
            "--tree requires --dissect",
            Vec::new(),
        ));
    }
    tree.validate_format(format)?;
    let capture_output = CaptureOutput::resolve(normalize, format)?;
    let registry = decode.registry()?;
    let decoding = prepare_decoding(
        filter.as_deref(),
        dissect,
        &registry,
        limits.reader_bounds().max_frame_bytes,
    )?;
    let mut tree = tree
        .tree
        .then(|| FieldTree::new(Arc::clone(&registry), tree.max_tree_bytes));
    let mut reader = open_capture(&invocation.control, &invocation.output, &path, limits)?;
    let selection = Selection {
        bounds,
        frames: &selection,
        decoding: decoding.as_ref(),
    };
    if let Some(output) = capture_output {
        output.validate_input(reader.format())?;
        let stdout = io::stdout();
        let mut destination = compression.writer(stdout.lock())?;
        let result = output.write(invocation, &mut reader, limits, selection, &mut destination);
        return finish_compressed_output(result, destination);
    }
    if format == Format::Text && stream.batches_records() {
        invocation.batch_stdout();
    }
    let result = records::run(
        invocation,
        &mut reader,
        limits,
        selection,
        format,
        stream,
        tree.as_mut(),
    );
    result.and(crate::rendering::flush_stdout_batch(invocation))
}

fn validate_dissect_format(dissect: bool, format: Format) -> Result<(), CliError> {
    if dissect && !matches!(format, Format::Text | Format::Ndjson) {
        return Err(CliError::from_classification(
            Classification::new(
                packetcraftr_core::error::Code::CliDissectUnsupportedFormat,
                Kind::Usage,
                Some("use --output text or --output ndjson to show the layer stack"),
            ),
            format!("--dissect has no effect on {format} output"),
            Vec::new(),
        ));
    }
    Ok(())
}
