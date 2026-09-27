// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture-reading selected-field workflow, with analysis only when required.

use packetcraftr_core as core;

use super::arguments::Args;
use crate::errors::CliError;
use crate::output::contract::{Command, Format};
use crate::rendering::{Projector, StreamEncoder};

pub(super) fn run(args: Args, format: Format, stream: &StreamEncoder) -> Result<(), CliError> {
    args.limits.validate()?;
    let bounds = args.epoch.resolve()?;
    let registry = args.decode.registry()?;
    let mut projector = Projector::prepare(
        &args.fields,
        args.max_projection_bytes,
        &registry,
        Command::Read,
        format,
    )?
    .expect("field selection dispatch");
    let filter = args
        .filter
        .as_deref()
        .map(|source| {
            crate::filtering::compile(
                source,
                &registry,
                crate::filtering::Capabilities::stream_capable(),
            )
        })
        .transpose()?;
    let mut reader = crate::input::open_capture(&args.path, args.limits.reader)?;
    let mut frames = 0u64;
    let mut bytes = 0u64;
    if projector.projection.requirements().stream_index
        || filter
            .as_ref()
            .is_some_and(|filter| filter.requirements().stream_index)
    {
        let summary = core::analysis::run(
            &mut reader,
            registry,
            &core::analysis::Options {
                time_bounds: bounds,
                cancellation: Some(crate::cancellation::signal().clone()),
                limits: core::analysis::Limits {
                    max_frames: args.limits.max_frames,
                    max_bytes: args.limits.max_bytes,
                    max_frame_bytes: args.limits.reader.max_frame_bytes,
                    ..Default::default()
                },
                ..Default::default()
            },
            |record| {
                let kept = filter
                    .as_ref()
                    .map(|filter| record.matches(filter))
                    .transpose()
                    .map_err(|source| CliError::classified(source).into_boundary_error())?
                    .unwrap_or(true);
                if kept {
                    let values = record
                        .project(&projector.projection, projector.remaining())
                        .map_err(|source| CliError::classified(source).into_boundary_error())?;
                    projector
                        .emit(record.number, values, stream)
                        .map_err(CliError::into_boundary_error)?;
                }
                Ok(())
            },
        )
        .map_err(CliError::classified)?;
        frames = summary.frames_read;
        bytes = summary.bytes_read;
    } else {
        // The stream-capable filter takes the analysis branch above, so the
        // frame-at-a-time seam applies here.
        let decoder =
            core::filter::FrameDecoder::new(registry, filter, args.limits.reader.max_frame_bytes)
                .map_err(CliError::classified)?;
        let mut budget = core::capture_file::Budget::new(core::capture_file::Limits {
            max_frames: args.limits.max_frames,
            max_bytes: args.limits.max_bytes,
        })
        .map_err(CliError::classified)?;
        while let Some(frame) = reader.next_frame().map_err(CliError::classified)? {
            budget
                .charge(frame.captured_length())
                .map_err(CliError::classified)?;
            (frames, bytes) = (budget.frames(), budget.captured_bytes());
            if bounds.is_some_and(|bounds| !bounds.contains(frame.timestamp)) {
                continue;
            }
            let Some(decoded) = decoder
                .decode_selected(frames, &frame)
                .map_err(|error| crate::filtering::frame_error(frames, error))?
            else {
                continue;
            };
            let context = core::filter::Context {
                decoded: &decoded,
                derived: &[],
                number: frames,
                tcp_stream: None,
                udp_stream: None,
            };
            let values = projector
                .projection
                .values(&context, projector.remaining())
                .map_err(CliError::classified)?;
            projector.emit(frames, values, stream)?;
        }
    }
    projector.finish(frames, bytes, stream)
}
