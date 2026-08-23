// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{core, output};

use self::arguments::Args;
use super::super::system::{client, prepare_route};
use super::registry;
use crate::command_options::SendArgs;
use crate::rendering::NdjsonStream;
use packetcraftr::BoundaryError;

pub(super) fn run(
    arguments: Args,
    format: output::contract::Format,
    stream: &mut NdjsonStream,
) -> Result<(), BoundaryError> {
    let Args {
        send,
        timeout_ms,
        max_responses,
        max_unmatched_frames,
        limits,
    } = arguments;
    let SendArgs {
        route,
        mode,
        allow_permissive_live,
        policy,
    } = send;
    let limits = limits.into_limits();
    let mut options = packetcraftr::exchange::Options {
        timeout: Duration::from_millis(timeout_ms),
        max_template_packets: 1,
        max_responses,
        max_unmatched_frames,
        max_capture_queue_frames: limits.max_frames,
        max_captured_bytes: limits.max_bytes,
        capture_overflow_policy: limits.overflow_policy,
        ..packetcraftr::exchange::Options::default()
    };
    options.decode.max_packet_size = limits.snap_length;
    // Validate before packet parsing can trigger hostname/interface work.
    options.validate().map_err(BoundaryError::from_error)?;

    let registry = registry()?;
    let request = prepare_route(route, policy.into_policy(), &registry)?;
    options.send = packetcraftr::send::Options {
        destination: request.destination,
        plan: request.options,
        build: core::build::Options {
            mode: mode.into(),
            ..core::build::Options::default()
        },
        allow_permissive_live,
    };
    let client = client(Arc::clone(&registry), request.policy);
    let template = core::template::Template::new(request.packet);
    if format == output::contract::Format::Ndjson {
        let event_stream = stream.clone();
        let summary = client
            .exchange_with_events(&template, options, move |event| {
                output::exchange::Event::try_from_exchange(event)
                    .map_err(BoundaryError::from_error)
                    .and_then(|(event, diagnostics)| event_stream.emit_data(event, diagnostics))
            })
            .map_err(BoundaryError::from_error)?;
        return rendering::render_complete(summary, stream);
    }
    let result = client
        .exchange(&template, options)
        .map_err(BoundaryError::from_error)?;
    match format {
        output::contract::Format::Text => rendering::render_text(&result),
        output::contract::Format::Json => rendering::render_aggregate(result),
        output::contract::Format::Pcap | output::contract::Format::PcapNg => {
            rendering::render_capture(&result, format)
        }
        _ => unreachable!("exchange format is checked before command dispatch"),
    }
}
