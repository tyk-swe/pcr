// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{core, output};

use self::arguments::Args;
use super::super::errors::CliError;
use super::super::system::{client, prepare_route};
use super::registry;
use crate::command_options::SendArgs;
use crate::rendering::NdjsonStream;

pub(super) fn run(
    arguments: Args,
    format: output::contract::Format,
    stream: &mut NdjsonStream,
) -> Result<(), CliError> {
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
    options.validate().map_err(CliError::classified)?;

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
    let mut observer = Observer::new(format, stream);
    let summary = client
        .exchange_with_events(
            &core::template::Template::new(request.packet),
            options,
            |event| {
                observer
                    .observe(event)
                    .map_err(CliError::into_boundary_error)
            },
        )
        .map_err(CliError::classified)?;
    observer.finish(summary, format)
}

struct Observer<'a> {
    stream: Option<&'a mut NdjsonStream>,
    collector: Option<packetcraftr::exchange::Collector>,
    sent_diagnostics: Vec<core::diagnostic::Diagnostic>,
}

impl<'a> Observer<'a> {
    fn new(format: output::contract::Format, stream: &'a mut NdjsonStream) -> Self {
        let streaming = format == output::contract::Format::Ndjson;
        Self {
            stream: streaming.then_some(stream),
            collector: (!streaming).then(packetcraftr::exchange::Collector::default),
            sent_diagnostics: Vec::new(),
        }
    }

    fn observe(&mut self, event: packetcraftr::exchange::Event) -> Result<(), CliError> {
        if let Some(stream) = self.stream.as_deref_mut() {
            if let packetcraftr::exchange::Event::Sent { sent, .. } = &event {
                self.sent_diagnostics
                    .extend(sent.built().diagnostics.clone());
            }
            let event =
                output::exchange::Event::try_from_exchange(event).map_err(CliError::classified)?;
            return rendering::render_event(event, stream);
        }
        self.collector
            .as_mut()
            .expect("non-stream exchange observer has a collector")
            .observe(event);
        Ok(())
    }

    fn finish(
        self,
        summary: packetcraftr::exchange::Summary,
        format: output::contract::Format,
    ) -> Result<(), CliError> {
        if let Some(stream) = self.stream {
            let mut diagnostics = summary.diagnostics.clone();
            diagnostics.extend(self.sent_diagnostics);
            return rendering::render_complete(summary, diagnostics, stream);
        }
        let result = self
            .collector
            .expect("non-stream exchange observer has a collector")
            .finish(summary);
        match format {
            output::contract::Format::Text => rendering::render_text(&result),
            output::contract::Format::Json => rendering::render_aggregate(result),
            output::contract::Format::Pcap | output::contract::Format::PcapNg => {
                rendering::render_capture(&result, format)
            }
            _ => unreachable!("exchange format is checked before command dispatch"),
        }
    }
}
