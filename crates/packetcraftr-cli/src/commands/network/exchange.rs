// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(in crate::commands) mod arguments;
mod rendering;

use crate::output::contract::Format;

use packetcraftr_core::capture_file as capture;
use packetcraftr_core::error::Kind;

use crate::output;

use self::arguments::Args;
use crate::errors::CliError;
use crate::invocation::StreamEncoder;
use crate::system::{Prepared, placeholder, prepare_live};

impl crate::commands::Spec for Args {
    const FORMATS: &'static [crate::output::contract::Format] = &[
        crate::output::contract::Format::Text,
        crate::output::contract::Format::Json,
        crate::output::contract::Format::Ndjson,
        crate::output::contract::Format::Pcap,
        crate::output::contract::Format::PcapNg,
    ];
    const CANCELLATION: bool = true;

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        self.send.policy.resources(settings);
        self.template.resources(settings);
        crate::resources::declare!(settings, self, [
            max_responses: Count @ ResultRetention,
            max_unmatched_frames: Count @ ResultRetention,
        ]);
        self.timeout.resources(settings);
        self.limits.resources(settings);
    }

    fn run(
        self,
        invocation: &crate::invocation::Invocation,
    ) -> Result<crate::commands::CommandExit, CliError> {
        run(invocation, self, invocation.format, &invocation.output)
            .map(|()| crate::commands::CommandExit::SUCCESS)
    }
}

pub(super) fn run(
    invocation: &crate::invocation::Invocation,
    arguments: Args,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let compression = arguments.send.compression.for_output(format)?;
    let stop = arguments.stop();
    let Args {
        send,
        template,
        timeout,
        stop_when_answered: _,
        max_responses,
        max_unmatched_frames,
        limits,
    } = arguments;
    let limits = limits.into_limits();
    let mut request = packetcraftr::exchange::Request {
        timeout: timeout.timeout(),
        stop,
        max_template_packets: template.max_template_packets,
        collection: packetcraftr::exchange::Collection {
            max_responses,
            max_unmatched_frames,
            capture: limits,
            ..packetcraftr::exchange::Collection::default()
        },
        ..packetcraftr::exchange::Request::new(
            placeholder(),
            packetcraftr::send::Options::default(),
        )
    };
    request.collection.decode.limits.max_packet_size = limits.snap_length;
    let Prepared { request, client } = prepare_live(invocation, send, template, request)?;
    match format {
        Format::Ndjson => {
            let emit = crate::commands::execution::emitter(invocation, rendering::emit_event);
            let summary = client
                .exchange(request.clone(), emit)
                .map_err(CliError::classified)?;
            invocation.check()?;
            rendering::render_complete(summary, stream)
        }
        _ => {
            let report = {
                let collector = packetcraftr::exchange::Collector::default();
                let report = client
                    .exchange(request.clone(), collector.clone())
                    .map_err(CliError::classified)?;
                collector.finish(report).map_err(CliError::classified)?
            };
            invocation.check()?;
            if format == Format::Json {
                crate::rendering::emit_published(
                    invocation,
                    output::contract::Command::Exchange,
                    output::envelope::Published::<output::exchange::Report>::try_from(report)
                        .map_err(CliError::classified)?,
                )
            } else {
                match format {
                    Format::Text => {
                        rendering::render_text(invocation, &report, stream.presentation())
                    }
                    Format::Pcap => {
                        rendering::render_capture(&report, capture::Format::Pcap, compression)
                    }
                    Format::PcapNg => {
                        rendering::render_capture(&report, capture::Format::PcapNg, compression)
                    }
                    Format::Json | Format::Ndjson => Err(CliError::new(
                        Kind::Internal,
                        "exchange machine formats dispatch before text rendering",
                    )),
                    other => other.unreachable(),
                }
            }
        }
    }
}
