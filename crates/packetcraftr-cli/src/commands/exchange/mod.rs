// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use std::time::Duration;

use packetcraftr::{analysis::pcap as capture, core, output};

use self::arguments::Args;
use super::format::{CollectedFormat, ExchangeFormat};
use crate::errors::CliError;
use crate::rendering::StreamEncoder;

pub(super) fn run(
    arguments: Args,
    format: output::contract::Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let format = ExchangeFormat::narrow(output::contract::Command::Exchange, format)?;
    let Args {
        send,
        timeout_ms,
        max_responses,
        max_unmatched_frames,
        limits,
    } = arguments;
    let limits = limits.into_limits();
    let mut options = packetcraftr::exchange::Options {
        timeout: Duration::from_millis(timeout_ms),
        max_template_packets: 1,
        max_responses,
        max_unmatched_frames,
        capture: limits,
        ..packetcraftr::exchange::Options::default()
    };
    options.decode.max_packet_size = limits.snap_length;
    // Validate before packet parsing can trigger hostname/interface work.
    options.validate().map_err(CliError::classified)?;

    let prepared = super::send::prepare(send)?;
    options.send = prepared.options;
    let client = prepared.client;
    let template = core::template::Template::new(prepared.packet);
    if format == ExchangeFormat::Ndjson {
        let event_stream = stream.clone();
        let summary = client
            .exchange_with_events(&template, options, move |event| {
                output::exchange::Event::try_from_exchange(event)
                    .map_err(CliError::classified)
                    .and_then(
                        |(event, diagnostics)| Ok(event_stream.emit_data(event, diagnostics)?),
                    )
                    .map_err(CliError::into_boundary_error)
            })
            .map_err(CliError::classified)?;
        return rendering::render_complete(summary, stream);
    }
    let format = CollectedFormat::narrow_from(output::contract::Command::Exchange, format)?;
    let result = client
        .exchange(&template, options)
        .map_err(CliError::classified)?;
    match format {
        CollectedFormat::Text => rendering::render_text(&result),
        CollectedFormat::Json => rendering::render_aggregate(result),
        CollectedFormat::Pcap => rendering::render_capture(&result, capture::Format::Pcap),
        CollectedFormat::PcapNg => rendering::render_capture(&result, capture::Format::PcapNg),
    }
}
