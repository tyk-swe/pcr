// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use crate::output::contract::SendFormat;

use packetcraftr_core as core;
use packetcraftr_core::capture_file as capture;

use crate::output;

use self::arguments::Args;
use crate::errors::CliError;
use crate::rendering::{
    emit_published, render_diagnostics_text, write_capture_file, write_hex_line, write_raw,
    write_summary_line,
};
use crate::system::preparation::{self, Prepared};

fn prepare(arguments: Args) -> Result<Prepared<packetcraftr::send::Request>, CliError> {
    let Args {
        send,
        template,
        repeat,
        rate,
    } = arguments;
    let request = packetcraftr::send::Request {
        repeat,
        rate,
        max_template_packets: template.max_template_packets,
        ..packetcraftr::send::Request::new(
            preparation::placeholder(),
            packetcraftr::send::Options::default(),
        )
    };
    preparation::prepare(send, template, request)
}

/// A sink that writes each confirmed frame with `write` as the send publishes
/// it, so partial progress is preserved when a later frame fails.
fn writing(
    write: impl Fn(&packetcraftr::send::SentFrame) -> Result<(), CliError> + Send + 'static,
) -> impl packetcraftr::Sink<packetcraftr::send::Event, Ack = ()> {
    move |packetcraftr::send::Event::Sent(frame): packetcraftr::send::Event| {
        write(&frame).map_err(CliError::into_boundary_error)
    }
}

/// Sends the prepared request, keeping every frame for the report.
fn collect(
    prepared: Prepared<packetcraftr::send::Request>,
) -> Result<packetcraftr::send::Aggregate, CliError> {
    let collector = packetcraftr::send::Collector::default();
    let report = prepared
        .client
        .send(prepared.request, collector.clone())
        .map_err(CliError::classified)?;
    collector.finish(report).map_err(CliError::classified)
}

impl super::Spec for Args {
    type Format = crate::output::contract::SendFormat;
    const CANCELLATION: bool = true;

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        self.send.resources(settings);
        self.template.resources(settings);
    }

    fn run(
        self,
        format: Self::Format,
        _stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(super) fn run(arguments: Args, format: SendFormat) -> Result<(), CliError> {
    let compression = arguments.send.compression.for_output(format.as_format())?;
    let prepared = prepare(arguments)?;
    match format {
        SendFormat::Text => {
            // Each confirmed frame is reported as it happens, and its builder
            // diagnostics are kept for the end of the run.
            let diagnostics = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let collected = std::sync::Arc::clone(&diagnostics);
            let report = prepared
                .client
                .send(
                    prepared.request,
                    writing(move |frame| {
                        let mut collected = collected
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        for diagnostic in &frame.packet.built().diagnostics {
                            core::diagnostic::push_once(&mut collected, diagnostic.clone());
                        }
                        write_summary_line(format_args!("{}", rendering::sent_line(frame)))
                    }),
                )
                .map_err(CliError::classified)?;
            if report.stats.packets_completed > 1 {
                write_summary_line(format_args!(
                    "sent {} frame(s), {} byte(s) across {} pass(es)",
                    report.stats.packets_completed, report.stats.bytes, report.passes_completed
                ))?;
            }
            let diagnostics = std::mem::take(
                &mut *diagnostics
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            );
            render_diagnostics_text(&diagnostics)
        }
        SendFormat::Json => {
            let report = collect(prepared)?;
            let published = output::envelope::Published::<output::send::Report>::try_from(report)
                .map_err(CliError::classified)?;
            emit_published(output::contract::Command::Send, published)
        }
        SendFormat::Hex => prepared
            .client
            .send(
                prepared.request,
                writing(|frame| write_hex_line(frame.packet.wire_bytes())),
            )
            .map_err(CliError::classified)
            .map(|_| ()),
        SendFormat::Raw => prepared
            .client
            .send(
                prepared.request,
                writing(|frame| write_raw(frame.packet.wire_bytes())),
            )
            .map_err(CliError::classified)
            .map(|_| ()),
        SendFormat::Pcap | SendFormat::PcapNg => {
            // The aggregate already holds every confirmed frame, in order.
            let report = collect(prepared)?;
            let capture_format = if format == SendFormat::Pcap {
                capture::Format::Pcap
            } else {
                capture::Format::PcapNg
            };
            let frames = report
                .sent
                .into_iter()
                .map(|frame| frame.packet.frame().clone());
            write_capture_file(capture_format, frames, compression)
        }
    }
}
