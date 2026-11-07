// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(in crate::commands) mod arguments;
pub(in crate::commands) mod output;

use crate::output::contract::Format;

use packetcraftr_core as core;
use packetcraftr_core::capture_file as capture;

use self::arguments::Args;
use crate::errors::CliError;
use crate::rendering::{
    emit_published, render_diagnostics_text, write_capture_file, write_hex_line, write_raw,
    write_summary_line,
};
use crate::system::{LiveDraft, Prepared, prepare_live};

fn prepare(
    invocation: &crate::invocation::Invocation,
    arguments: Args,
) -> Result<Prepared<packetcraftr::send::Request>, CliError> {
    let Args {
        send,
        template,
        repeat,
        rate,
    } = arguments;
    let draft = Draft { repeat, rate };
    prepare_live(invocation, send, template, draft)
}

fn writing(
    write: impl Fn(&packetcraftr::send::SentFrame) -> Result<(), CliError> + Send + 'static,
) -> impl packetcraftr::Sink<packetcraftr::send::Event, Ack = ()> {
    move |packetcraftr::send::Event::Sent(frame): packetcraftr::send::Event| {
        write(&frame).map_err(CliError::into_boundary_error)
    }
}

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

use crate::output::contract::PublishedType;

impl crate::commands::Spec for Args {
    const PUBLISHED: &'static [PublishedType] = &[PublishedType {
        definition: "sendSuccess",
        command: "send",
        rust_types: &["crate::commands::network::send::output::Report"],
        events: &[],
        example: "examples/documents/output-send-success.json",
    }];
    const FORMATS: &'static [crate::output::contract::Format] = &[
        crate::output::contract::Format::Text,
        crate::output::contract::Format::Json,
        crate::output::contract::Format::Hex,
        crate::output::contract::Format::Raw,
        crate::output::contract::Format::Pcap,
        crate::output::contract::Format::PcapNg,
    ];
    const CANCELLATION: bool = true;

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        self.send.policy.resources(settings);
        self.template.resources(settings);
    }

    fn run(
        self,
        invocation: &crate::invocation::Invocation,
    ) -> Result<crate::commands::CommandExit, CliError> {
        run(invocation, self).map(|()| crate::commands::CommandExit::SUCCESS)
    }
}

fn run(invocation: &crate::invocation::Invocation, arguments: Args) -> Result<(), CliError> {
    let format = invocation.format;
    let presentation = invocation.output.presentation();
    let compression = arguments.send.compression.for_output(format)?;
    let prepared = prepare(invocation, arguments)?;
    match format {
        Format::Text => {
            let diagnostics = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let collected = std::sync::Arc::clone(&diagnostics);
            let report = prepared
                .client
                .send(
                    prepared.request,
                    writing({
                        let invocation = invocation.clone();
                        move |frame| {
                            let invocation = &invocation;
                            let mut collected = collected
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            for diagnostic in &frame.packet.built().diagnostics {
                                core::diagnostic::push_once(&mut collected, diagnostic.clone());
                            }
                            write_summary_line(invocation, format_args!("{}", sent_line(frame)))?;
                            let route = frame.packet.route();
                            if let Some(neighbor) = &route.neighbor_resolution
                                && neighbor.evidence_truncated
                            {
                                crate::rendering::write_stdout_line(
                                    invocation,
                                    format_args!("warning: neighbor evidence truncated"),
                                )?;
                            }
                            if presentation.verbose {
                                let route = crate::output::network::MaterializedRoute::try_from(
                                    route.clone(),
                                )
                                .map_err(CliError::classified)?;
                                presentation.details(
                                    invocation,
                                    "Route and neighbor evidence",
                                    &route,
                                )?;
                                crate::rendering::write_stdout_line(
                                    invocation,
                                    format_args!(
                                        "bytes: {}",
                                        crate::rendering::SpacedHex(frame.packet.wire_bytes())
                                    ),
                                )?;
                            }
                            Ok(())
                        }
                    }),
                )
                .map_err(CliError::classified)?;
            if report.stats.packets_completed > 1 {
                write_summary_line(
                    invocation,
                    format_args!(
                        "sent {} frame(s), {} byte(s) across {} pass(es)",
                        report.stats.packets_completed, report.stats.bytes, report.passes_completed
                    ),
                )?;
            }
            let diagnostics = std::mem::take(
                &mut *diagnostics
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            );
            render_diagnostics_text(invocation, &diagnostics)
        }
        Format::Json => {
            let report = collect(prepared)?;
            let published = crate::output::envelope::Published::<output::Report>::try_from(report)
                .map_err(CliError::classified)?;
            emit_published(
                invocation,
                crate::output::contract::Command::Send,
                published,
            )
        }
        Format::Hex => prepared
            .client
            .send(
                prepared.request,
                writing(|frame| write_hex_line(frame.packet.wire_bytes())),
            )
            .map_err(CliError::classified)
            .map(|_| ()),
        Format::Raw => prepared
            .client
            .send(
                prepared.request,
                writing(|frame| write_raw(frame.packet.wire_bytes())),
            )
            .map_err(CliError::classified)
            .map(|_| ()),
        Format::Pcap | Format::PcapNg => {
            let report = collect(prepared)?;
            let capture_format = if format == Format::Pcap {
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
        other => other.unreachable(),
    }
}

fn sent_line(frame: &packetcraftr::send::SentFrame) -> String {
    let route = frame.packet.route();
    format!(
        "sent {} bytes via {} (index {}, {})",
        frame.packet.wire_bytes().len(),
        route.plan.decision.interface.name,
        route.plan.decision.interface.index,
        route.plan.mode
    )
}

struct Draft {
    repeat: u32,
    rate: Option<u32>,
}
impl LiveDraft for Draft {
    type Parameters = packetcraftr::send::Parameters;
    fn validate(self, max_template_packets: usize) -> Result<Self::Parameters, CliError> {
        Self::Parameters::new(self.repeat, self.rate, max_template_packets)
            .map_err(CliError::classified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{contract::Command, stream::StreamEncoder};
    use clap::Parser;

    #[derive(Parser)]
    struct CommandLine {
        #[command(flatten)]
        arguments: Args,
    }

    #[test]
    fn invalid_send_options_precede_recipe_io() {
        let invocation = crate::invocation::Invocation::new(
            Format::Json,
            StreamEncoder::new(Command::Send, std::io::sink()).into(),
            None,
            Default::default(),
            None,
        );
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.json");
        for (repeat, rate) in [(0, None), (1, Some(0))] {
            let mut arguments = CommandLine::try_parse_from([
                std::ffi::OsStr::new("send"),
                std::ffi::OsStr::new("--packet-file"),
                missing.as_os_str(),
            ])
            .unwrap()
            .arguments;
            arguments.repeat = repeat;
            arguments.rate = rate;
            let error = prepare(&invocation, arguments).err().unwrap();
            assert_eq!(error.classification.code, core::error::Code::CliSendLimit);
        }
    }
}
