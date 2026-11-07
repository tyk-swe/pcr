// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(in crate::commands) mod arguments;
pub(in crate::commands) mod output;
mod rendering;

use crate::output::contract::Format;

use packetcraftr_core::capture_file as capture;
use packetcraftr_core::error::Kind;

use self::arguments::Args;
use crate::errors::CliError;
use crate::system::{LiveDraft, Prepared, prepare_live};

use crate::output::contract::PublishedType;

impl crate::commands::Spec for Args {
    const PUBLISHED: &'static [PublishedType] = &[
        PublishedType {
            definition: "exchangeSuccess",
            command: "exchange",
            rust_types: &["crate::commands::network::exchange::output::Report"],
            events: &[],
            example: "examples/documents/output-exchange-success.json",
        },
        PublishedType {
            definition: "exchangeStreamSuccess",
            command: "exchange",
            rust_types: &["crate::commands::network::exchange::output::Event"],
            events: &[
                "complete",
                "diagnostic",
                "response",
                "sent",
                "unanswered",
                "undecoded",
                "unsolicited",
            ],
            example: "examples/documents/output-exchange-complete.json",
        },
    ];
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
        run(invocation, self).map(|()| crate::commands::CommandExit::SUCCESS)
    }
}

fn run(invocation: &crate::invocation::Invocation, arguments: Args) -> Result<(), CliError> {
    let format = invocation.format;
    let stream = &invocation.output;
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
    let draft = Draft {
        timeout: timeout.timeout(),
        stop,
        collection: packetcraftr::exchange::Collection {
            max_responses,
            max_unmatched_frames,
            capture: limits,
            decode: packetcraftr_core::decode::Options {
                limits: packetcraftr_core::packet::Limits {
                    max_packet_size: limits.snap_length,
                    ..packetcraftr_core::packet::Limits::default()
                },
            },
        },
    };
    let Prepared { request, client } = prepare_live(invocation, send, template, draft)?;
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
                    crate::output::contract::Command::Exchange,
                    crate::output::envelope::Published::<output::Report>::try_from(report)
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

struct Draft {
    timeout: std::time::Duration,
    collection: packetcraftr::exchange::Collection,
    stop: packetcraftr::exchange::StopCondition,
}
impl LiveDraft for Draft {
    type Parameters = packetcraftr::exchange::Parameters;
    fn validate(self, max_template_packets: usize) -> Result<Self::Parameters, CliError> {
        Self::Parameters::new(
            self.timeout,
            max_template_packets,
            self.collection,
            self.stop,
        )
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
    fn invalid_exchange_options_precede_recipe_io() {
        let invocation = crate::invocation::Invocation::new(
            Format::Json,
            StreamEncoder::new(Command::Exchange, std::io::sink()).into(),
            None,
            Default::default(),
            None,
        );
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.json");
        let arguments = CommandLine::try_parse_from([
            std::ffi::OsStr::new("exchange"),
            std::ffi::OsStr::new("--packet-file"),
            missing.as_os_str(),
            std::ffi::OsStr::new("--timeout-ms"),
            std::ffi::OsStr::new("0"),
        ])
        .unwrap()
        .arguments;
        let error = run(&invocation, arguments).unwrap_err();
        assert_eq!(
            error.classification.code,
            packetcraftr_core::error::Code::CliExchangeLimit
        );
    }
}
