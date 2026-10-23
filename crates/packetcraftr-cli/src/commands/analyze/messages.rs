// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::commands::offline_analysis::{
    Inspection, complete_application, inspect, require_tcp_stream,
};
use crate::{
    command_options::{
        ApplicationLimitsArgs, DecodeArgs, OfflineLimitsArgs, Selector, stream_selector,
    },
    errors::CliError,
    output::{
        contract::{Command, Format},
        messages as wire,
    },
    rendering::write_stdout_line,
};
use packetcraftr_core::{
    analysis::{
        StreamRef,
        messages::{Collector, Event},
    },
    protocol::BuiltinProtocol,
};
use std::path::PathBuf;

pub(crate) const AFTER_LONG_HELP:&str="Reassemble bounded TCP messages with physical source-frame evidence. Unknown versions remain opaque; framing gaps disable the affected direction.

Examples:
  packetcraftr analyze messages capture.pcap --protocol mqtt
  packetcraftr --output ndjson analyze messages capture.pcap --decode-as tcp.port=1884:mqtt";
#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// PCAP/PCAPNG input; - reads redirected stdin.
    pub(crate) path: PathBuf,
    /// Select supported TCP message protocols; repeat to select several. Defaults to all.
    #[arg(long = "protocol", value_name = "PROTOCOL")]
    pub(crate) protocols: Vec<String>,
    /// Select a whole TCP conversation.
    #[arg(long,value_name="tcp:INDEX",value_parser=stream_selector)]
    pub(crate) stream: Option<Selector<StreamRef>>,
    #[command(flatten)]
    pub(crate) application: ApplicationLimitsArgs,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
}
impl crate::commands::Spec for Args {
    const FORMATS: &'static [Format] = &[Format::Text, Format::Json, Format::Ndjson];
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;
    fn run_time(&self) -> Option<&dyn crate::command_options::Bounded> {
        Some(&self.limits)
    }
    fn resources(&self, s: &mut crate::resources::Settings<'_>) {
        self.application.resources(s);
        self.limits
            .resources(s, crate::command_options::AnalysisStages::with_tcp(true));
    }
    fn run(
        self,
        invocation: &crate::invocation::Invocation,
    ) -> Result<crate::commands::CommandExit, CliError> {
        run(invocation, self)?;
        Ok(crate::commands::CommandExit::SUCCESS)
    }
}
fn selected(names: &[String]) -> Result<Vec<BuiltinProtocol>, CliError> {
    if names.is_empty() {
        return Ok(BuiltinProtocol::ALL
            .iter()
            .copied()
            .filter(|p| p.stream_decode())
            .collect());
    }
    names.iter().map(|name|BuiltinProtocol::from_name_or_alias(&name.to_ascii_lowercase()).filter(|p|p.stream_decode()).ok_or_else(||CliError::new(packetcraftr_core::error::Kind::Usage,format!("{name:?} is not a supported TCP message protocol; see reference protocols")))).collect()
}
fn run(invocation: &crate::invocation::Invocation, args: Args) -> Result<(), CliError> {
    args.application.validate_output()?;
    let collector = Collector::new(
        args.application.core(),
        args.decode.registry()?,
        selected(&args.protocols)?,
    )
    .map_err(CliError::classified)?;
    let selector = require_tcp_stream(args.stream.as_ref(), "message")?;
    let (mut messages, mut issues) = (Vec::new(), Vec::new());
    let outcome = inspect(
        invocation,
        Inspection {
            path: &args.path,
            limits: args.limits,
            decode: &args.decode,
            application: args.application,
            selector,
        },
        collector,
        |output, event| match event {
            Event::Message(m) => output.emit(
                wire::Message::try_from(*m).map_err(CliError::classified)?,
                &mut messages,
                |i, m| {
                    write_stdout_line(
                        i,
                        format_args!(
                            "{} tcp:{} {} {:?} {} bytes",
                            m.index,
                            m.stream,
                            m.protocol,
                            m.status,
                            m.wire_hex.len() / 2
                        ),
                    )
                },
            ),
            Event::Issue(v) => output.emit(wire::Issue::from(v), &mut issues, |i, v| {
                write_stdout_line(
                    i,
                    format_args!("frame {} tcp:{} {:?}", v.number, v.stream, v.status),
                )
            }),
        },
    )?;
    let complete = wire::Complete::try_from((&outcome.run, outcome.summary, outcome.scopes))
        .map_err(CliError::classified)?;
    complete_application(
        invocation,
        Command::Messages,
        complete,
        |complete| wire::Report {
            messages,
            issues,
            complete,
        },
        |i, c| {
            write_stdout_line(
                i,
                format_args!(
                    "{} messages, {} complete, {} incomplete",
                    c.summary.messages, c.summary.complete_messages, c.summary.incomplete_messages
                ),
            )
        },
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_selection_rejects_datagram_only_codecs() {
        assert!(selected(&["coap".into()]).is_err());
        assert_eq!(
            selected(&["MQTT".into()]).unwrap(),
            vec![BuiltinProtocol::Mqtt]
        );
    }
}
