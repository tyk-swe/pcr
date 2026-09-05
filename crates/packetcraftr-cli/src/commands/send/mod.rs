// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::output::contract::Format;

pub(super) use crate::command_options::SendArgs;

use std::sync::Arc;

use packetcraftr::{analysis::pcap as capture, core, output};

use super::registry;
use crate::errors::CliError;
use crate::rendering::{
    emit_aggregate_with_stats, render_diagnostics_text, write_capture_file, write_plain_line,
    write_raw, write_summary_line,
};
use crate::system::{Client, client, prepare_route};

pub(super) const AFTER_LONG_HELP: &str = r#"Live transmission is policy-gated and may require native features, dependencies, and privileges.

Example:
  packetcraftr send --packet 'ipv4(dst=192.0.2.1)/icmpv4(type=8,code=0)'"#;

/// One `SendArgs` resolved into everything a transmitting command needs: the
/// registry it dissects with, the packet, the send options, and a client bound
/// to the same policy.
///
/// `send` transmits it directly; `exchange` transmits the same packet and then
/// captures against it, so both resolve the route the same way.
pub(super) struct PreparedSend {
    pub(super) packet: core::Packet,
    pub(super) options: packetcraftr::send::Options,
    pub(super) client: Client,
}

pub(super) fn prepare(arguments: SendArgs) -> Result<PreparedSend, CliError> {
    let SendArgs {
        route,
        mode,
        allow_permissive_live,
        policy,
    } = arguments;
    let registry = registry()?;
    let request = prepare_route(route, policy.into_policy(), &registry)?;
    let client = client(Arc::clone(&registry), request.policy);
    Ok(PreparedSend {
        packet: request.packet,
        options: packetcraftr::send::Options {
            destination: request.destination,
            plan: request.options,
            build: core::build::Options {
                mode: mode.into(),
                ..core::build::Options::default()
            },
            allow_permissive_live,
        },
        client,
    })
}

pub(super) fn run(arguments: SendArgs, format: Format) -> Result<(), CliError> {
    let prepared = prepare(arguments)?;
    let report = prepared
        .client
        .send(prepared.packet, prepared.options)
        .map_err(CliError::classified)?;
    let capture_frame = report.sent.frame().clone();
    let (result, diagnostics, stats) =
        output::send::Report::try_from_report(report).map_err(CliError::classified)?;
    match format {
        Format::Text => {
            write_summary_line(format_args!(
                "sent {} bytes via {} (index {}, {})",
                result.frame.length,
                result.route.plan.decision.interface.name,
                result.route.plan.decision.interface.index,
                result.route.plan.mode
            ))?;
            render_diagnostics_text(&diagnostics)
        }
        Format::Json => {
            emit_aggregate_with_stats(output::contract::Command::Send, result, diagnostics, stats)
        }
        Format::Hex => write_plain_line(format_args!("{}", result.frame.bytes_hex())),
        Format::Raw => write_raw(result.frame.bytes()),
        Format::Pcap => write_capture_file(capture::Format::Pcap, [capture_frame]),
        Format::PcapNg => write_capture_file(capture::Format::PcapNg, [capture_frame]),
        _ => unreachable!("command dispatch validated the output format"),
    }
}
