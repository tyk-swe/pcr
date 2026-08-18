// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod arguments;

pub(super) use crate::command_options::SendArgs;
pub(super) use arguments::AFTER_LONG_HELP;

use std::sync::Arc;
use std::time::SystemTime;

use packetcraftr::{
    core::{
        self,
        frame::{Frame, LinkType},
    },
    netio as net, output,
};

use super::super::errors::CliError;
use super::super::rendering::{
    emit_aggregate_with_stats, render_diagnostics_text, write_capture_file, write_plain_line,
    write_raw, write_stdout_line,
};
use super::super::system::{client, prepare_route};
use super::registry;

pub(super) fn run(arguments: SendArgs, format: output::contract::Format) -> Result<(), CliError> {
    let SendArgs {
        route,
        mode,
        confirm_live_opt_in,
        policy,
    } = arguments;
    let registry = registry()?;
    let request = prepare_route(route, policy.into_policy(), &registry)?;
    let client = client(Arc::clone(&registry), request.policy);
    let report = client
        .send(
            request.packet,
            packetcraftr::send::Options {
                destination: request.destination,
                plan: request.options,
                build: core::build::Options {
                    mode: mode.into(),
                    ..core::build::Options::default()
                },
                confirm_live_opt_in,
            },
        )
        .map_err(CliError::classified)?;
    let capture_link_type = capture_link_type(
        report.sent.route().plan.mode,
        report.sent.route().plan.decision.link_type,
    )?;
    let (result, diagnostics, stats) =
        output::send::Result::try_from_report(report).map_err(CliError::classified)?;
    match format {
        output::contract::Format::Text => {
            write_stdout_line(format_args!(
                "sent {} bytes via {} (index {}, {:?})",
                result.frame.length,
                result.route.plan.decision.interface.name,
                result.route.plan.decision.interface.index,
                result.route.plan.mode
            ))?;
            render_diagnostics_text(&diagnostics)
        }
        output::contract::Format::Json => {
            emit_aggregate_with_stats(output::contract::Command::Send, result, diagnostics, stats)
        }
        output::contract::Format::Hex => {
            write_plain_line(format_args!("{}", result.frame.bytes_hex()))
        }
        output::contract::Format::Raw => write_raw(result.frame.bytes()),
        output::contract::Format::Pcap | output::contract::Format::PcapNg => {
            let frame = Frame::new(
                SystemTime::now(),
                capture_link_type,
                result.frame.bytes().to_vec(),
            )
            .map_err(|source| CliError::new(3, source.to_string()))?;
            write_capture_file(format, [frame])
        }
        _ => unreachable!("send format is checked before command dispatch"),
    }
}

fn capture_link_type(
    mode: net::link::Mode,
    route_link_type: LinkType,
) -> Result<LinkType, CliError> {
    match mode {
        net::link::Mode::Layer2 => Ok(route_link_type),
        net::link::Mode::Layer3 => Ok(LinkType::RAW),
        net::link::Mode::Auto => Err(CliError::new(
            70,
            "send result retained an unresolved automatic link mode",
        )),
    }
}
