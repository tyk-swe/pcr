// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;

use std::sync::Arc;
use std::time::SystemTime;

use packetcraftr::{
    live as client, network as net, output, packet,
    packet::frame::{Frame, LinkType},
};

use self::arguments::SendArgs;
use super::super::errors::CliError;
use super::super::rendering::{
    emit_aggregate_with_stats, render_diagnostics_text, write_capture_file, write_plain_line,
    write_raw, write_stdout_line,
};
use super::super::system::{default_registry_arc, prepare_route_request, system_client};

pub(super) fn run(arguments: SendArgs, output: output::contract::Format) -> Result<(), CliError> {
    let SendArgs {
        route,
        mode,
        allow_permissive_live,
        policy,
    } = arguments;
    let registry = default_registry_arc()?;
    let request = prepare_route_request(route, policy.into_policy(), &registry)?;
    let client = system_client(Arc::clone(&registry), request.policy);
    let report = client
        .send(
            request.packet,
            client::send::Options {
                destination: request.destination,
                plan: request.options,
                build: packet::build::Options {
                    mode: mode.into(),
                    ..packet::build::Options::default()
                },
                allow_permissive_live,
            },
        )
        .map_err(CliError::classified)?;
    let capture_link_type = send_capture_link_type(
        report.sent.route().plan.mode,
        report.sent.route().plan.route.link_type,
    )?;
    let (result, diagnostics, stats) =
        output::send::Result::try_from_report(report).map_err(CliError::classified)?;
    match output {
        output::contract::Format::Text => {
            write_stdout_line(format_args!(
                "sent {} bytes via {} (index {}, {:?})",
                result.frame.length,
                result.route.plan.route.interface.name,
                result.route.plan.route.interface.index,
                result.route.plan.mode
            ))?;
            render_diagnostics_text(&diagnostics)
        }
        output::contract::Format::Json => {
            emit_aggregate_with_stats(output::contract::Command::Send, result, diagnostics, stats)
        }
        output::contract::Format::Hex => {
            write_plain_line(format_args!("{}", result.frame.bytes_hex))
        }
        output::contract::Format::Raw => write_raw(result.frame.bytes()),
        output::contract::Format::Pcap | output::contract::Format::Pcapng => {
            let frame = Frame::new(
                SystemTime::now(),
                capture_link_type,
                result.frame.bytes().to_vec(),
            )
            .map_err(|source| CliError::new(3, source.to_string()))?;
            write_capture_file(output, [frame])
        }
        _ => Err(CliError::classified(
            output::contract::Error::UnsupportedFormat {
                command: output::contract::Command::Send,
                format: output,
            },
        )),
    }
}

fn send_capture_link_type(
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
