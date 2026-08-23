// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) use crate::command_options::SendArgs;

use std::sync::Arc;

use packetcraftr::{core, output};

use super::super::rendering::{
    emit_aggregate_with_stats, render_diagnostics_text, write_capture_file, write_plain_line,
    write_raw, write_stdout_line,
};
use super::super::system::{client, prepare_route};
use super::registry;
use packetcraftr::BoundaryError;

pub(super) const AFTER_LONG_HELP: &str = r#"Live transmission is policy-gated and may require native features, dependencies, and privileges.

Example:
  packetcraftr send --packet 'ipv4(dst=192.0.2.1)/icmpv4(type=8,code=0)'"#;

pub(super) fn run(
    arguments: SendArgs,
    format: output::contract::Format,
) -> Result<(), BoundaryError> {
    let SendArgs {
        route,
        mode,
        allow_permissive_live,
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
                allow_permissive_live,
            },
        )
        .map_err(BoundaryError::from_error)?;
    let capture_frame = report.sent.frame().clone();
    let (result, diagnostics, stats) =
        output::send::Result::try_from_report(report).map_err(BoundaryError::from_error)?;
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
            write_capture_file(format, [capture_frame])
        }
        _ => unreachable!("send format is checked before command dispatch"),
    }
}
