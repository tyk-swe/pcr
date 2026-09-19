// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;

use packetcraftr_cli::output::contract::SendFormat;

use std::sync::Arc;

use packetcraftr_core as core;
use packetcraftr_core::analysis::pcap as capture;

use packetcraftr_cli::output;

use self::arguments::Args;
use crate::errors::CliError;
use crate::input::read_recipe;
use crate::rendering::{
    emit_aggregate_with_stats, render_diagnostics_text, write_capture_file, write_plain_line,
    write_raw, write_summary_line,
};
use crate::system::{Client, client, prepare_packet_route};

/// The recipe, route, and set-execution options with a client bound to the
/// same policy.
struct PreparedSend {
    template: core::template::Template,
    options: packetcraftr::send::SetOptions,
    client: Client,
}

fn prepare(arguments: Args) -> Result<PreparedSend, CliError> {
    let Args {
        send,
        template,
        repeat,
        rate,
    } = arguments;
    let max_template_packets = template.max_template_packets;
    let axes = template.parse()?;
    let registry = packetcraftr_core::protocol::builtin::registry();
    let packet = read_recipe(
        send.route.recipe,
        &registry,
        core::layout::DEFAULT_MAX_LAYERS,
    )?;
    let template = axes.into_template(packet);
    let policy = send.policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    let mut options = packetcraftr::send::SetOptions {
        repeat,
        rate,
        max_template_packets,
        ..Default::default()
    };
    let total = options
        .validate_for(&template)
        .map_err(CliError::classified)?;
    policy
        .authorize(packetcraftr::policy::Operation::Budgeted(
            packetcraftr::policy::WireBudget::new(total, 0),
        ))
        .map_err(CliError::classified)?;
    let first =
        crate::system::authorize_expanded_destinations(&template, max_template_packets, &policy)?;
    let prepared = prepare_packet_route(first, send.route.destination, send.route.route, policy)?;
    let client = client(Arc::clone(&registry), prepared.policy);
    options.send = packetcraftr::send::Options {
        destination: prepared.destination,
        plan: prepared.options,
        build: core::build::Options {
            mode: send.mode.into(),
            ..core::build::Options::default()
        },
        allow_permissive_live: send.allow_permissive_live,
    };
    Ok(PreparedSend {
        template,
        options,
        client,
    })
}

/// Maps a per-frame rendering failure into the workflow's output channel.
fn output_failure(error: CliError) -> packetcraftr::Error {
    packetcraftr::Error::SendOutput {
        source: Box::new(packetcraftr_core::error::BoundaryError::new(
            error.message,
            error.classification,
            error.causes,
        )),
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

pub(super) fn run(arguments: Args, format: SendFormat) -> Result<(), CliError> {
    let compression = arguments.send.compression;
    compression.validate(format.as_format())?;
    let prepared = prepare(arguments)?;
    match format {
        SendFormat::Text => {
            // Each confirmed frame is reported as it happens, so partial
            // progress is preserved when a later frame fails.
            let report = prepared
                .client
                .send_set_with_events(&prepared.template, prepared.options, |frame| {
                    write_summary_line(format_args!("{}", sent_line(frame))).map_err(output_failure)
                })
                .map_err(CliError::classified)?;
            let diagnostics = collect_diagnostics(&report);
            if report.sent.len() > 1 {
                write_summary_line(format_args!(
                    "sent {} frame(s), {} byte(s) across {} pass(es)",
                    report.stats.packets_completed, report.stats.bytes, report.passes_completed
                ))?;
            }
            render_diagnostics_text(&diagnostics)
        }
        SendFormat::Json => {
            let report = prepared
                .client
                .send_set(&prepared.template, prepared.options)
                .map_err(CliError::classified)?;
            let (result, diagnostics, stats) =
                output::send::Report::try_from_report(report).map_err(CliError::classified)?;
            emit_aggregate_with_stats(output::contract::Command::Send, result, diagnostics, stats)
        }
        SendFormat::Hex => prepared
            .client
            .send_set_with_events(&prepared.template, prepared.options, |frame| {
                write_plain_line(format_args!(
                    "{}",
                    output::frame::Wire::new(frame.packet.wire_bytes().clone()).bytes_hex()
                ))
                .map_err(output_failure)
            })
            .map_err(CliError::classified)
            .map(|_| ()),
        SendFormat::Raw => prepared
            .client
            .send_set_with_events(&prepared.template, prepared.options, |frame| {
                write_raw(frame.packet.wire_bytes()).map_err(output_failure)
            })
            .map_err(CliError::classified)
            .map(|_| ()),
        SendFormat::Pcap | SendFormat::PcapNg => {
            // The report already holds every confirmed frame, in order.
            let report = prepared
                .client
                .send_set(&prepared.template, prepared.options)
                .map_err(CliError::classified)?;
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

fn collect_diagnostics(
    report: &packetcraftr::send::SetReport,
) -> Vec<core::diagnostic::Diagnostic> {
    let mut diagnostics = Vec::new();
    for frame in &report.sent {
        for diagnostic in &frame.packet.built().diagnostics {
            core::diagnostic::push_once(&mut diagnostics, diagnostic.clone());
        }
    }
    diagnostics
}
