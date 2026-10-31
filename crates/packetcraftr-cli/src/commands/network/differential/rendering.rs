// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::differential as lib;

use crate::errors::CliError;
use crate::invocation::StreamEncoder;
use crate::output;
use crate::rendering::write_stdout_line;

pub(super) fn render_plan_text(
    invocation: &crate::invocation::Invocation,
    plan: &output::differential::PlanReport,
) -> Result<(), CliError> {
    write_stdout_line(invocation, format_args!("plan_digest={}", plan.plan_digest))?;
    write_stdout_line(invocation, format_args!("token={}", plan.token))?;
    write_stdout_line(
        invocation,
        format_args!(
            "repeats={} total_packets={} total_wire_bytes={}",
            plan.repeats, plan.total_packets, plan.total_wire_bytes
        ),
    )?;
    for row in &plan.rows {
        write_stdout_line(
            invocation,
            format_args!(
                "variant={} packets_per_attempt={} hypothesis={}",
                row.variant, row.packets_per_attempt, row.hypothesis
            ),
        )?;
    }
    Ok(())
}

pub(super) fn render_report_text(
    invocation: &crate::invocation::Invocation,
    report: &output::differential::Report,
) -> Result<(), CliError> {
    write_stdout_line(
        invocation,
        format_args!(
            "valid={} provisional={} plan_digest={}",
            report.valid, report.provisional, report.plan_digest
        ),
    )?;
    for row in &report.rows {
        write_stdout_line(
            invocation,
            format_args!(
                "variant={} verdict={} answered={}/{}",
                row.variant, row.verdict, row.answered, row.attempts
            ),
        )?;
    }
    Ok(())
}

pub(super) fn emit_event(event: lib::Event, stream: &StreamEncoder) -> Result<(), CliError> {
    let published = output::envelope::Published::<output::differential::Event>::try_from(event)
        .map_err(CliError::classified)?;
    Ok(stream.emit_published(published)?)
}

pub(super) fn render_complete(report: lib::Report, stream: &StreamEncoder) -> Result<(), CliError> {
    Ok(stream.complete_published(
        output::envelope::Published::<output::differential::Event>::from(report),
    )?)
}

pub(super) fn emit_responder_event(
    event: lib::ResponderEvent,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    Ok(stream.emit_published(output::envelope::Published::<
        output::differential::ResponderEvent,
    >::from(event))?)
}

pub(super) fn render_responder_complete(
    report: lib::ResponderReport,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    Ok(stream.complete_published(output::envelope::Published::<
        output::differential::ResponderEvent,
    >::from(report))?)
}

pub(super) fn render_responder_text(
    invocation: &crate::invocation::Invocation,
    report: &output::differential::ResponderReport,
) -> Result<(), CliError> {
    write_stdout_line(
        invocation,
        format_args!(
            "received={} ignored={} replies_sent={}",
            report.received, report.ignored, report.replies_sent
        ),
    )?;
    for record in &report.records {
        write_stdout_line(
            invocation,
            format_args!(
                "variant={} attempt={} source={} payload_sha256={}",
                record.variant, record.attempt_seq, record.source, record.payload_sha256
            ),
        )?;
    }
    Ok(())
}
