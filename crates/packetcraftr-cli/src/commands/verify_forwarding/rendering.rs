// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_cli::output::contract::ToolFormat;
use packetcraftr_cli::output::{self, forwarding::Report};
use packetcraftr_core::analysis::forwarding as analysis;
use packetcraftr_core::field::FieldValue;

use super::arguments::Args;
use crate::commands::offline_analysis::omitted_diagnostic;
use crate::errors::CliError;
use crate::rendering::{StreamEncoder, emit_json, write_stdout_line};

pub(super) fn render(
    format: ToolFormat,
    stream: &StreamEncoder,
    report: &analysis::Report,
    arguments: &Args,
    sources: analysis::Sided<output::forwarding::CaptureSource>,
) -> Result<(), CliError> {
    match format {
        ToolFormat::Text => {
            render_text(report)?;
            for (side, source) in [("ingress", sources.ingress), ("egress", sources.egress)] {
                write_stdout_line(format_args!(
                    "{side} source: sha256 {}, {} encoded bytes consumed through EOF",
                    source.sha256, source.encoded_bytes,
                ))?;
            }
            Ok(())
        }
        ToolFormat::Json | ToolFormat::Ndjson => {
            let mut document = Report::from_report(
                report,
                analysis::Sided {
                    ingress: arguments.ingress.display().to_string(),
                    egress: arguments.egress.display().to_string(),
                },
            )?;
            document.captures.ingress.source = Some(sources.ingress);
            document.captures.egress.source = Some(sources.egress);
            document.captures.ingress.selection_filter = arguments.ingress_filter.clone();
            document.captures.egress.selection_filter = arguments.egress_filter.clone();
            document.decode = Some(output::forwarding::DecodeContext {
                tls_ports: arguments.decode.ports.clone(),
                bindings: arguments.decode.bindings.clone(),
            });
            let diagnostics = omitted_diagnostic(
                "verify_forwarding.details_omitted",
                "report detail entries",
                omitted_total(&report.omitted),
                "--max-details / --max-detail-bytes",
            );
            if format == ToolFormat::Json {
                let envelope = crate::resources::decorate(output::envelope::Envelope::success(
                    output::contract::Command::VerifyForwarding,
                    document,
                    diagnostics,
                ));
                // Measure the complete pretty-printed envelope, including its
                // indentation and resources, and reserve the final newline.
                crate::rendering::bounded_pretty_json_len(
                    &envelope,
                    output::stream::MAX_RECORD_BYTES - 1,
                )
                .map_err(|error| error.into_cli_error(report_limit_error))?;
                crate::cancellation::check()?;
                emit_json(&envelope)
            } else {
                // Guard the composition, not just individual detail lists.
                // The stream encoder also bounds the complete compact record.
                crate::rendering::bounded_json_len(
                    &document,
                    output::stream::MAX_RECORD_BYTES - 1024 * 1024,
                )
                .map_err(|error| error.into_cli_error(report_limit_error))?;
                crate::cancellation::check()?;
                Ok(stream.complete(document, diagnostics)?)
            }
        }
    }
}

fn report_limit_error() -> CliError {
    CliError::from_classification(
        packetcraftr_core::error::Classification::new(
            "policy.verify_report_limit",
            packetcraftr_core::error::Kind::Policy,
            Some("reduce the report detail budget"),
        ),
        "forwarding report exceeds its publication budget",
        Vec::new(),
    )
}

fn omitted_total(omitted: &analysis::Omissions) -> u64 {
    omitted
        .matches
        .saturating_add(omitted.violations)
        .saturating_add(omitted.unmatched_ingress)
        .saturating_add(omitted.unmatched_egress)
        .saturating_add(omitted.unkeyed_ingress)
        .saturating_add(omitted.unkeyed_egress)
        .saturating_add(omitted.ambiguous_groups)
        .saturating_add(omitted.group_members)
}

const fn verdict_text(verdict: analysis::Verdict) -> &'static str {
    match verdict {
        analysis::Verdict::Pass => "pass",
        analysis::Verdict::Fail => "fail",
        analysis::Verdict::Inconclusive => "inconclusive",
    }
}

fn value_text(value: Option<&FieldValue>) -> String {
    value.map_or_else(|| "<absent>".to_owned(), ToString::to_string)
}

fn key_text(key: &[FieldValue]) -> String {
    key.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_text(report: &analysis::Report) -> Result<(), CliError> {
    write_stdout_line(format_args!("verdict: {}", verdict_text(report.verdict)))?;
    let rules = &report.rules;
    let comparison = match rules.comparison {
        analysis::ComparisonKind::CorrespondenceOnly => "correspondence_only",
        analysis::ComparisonKind::PropertyChecks => "property_checks",
    };
    write_stdout_line(format_args!("comparison: {comparison}"))?;
    for warning in &rules.warnings {
        write_stdout_line(format_args!(
            "warning {}: {}",
            warning.code, warning.message
        ))?;
    }
    if !rules.preserve_presence.is_empty() || !rules.expect_absent.is_empty() {
        write_stdout_line(format_args!(
            "decoder-view presence rules: preserve [{}]; expect absent [{}]",
            rules.preserve_presence.join(", "),
            rules.expect_absent.join(", "),
        ))?;
    }
    write_stdout_line(format_args!(
        "rules: identity [{}]; preserve [{}]; expect [{}]",
        rules.identity.join(", "),
        rules.preserve.join(", "),
        rules
            .expect
            .iter()
            .map(|rule| format!("{}={}", rule.field, rule.value))
            .collect::<Vec<_>>()
            .join(", "),
    ))?;
    for (side, capture) in [
        ("ingress", &report.sides.ingress),
        ("egress", &report.sides.egress),
    ] {
        write_stdout_line(format_args!(
            "{side}: {} read, {} selected ({} keyed, {} unkeyed, {} incomplete)",
            capture.read, capture.selected, capture.keyed, capture.unkeyed, capture.incomplete,
        ))?;
    }
    let summary = &report.summary;
    write_stdout_line(format_args!(
        "matches: {} unique ({} reordered); unmatched: {} ingress, {} egress; ambiguous: {} group(s), {} observation(s)",
        summary.unique_matches,
        summary.reordered_pairs,
        summary.ingress_only,
        summary.egress_only,
        summary.ambiguous_groups,
        summary.ambiguous_observations,
    ))?;
    write_stdout_line(format_args!(
        "checks: {} evaluated ({} satisfied, {} violated, {} unevaluable)",
        summary.checks_evaluated,
        summary.checks_satisfied,
        summary.checks_violated,
        summary.checks_unevaluable,
    ))?;
    for violation in &report.violations {
        write_stdout_line(format_args!("{}", violation_text(violation)))?;
    }
    for (side, list) in [
        ("ingress", &report.unmatched.ingress),
        ("egress", &report.unmatched.egress),
    ] {
        for evidence in list {
            write_stdout_line(format_args!("unmatched {side} frame {}", evidence.frame))?;
        }
    }
    for (side, list) in [
        ("ingress", &report.unkeyed.ingress),
        ("egress", &report.unkeyed.egress),
    ] {
        for observation in list {
            write_stdout_line(format_args!(
                "unkeyed {side} frame {}",
                observation.evidence.frame
            ))?;
        }
    }
    for group in &report.ambiguous {
        write_stdout_line(format_args!(
            "ambiguous identity [{}]: {} ingress and {} egress observation(s), never paired",
            key_text(&group.key),
            group.ingress_total,
            group.egress_total,
        ))?;
    }
    let omitted = omitted_total(&report.omitted);
    if omitted > 0 {
        write_stdout_line(format_args!(
            "{omitted} report detail entries omitted by --max-details / --max-detail-bytes"
        ))?;
    }
    for assumption in report.assumptions {
        write_stdout_line(format_args!("assumption: {assumption}"))?;
    }
    Ok(())
}

fn violation_text(violation: &analysis::Violation) -> String {
    let check = &violation.check;
    match check.kind {
        analysis::CheckKind::Preserve => format!(
            "violation: preserve {} — ingress frame {} carried {}, egress frame {} carried {}",
            check.field,
            violation
                .ingress
                .as_ref()
                .map_or_else(|| "?".to_owned(), |evidence| evidence.frame.to_string()),
            value_text(violation.expected.as_ref()),
            violation.egress.frame,
            value_text(violation.actual.as_ref()),
        ),
        analysis::CheckKind::PreservePresence => format!(
            "violation: preserve presence {} — ingress {}, egress {}",
            check.field,
            value_text(violation.expected.as_ref()),
            value_text(violation.actual.as_ref()),
        ),
        analysis::CheckKind::ExpectAbsent => format!(
            "violation: expect absence {} — egress frame {} carried {}",
            check.field,
            violation.egress.frame,
            value_text(violation.actual.as_ref()),
        ),
        analysis::CheckKind::Expect => format!(
            "violation: expect {}={} — egress frame {} carried {}",
            check.field,
            check.value.as_deref().unwrap_or("?"),
            violation.egress.frame,
            value_text(violation.actual.as_ref()),
        ),
    }
}
