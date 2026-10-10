// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;
use crate::output::identify::Report;
use crate::rendering::{duration_text, write_stdout_line};

pub(super) fn render_text(report: &Report) -> Result<(), CliError> {
    for record in &report.records {
        write_stdout_line(format_args!(
            "{} {} {}",
            record.endpoint.transport, record.endpoint.address, record.outcome
        ))?;
        for probe in &record.probes {
            write_stdout_line(format_args!(
                "  probe={} attempt={} io={} observation={} response_hex={}",
                probe.probe,
                probe.attempt,
                probe.io_outcome,
                probe.observation.outcome,
                probe.response_hex
            ))?;
            for claim in &probe.observation.claims {
                write_stdout_line(format_args!(
                    "    unauthenticated_claim field={} value_hex={}",
                    claim.field, claim.value_hex
                ))?;
            }
        }
        for candidate in &record.candidates {
            write_stdout_line(format_args!(
                "  candidate product={:?} version={:?} confidence={} corpus={:?} corpus_version={:?} probe={:?} rule={:?}",
                candidate.product,
                candidate.version,
                candidate.confidence,
                candidate.provenance.corpus,
                candidate.provenance.version,
                candidate.provenance.probe,
                candidate.provenance.rule
            ))?;
        }
    }
    write_stdout_line(format_args!(
        "corpus={:?} version={:?} exclusions={:?} exclusion_version={:?} complete={} attempts={} write_bytes={} read_bytes={} elapsed={}",
        report.corpus,
        report.corpus_version,
        report.exclusion_set,
        report.exclusion_version,
        report.complete,
        report.usage.attempts,
        report.usage.write_bytes,
        report.usage.read_bytes,
        duration_text(report.elapsed)
    ))
}
