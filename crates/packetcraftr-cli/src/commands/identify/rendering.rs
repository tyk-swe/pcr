// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;
use crate::output::identify::Report;
use crate::rendering::{duration_text, write_stdout_line};

pub(super) fn render_text(
    report: &Report,
    presentation: crate::rendering::Presentation,
) -> Result<(), CliError> {
    for record in &report.records {
        write_stdout_line(format_args!(
            "{} {} {}",
            record.endpoint.transport, record.endpoint.address, record.outcome
        ))?;
        for probe in &record.probes {
            if !matches!(
                probe.io_outcome,
                crate::output::identify::IoOutcome::Complete
                    | crate::output::identify::IoOutcome::Eof
            ) || probe.observation.outcome
                != crate::output::identify::ObservationOutcome::Complete
            {
                write_stdout_line(format_args!(
                    "  probe={} attempt={} io={} observation={}",
                    probe.probe, probe.attempt, probe.io_outcome, probe.observation.outcome
                ))?;
            }
            for diagnostic in [&probe.diagnostic, &probe.observation.diagnostic]
                .into_iter()
                .flatten()
            {
                write_stdout_line(format_args!("  warning: {diagnostic}"))?;
            }
            if let Some(tls) = &probe.tls
                && tls.certificates_truncated
            {
                write_stdout_line(format_args!("  warning: certificate evidence truncated"))?;
            }
            presentation.details("Probe evidence (unauthenticated)", probe)?;
        }
        for candidate in &record.candidates {
            if !presentation.verbose {
                write_stdout_line(format_args!(
                    "  candidate product={:?} version={:?} confidence={} (inferred, unauthenticated)",
                    candidate.product, candidate.version, candidate.confidence
                ))?;
                continue;
            }
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
