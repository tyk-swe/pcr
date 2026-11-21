// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::{Path, PathBuf};

use clap::Args;
use packetcraftr_core::error::Kind;
use packetcraftr_core::security::{bundle, diff};

use crate::commands::security::{Bounds, input, invalid, read, source};
use crate::commands::{CommandExit, Generate};
use crate::errors::CliError;
use crate::output::contract::Format;
use crate::terminal::emit_stdout_document;

pub(crate) const PLAN_AFTER_LONG_HELP: &str = r"Emit an ordered retest checklist from an engagement journal. Bundles and journals deliberately do not record command arguments, so each step names the command and the digests a rerun must reproduce or consciously supersede rather than pretending the original invocation can be replayed. With --bundle, the bundle must be anchored to this journal head. Compare the rerun results with analyze findings-diff.

Example:
  packetcraftr analyze retest-plan --journal journal.json --bundle bundle.json";

#[derive(Debug, Args)]
pub(crate) struct RetestPlan {
    /// Engagement journal to turn into a retest checklist.
    #[arg(long)]
    journal: PathBuf,
    /// Evidence bundle that must be anchored to the journal head.
    #[arg(long)]
    bundle: Option<PathBuf>,
    #[command(flatten)]
    bounds: Bounds,
}

pub(crate) const FINDINGS_AFTER_LONG_HELP: &str = r"Compare findings from two aggregate JSON results by rule and subject. Repeated findings keep their multiplicity, a severity change is reported separately from presence, and coverage is never inferred: this compares the supplied reports, it does not rerun either assessment.

Example:
  packetcraftr analyze findings-diff before.json after.json";

pub(crate) const BUNDLE_AFTER_LONG_HELP: &str = r"Parse and validate a packetcraftr.bundle/v1 Evidence bundle: its kind must match the embedded report, its sources must match the report exactly, and its inputs digest must recompute. Each optional result file is also required to match a bundle source by SHA-256. Sources without a supplied file are counted as unverified, because their bytes are not embedded in the bundle.

Example:
  packetcraftr analyze bundle-verify bundle.json scan.json Hunt.json";

#[derive(Debug, Args)]
pub(crate) struct FindingsDiff {
    /// Earlier aggregate JSON result.
    before: PathBuf,
    /// Later aggregate JSON result.
    after: PathBuf,
    #[command(flatten)]
    bounds: Bounds,
}

#[derive(Debug, Args)]
pub(crate) struct BundleVerify {
    /// Evidence bundle JSON file.
    bundle: PathBuf,
    /// Files whose exact bytes must appear among the bundle sources.
    results: Vec<PathBuf>,
    #[command(flatten)]
    bounds: Bounds,
}

fn require_text(format: Format, command: &str) -> Result<(), CliError> {
    if format != Format::Text {
        return Err(CliError::new(
            Kind::Usage,
            format!("{command} prints text only, not --output {format}"),
        ));
    }
    Ok(())
}

fn check_stdin(paths: impl IntoIterator<Item = impl AsRef<Path>>) -> Result<(), CliError> {
    if paths
        .into_iter()
        .filter(|path| path.as_ref() == Path::new("-"))
        .count()
        > 1
    {
        return Err(invalid("stdin may serve at most one input"));
    }
    Ok(())
}

fn absent(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("-")
}

fn severities(values: &[packetcraftr_core::security::Severity]) -> String {
    values
        .iter()
        .map(|value| format!("{value:?}").to_lowercase())
        .collect::<Vec<_>>()
        .join(",")
}

impl Generate for FindingsDiff {
    fn generate(
        self,
        invocation: &crate::invocation::Invocation,
        format: Format,
    ) -> Result<CommandExit, CliError> {
        require_text(format, "findings-diff")?;
        check_stdin([&self.before, &self.after])?;
        let before = input::report(&read(
            invocation,
            &self.before,
            self.bounds.max_result_bytes,
        )?)?;
        let after = input::report(&read(
            invocation,
            &self.after,
            self.bounds.max_result_bytes,
        )?)?;
        let diff = diff::diff_reports(&before, &after);
        let mut text = format!(
            "before_kind={} after_kind={} new={} still_present={} fixed={} severity_changed={}\n",
            before.kind,
            after.kind,
            diff.new_findings.len(),
            diff.still_present.len(),
            diff.fixed.len(),
            diff.severity_changed.len(),
        );
        for (label, rows) in [
            ("new", &diff.new_findings),
            ("still_present", &diff.still_present),
            ("fixed", &diff.fixed),
            ("severity_changed", &diff.severity_changed),
        ] {
            for row in rows {
                text.push_str(&format!(
                    "{label} rule={} subject={} before={} after={} before_severities={} after_severities={}\n",
                    row.key.rule_id,
                    row.key.subject,
                    row.before,
                    row.after,
                    severities(&row.before_severities),
                    severities(&row.after_severities),
                ));
            }
        }
        emit_stdout_document(invocation, &text)?;
        Ok(CommandExit::SUCCESS)
    }
}

impl Generate for BundleVerify {
    fn generate(
        self,
        invocation: &crate::invocation::Invocation,
        format: Format,
    ) -> Result<CommandExit, CliError> {
        require_text(format, "bundle-verify")?;
        check_stdin(std::iter::once(&self.bundle).chain(self.results.iter()))?;
        let bytes = read(invocation, &self.bundle, bundle::MAX_BUNDLE_DOCUMENT_BYTES)?;
        let bundle = bundle::Bundle::parse(&bytes).map_err(CliError::classified)?;
        let mut matched_sources = std::collections::BTreeSet::new();
        for path in &self.results {
            let bytes = read(invocation, path, self.bounds.max_result_bytes)?;
            let supplied = source(path, &bytes);
            let matching: Vec<usize> = bundle
                .sources
                .iter()
                .enumerate()
                .filter(|(_, source)| source.sha256 == supplied.sha256)
                .map(|(index, _)| index)
                .collect();
            if matching.is_empty() {
                return Err(invalid(format!(
                    "result {} with sha256 {} is not a bundle source",
                    path.display(),
                    supplied.sha256
                )));
            }
            matched_sources.extend(matching);
        }
        let scope = bundle.scope.as_ref().map_or_else(
            || "-".to_owned(),
            |scope| format!("{}:{}", scope.label, scope.digest),
        );
        emit_stdout_document(
            invocation,
            &format!(
                "bundle schema={} kind={} tool_version={} sources={} inputs_digest={} scope={scope} matched={} unverified_sources={} valid=true\n",
                bundle.schema,
                bundle.kind,
                bundle.tool_version,
                bundle.sources.len(),
                bundle.inputs_digest,
                matched_sources.len(),
                bundle.sources.len() - matched_sources.len(),
            ),
        )?;
        Ok(CommandExit::SUCCESS)
    }
}

impl Generate for RetestPlan {
    fn generate(
        self,
        invocation: &crate::invocation::Invocation,
        format: Format,
    ) -> Result<(), CliError> {
        require_text(format, "retest-plan")?;
        check_stdin(std::iter::once(&self.journal).chain(self.bundle.iter()))?;
        let journal_bytes = read(
            invocation,
            &self.journal,
            packetcraftr_core::security::journal::MAX_JOURNAL_DOCUMENT_BYTES,
        )?;
        let journal = packetcraftr_core::security::journal::Journal::parse(&journal_bytes)
            .map_err(CliError::classified)?;
        let anchored = if let Some(bundle_path) = &self.bundle {
            let bundle_bytes = read(invocation, bundle_path, bundle::MAX_BUNDLE_DOCUMENT_BYTES)?;
            let bundle = bundle::Bundle::parse(&bundle_bytes).map_err(CliError::classified)?;
            let anchored_head = bundle
                .report
                .measurements
                .get("journal_head")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| invalid("bundle is not anchored to a journal head"))?;
            if anchored_head != journal.head() {
                return Err(invalid(
                    "bundle journal head does not match the supplied journal",
                ));
            }
            true
        } else {
            false
        };
        let mut text = format!(
            "retest_plan journal_label={} journal_head={} records={} bundle_anchored={anchored} arguments_recorded=false\n",
            journal.label,
            journal.head(),
            journal.records.len(),
        );
        for record in &journal.records {
            text.push_str(&format!(
                "step={} rerun_command={} result_sha256={} scope_digest={} plan_digest={}\n",
                record.sequence,
                record.command,
                record.result_sha256,
                absent(&record.scope_digest),
                absent(&record.plan_digest),
            ));
        }
        text.push_str(
            "note: rerun each named command with its engagement inputs, then compare with analyze findings-diff\n",
        );
        let _ = self.bounds;
        emit_stdout_document(invocation, &text)
    }
}
