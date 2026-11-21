// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Write;
use std::path::PathBuf;

use clap::Args;
use packetcraftr_core::error::Kind;
use packetcraftr_core::security::journal::{Journal, RecordInput};
use packetcraftr_core::security::{self, input as aggregate_input};
use serde_json::Value;

use crate::commands::security::{Bounds, input, invalid, read};
use crate::commands::{CommandExit, Generate};
use crate::errors::CliError;
use crate::output::contract::Format;
use crate::terminal::emit_stdout_document;

pub(crate) const BUILD_AFTER_LONG_HELP: &str = r"Builds a hash-chained engagement journal from successful aggregate JSON results, in the order given. Each record binds the command, the SHA-256 of the exact result file bytes, the Scope digest when --scope-file is given, and a plan digest when the result carries one. The output is a new packetcraftr.journal/v1 file and existing destinations are refused. Nothing is sent.

Example:
  packetcraftr analyze journal-build --label lab-segment --journal journal.json --scope-file scope.json scan.json hunt.json";

pub(crate) const VERIFY_AFTER_LONG_HELP: &str = r"Verifies a packetcraftr.journal/v1 hash chain and, for every result file given, that its exact bytes and command appear as a journal record. Records without a supplied result file are counted as unverified rather than treated as failures. Nothing is sent.

Example:
  packetcraftr analyze journal-verify journal.json scan.json hunt.json";

#[derive(Debug, Args)]
pub(crate) struct Build {
    /// Successful aggregate JSON result files, journaled in this order. One
    /// input may be - to read redirected JSON stdin.
    #[arg(required = true, num_args = 1..)]
    results: Vec<PathBuf>,
    /// Printable journal label, 1 to 128 characters.
    #[arg(long)]
    label: String,
    /// New packetcraftr.journal/v1 JSON file; existing destinations are refused.
    #[arg(long)]
    journal: PathBuf,
    #[command(flatten)]
    bounds: Bounds,
    #[command(flatten)]
    scope: crate::command_options::ScopeArgs,
}

#[derive(Debug, Args)]
pub(crate) struct Verify {
    /// The packetcraftr.journal/v1 file to verify.
    journal: PathBuf,
    /// Result files whose exact bytes must appear in the journal.
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

pub(in crate::commands) fn record_input(
    bytes: &[u8],
    scope_digest: Option<String>,
) -> Result<RecordInput, CliError> {
    let allowed: Vec<&str> = crate::commands::Command::ALL
        .iter()
        .map(|command| command.as_str())
        .collect();
    let envelope = aggregate_input::aggregate::<Value>(bytes, &allowed)
        .map_err(|error| invalid(error.to_string()))?;
    let plan_digest = envelope
        .result
        .get("plan_digest")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(RecordInput {
        command: envelope.command,
        result_sha256: crate::output::hex::compact_hex(&sha256(bytes)),
        scope_digest,
        plan_digest,
    })
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

impl Generate for Build {
    fn generate(
        self,
        invocation: &crate::invocation::Invocation,
        format: Format,
    ) -> Result<CommandExit, CliError> {
        require_text(format, "journal-build")?;
        if self.results.len() > security::journal::MAX_JOURNAL_RECORDS {
            return Err(invalid(format!(
                "journal-build accepts at most {} result files",
                security::journal::MAX_JOURNAL_RECORDS
            )));
        }
        if self
            .results
            .iter()
            .any(|path| path.as_os_str() == self.journal.as_os_str())
        {
            return Err(invalid("--journal must not name a result file"));
        }
        input::validate_stdin_sources(self.results.iter().map(PathBuf::as_path))?;
        let mut staged = crate::staged_output::StagedFile::stage(invocation, &self.journal)?;
        let scope_digest = self.scope.scope().map(packetcraftr::policy::Scope::digest);
        let mut journal = Journal::new(self.label.clone()).map_err(CliError::classified)?;
        for path in &self.results {
            let bytes = read(invocation, path, self.bounds.max_result_bytes)?;
            let input = record_input(&bytes, scope_digest.clone())?;
            journal.append(input).map_err(CliError::classified)?;
        }
        let mut bytes = serde_json::to_vec_pretty(&journal)
            .map_err(|error| CliError::caused(Kind::Io, &error))?;
        bytes.push(b'\n');
        if bytes.len() > self.bounds.max_result_bytes {
            return Err(CliError::classified(security::Error::Limit {
                field: "max_result_bytes",
                limit: self.bounds.max_result_bytes,
            }));
        }
        if bytes.len() > security::journal::MAX_JOURNAL_DOCUMENT_BYTES {
            return Err(invalid("journal exceeds its document byte limit"));
        }
        staged
            .as_file_mut()
            .write_all(&bytes)
            .map_err(|error| CliError::caused(Kind::Io, &error))?;
        staged.sync()?;
        staged.persist()?;
        emit_stdout_document(
            invocation,
            &format!(
                "journal label={} records={} head={} file={}\n",
                journal.label,
                journal.records.len(),
                journal.head(),
                self.journal.display()
            ),
        )?;
        Ok(CommandExit::SUCCESS)
    }
}

fn verify_report(journal: &Journal, supplied: &[(String, String)]) -> Result<String, CliError> {
    let mut matched = 0_usize;
    for (command, digest) in supplied {
        if journal.find(command, digest).is_none() {
            return Err(invalid(format!(
                "result {command} with sha256 {digest} is not in the journal"
            )));
        }
        matched += 1;
    }
    let unverified = journal.records.len().saturating_sub(
        journal
            .records
            .iter()
            .filter(|record| {
                supplied.iter().any(|(command, digest)| {
                    command == &record.command && digest == &record.result_sha256
                })
            })
            .count(),
    );
    Ok(format!(
        "journal label={} records={} head={} matched={} unverified_records={} valid=true\n",
        journal.label,
        journal.records.len(),
        journal.head(),
        matched,
        unverified,
    ))
}

impl Generate for Verify {
    fn generate(
        self,
        invocation: &crate::invocation::Invocation,
        format: Format,
    ) -> Result<CommandExit, CliError> {
        require_text(format, "journal-verify")?;
        input::validate_stdin_sources(
            std::iter::once(self.journal.as_path())
                .chain(self.results.iter().map(PathBuf::as_path)),
        )?;
        let bytes = read(
            invocation,
            &self.journal,
            security::journal::MAX_JOURNAL_DOCUMENT_BYTES,
        )?;
        let journal = Journal::parse(&bytes).map_err(CliError::classified)?;
        let mut supplied = Vec::with_capacity(self.results.len());
        for path in &self.results {
            let bytes = read(invocation, path, self.bounds.max_result_bytes)?;
            let input = record_input(&bytes, None)?;
            supplied.push((input.command, input.result_sha256));
        }
        emit_stdout_document(invocation, &verify_report(&journal, &supplied)?)?;
        Ok(CommandExit::SUCCESS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(command: &str) -> Vec<u8> {
        format!(
            r#"{{"schema":"{}","status":"success","mode":"aggregate","command":"{command}","result":{{"plan_digest":"{}"}}}}"#,
            security::OUTPUT_SCHEMA,
            "d".repeat(64)
        )
        .into_bytes()
    }

    #[test]
    fn record_input_binds_command_bytes_and_plan_digest() {
        let bytes = envelope("differential");
        let input = record_input(&bytes, Some("a".repeat(64))).unwrap();
        assert_eq!(input.command, "differential");
        assert_eq!(input.plan_digest.as_deref(), Some("d".repeat(64).as_str()));
        assert_eq!(
            input.result_sha256,
            crate::output::hex::compact_hex(&sha256(&bytes))
        );
        assert!(record_input(&envelope("not-a-command"), None).is_err());
        assert!(record_input(b"not json", None).is_err());
    }

    #[test]
    fn verify_report_rejects_unjournaled_results_and_counts_unverified() {
        let mut journal = Journal::new("lab").unwrap();
        journal
            .append(RecordInput {
                command: "scan".to_owned(),
                result_sha256: "b".repeat(64),
                scope_digest: None,
                plan_digest: None,
            })
            .unwrap();
        journal
            .append(RecordInput {
                command: "hunt".to_owned(),
                result_sha256: "c".repeat(64),
                scope_digest: None,
                plan_digest: None,
            })
            .unwrap();
        let text = verify_report(&journal, &[("scan".to_owned(), "b".repeat(64))]).unwrap();
        assert!(text.contains("matched=1 unverified_records=1"), "{text}");
        assert!(verify_report(&journal, &[("scan".to_owned(), "e".repeat(64))]).is_err());
        assert!(verify_report(&journal, &[("hunt".to_owned(), "b".repeat(64))]).is_err());
    }
}
