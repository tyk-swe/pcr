// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::commands::security::{Bounds, input, invalid, publish, read, source};
use crate::commands::{CommandExit, Spec};
use crate::invocation::Invocation;
use crate::output::contract::{Command, Format};
use crate::{errors::CliError, resources::Settings};
use clap::Args;
use packetcraftr_core::security::{Report, Source};
use std::{collections::BTreeSet, io::Write, path::PathBuf};

#[derive(Debug, Args)]
pub(crate) struct Assessment {
    /// Aggregate JSON from hunt, dns-anomalies, beacons, audit-tls, audit-http, or scan-diff.
    /// One input may be - to read redirected JSON stdin.
    #[arg(required = true, num_args = 1..)]
    results: Vec<PathBuf>,
    /// New standalone HTML file; existing destinations are refused.
    #[arg(long)]
    html: PathBuf,
    #[command(flatten)]
    bounds: Bounds,
}
impl Spec for Assessment {
    const FORMATS: &'static [Format] = &[Format::Text, Format::Json];
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;
    fn resources(&self, s: &mut Settings<'_>) {
        self.bounds.resources(s);
    }
    fn run(self, i: &Invocation) -> Result<CommandExit, CliError> {
        let limits = self.bounds.core()?;
        if self.results.len() > 128 {
            return Err(invalid("reports accept at most 128 result files"));
        }
        input::validate_stdin_sources(self.results.iter().map(PathBuf::as_path))?;
        let mut staged = crate::staged_output::StagedFile::stage(i, &self.html)?;
        let mut report = Report::new("report");
        let mut seen_sources = BTreeSet::new();
        for path in &self.results {
            i.check()?;
            let bytes = read(path, self.bounds.max_result_bytes)?;
            let result = input::report(&bytes)?;
            if !result.completeness.complete {
                if result.completeness.reasons.is_empty() {
                    report
                        .completeness
                        .note(format!("{}: source evidence incomplete", path.display()));
                }
                for reason in result.completeness.reasons {
                    report
                        .completeness
                        .note(format!("{}: {reason}", path.display()));
                }
            }
            for mut finding in result.findings {
                redact(&mut finding.evidence);
                finding.evidence =
                    serde_json::json!({"source_file":path, "observation":finding.evidence});
                limits
                    .push(&mut report, finding)
                    .map_err(CliError::classified)?;
            }
            append_sources(
                &mut report,
                &mut seen_sources,
                std::iter::once(source(path, &bytes)).chain(result.sources),
            );
            crate::rendering::bounded_json_len(
                &crate::output::security::Report::from(&report),
                self.bounds.max_result_bytes,
                serde_json::ser::CompactFormatter,
            )
            .map_err(|e| e.into_cli_error(|| invalid("report exceeds --max-result-bytes")))?;
        }
        report
            .measurements
            .insert("html".into(), serde_json::json!(self.html));
        crate::rendering::bounded_json_len(
            &crate::output::security::Report::from(&report),
            self.bounds.max_result_bytes,
            serde_json::ser::CompactFormatter,
        )
        .map_err(|e| e.into_cli_error(|| invalid("report exceeds --max-result-bytes")))?;
        let html =
            crate::rendering::security::html(&crate::output::security::Report::from(&report));
        if html.len() > self.bounds.max_result_bytes.saturating_mul(8) {
            return Err(invalid("HTML exceeds bounded report expansion"));
        }
        staged
            .as_file_mut()
            .write_all(html.as_bytes())
            .map_err(|e| CliError::caused(packetcraftr_core::error::Kind::Io, &e))?;
        staged.sync()?;
        i.check()?;
        staged.persist()?;
        publish(i, Command::Assessment, report, self.bounds)
    }
}

fn append_sources(
    report: &mut Report,
    seen: &mut BTreeSet<(String, String)>,
    sources: impl IntoIterator<Item = Source>,
) {
    for source in sources {
        if seen.insert((source.path.clone(), source.sha256.clone())) {
            report.sources.push(source);
        }
    }
}
fn redact(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            let cookie = map.contains_key("same_site") || map.contains_key("http_only");
            for (key, value) in map {
                if key.eq_ignore_ascii_case("set-cookie") || (cookie && key == "value") {
                    *value = serde_json::json!("[redacted]");
                } else {
                    redact(value);
                }
            }
        }
        serde_json::Value::Array(array) => {
            for value in array {
                redact(value);
            }
        }
        _ => {}
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn source_provenance_preserves_first_seen_order_and_distinct_hashes() {
        use super::*;
        let mut report = Report::new("report");
        let mut seen = BTreeSet::new();
        let sources = [
            ("result.json", "a"),
            ("ioc.json", "b"),
            ("ioc.json", "b"),
            ("ioc.json", "c"),
        ];
        append_sources(
            &mut report,
            &mut seen,
            sources.into_iter().map(|(path, sha256)| Source {
                path: path.into(),
                sha256: sha256.into(),
            }),
        );
        assert_eq!(
            report
                .sources
                .iter()
                .map(|s| (s.path.as_str(), s.sha256.as_str()))
                .collect::<Vec<_>>(),
            vec![("result.json", "a"), ("ioc.json", "b"), ("ioc.json", "c")]
        );
    }

    #[test]
    fn redacts_cookies() {
        let mut v = serde_json::json!({"cookies":[{"value":"secret","http_only":false}],"Set-Cookie":"sid=secret"});
        super::redact(&mut v);
        assert!(!v.to_string().contains("secret"));
    }
}
