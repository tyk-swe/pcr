// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::commands::security::{Bounds, check_result_size, input, invalid, publish, read, source};
use crate::commands::{CommandExit, Spec};
use crate::invocation::Invocation;
use crate::output::contract::{Command, Format};
use crate::{errors::CliError, resources::Settings};
use clap::Args;
use packetcraftr_core::security::{Report, Source};
use std::{collections::BTreeSet, io::Write, path::PathBuf};

#[derive(Debug, Args)]
pub(crate) struct Assessment {
    /// Aggregate JSON from hunt, dns-anomalies, beacons, audit-tls, audit-http,
    /// scan-diff, scan, differential, fuzz, exchange, or traceroute. Engagement
    /// results become one info observation each from typed counts, their raw
    /// frames are never copied, and --fail-on info therefore applies to them.
    /// One input may be - to read redirected JSON stdin.
    #[arg(required = true, num_args = 1..)]
    results: Vec<PathBuf>,
    /// New standalone HTML file; existing destinations are refused.
    #[arg(long)]
    html: PathBuf,
    /// New packetcraftr.bundle/v1 evidence bundle JSON file; existing
    /// destinations are refused.
    #[arg(long)]
    bundle: Option<PathBuf>,
    #[command(flatten)]
    bounds: Bounds,
    #[command(flatten)]
    scope: crate::command_options::ScopeArgs,
}
use crate::output::contract::PublishedType;

impl Spec for Assessment {
    const PUBLISHED: &'static [PublishedType] = &[PublishedType {
        definition: "securitySuccess",
        command: "report",
        rust_types: &["crate::commands::security::output::Report"],
        events: &[],
        example: "examples/documents/output-report-success.json",
    }];
    const FORMATS: &'static [Format] = crate::output::contract::TEXT_JSON;
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
        if self
            .bundle
            .as_deref()
            .is_some_and(|bundle| same_destination(bundle, &self.html))
        {
            return Err(invalid("--html and --bundle must name different files"));
        }
        let mut staged = crate::staged_output::StagedFile::stage(i, &self.html)?;
        let mut staged_bundle = self
            .bundle
            .as_ref()
            .map(|path| crate::staged_output::StagedFile::stage(i, path))
            .transpose()?;
        let mut report = Report::new("report");
        let mut seen_inputs = BTreeSet::new();
        let mut seen_sources = BTreeSet::new();
        for path in &self.results {
            i.check()?;
            let bytes = read(i, path, self.bounds.max_result_bytes)?;
            let input_source = source(path, &bytes);
            if !seen_inputs.insert((path.as_os_str(), input_source.sha256.clone())) {
                continue;
            }
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
            let source_file = path.display().to_string();
            for mut finding in result.findings {
                redact(&mut finding.evidence);
                finding.evidence =
                    serde_json::json!({"source_file":source_file, "observation":finding.evidence});
                limits
                    .push(&mut report, finding)
                    .map_err(CliError::classified)?;
            }
            append_sources(
                &mut report,
                &mut seen_sources,
                std::iter::once(input_source).chain(result.sources),
            );
            check_result_size(
                i.format,
                &crate::commands::security::output::Report::from(&report),
                self.bounds.max_result_bytes,
                "report exceeds --max-result-bytes",
            )?;
        }
        report
            .measurements
            .insert("html".into(), self.html.display().to_string().into());
        if let Some(bundle) = &self.bundle {
            report
                .measurements
                .insert("bundle".into(), bundle.display().to_string().into());
        }
        if let Some(scope) = self.scope.scope() {
            report
                .measurements
                .insert("scope_digest".into(), serde_json::json!(scope.digest()));
        }
        let published = crate::commands::security::output::Report::from(&report);
        check_result_size(
            i.format,
            &published,
            self.bounds.max_result_bytes,
            "report exceeds --max-result-bytes",
        )?;
        let html = crate::commands::security::rendering::html(&published);
        if html.len() > self.bounds.max_result_bytes.saturating_mul(8) {
            return Err(invalid("HTML exceeds bounded report expansion"));
        }
        staged
            .as_file_mut()
            .write_all(html.as_bytes())
            .map_err(|e| CliError::caused(packetcraftr_core::error::Kind::Io, &e))?;
        staged.sync()?;
        if let Some(staged_bundle) = staged_bundle.as_mut() {
            let bundle = packetcraftr_core::security::bundle::Bundle::new(
                report.clone(),
                self.scope
                    .scope()
                    .map(|scope| packetcraftr_core::security::bundle::ScopeRef {
                        label: scope.label.clone(),
                        digest: scope.digest(),
                    }),
            );
            let bundle_limit = self
                .bounds
                .max_result_bytes
                .min(packetcraftr_core::security::bundle::MAX_BUNDLE_DOCUMENT_BYTES);
            crate::publication::bounded_json_len(
                &bundle,
                bundle_limit,
                serde_json::ser::CompactFormatter,
            )
            .map_err(|e| e.into_cli_error(|| invalid("bundle exceeds --max-result-bytes")))?;
            let bytes = serde_json::to_vec_pretty(&bundle)
                .map_err(|e| CliError::caused(packetcraftr_core::error::Kind::Io, &e))?;
            if bytes.len() > bundle_limit {
                return Err(invalid("bundle exceeds --max-result-bytes"));
            }
            staged_bundle
                .as_file_mut()
                .write_all(&bytes)
                .map_err(|e| CliError::caused(packetcraftr_core::error::Kind::Io, &e))?;
            staged_bundle.sync()?;
        }
        i.check()?;
        staged.persist()?;
        if let Some(staged_bundle) = staged_bundle {
            staged_bundle.persist()?;
        }
        publish(i, Command::Assessment, report, self.bounds)
    }
}

fn same_destination(left: &std::path::Path, right: &std::path::Path) -> bool {
    fn normalized(path: &std::path::Path) -> PathBuf {
        use std::path::Component;
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(path)
        };
        let mut out = PathBuf::new();
        for component in absolute.components() {
            match component {
                Component::CurDir => {}
                Component::ParentDir => {
                    if let Ok(resolved) = out.canonicalize() {
                        out = resolved;
                    }
                    out.pop();
                }
                other => {
                    out.push(other.as_os_str());
                    if let Ok(resolved) = out.canonicalize() {
                        out = resolved;
                    }
                }
            }
        }
        out
    }
    let left = normalized(left);
    let right = normalized(right);
    if cfg!(windows) {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    } else {
        left == right
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
    fn provenance_preserves_order_and_distinct_hashes() {
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
