// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Bounds, Command, CommandExit, Format, Invocation, Spec, invalid};
use crate::{errors::CliError, resources::Settings};
use clap::Args;
use packetcraftr_core::security::Report;
use std::{io::Write, path::PathBuf};

#[derive(Debug, Args)]
pub(crate) struct Assessment {
    /// Aggregate JSON from hunt, dns-anomalies, beacons, audit-tls, audit-http, or scan-diff.
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
        let mut staged = crate::staged_output::StagedFile::stage(i, &self.html)?;
        let mut report = Report::new("report");
        for path in &self.results {
            i.check()?;
            let bytes = super::read(path, self.bounds.max_result_bytes)?;
            let mut result = super::input::report(&bytes)?;
            if !result.completeness.complete {
                for reason in result.completeness.reasons {
                    report
                        .completeness
                        .note(format!("{}: {reason}", path.display()));
                }
            }
            for finding in &mut result.findings {
                redact(&mut finding.evidence);
                finding.evidence =
                    serde_json::json!({"source_file":path, "observation":finding.evidence});
                limits
                    .push(&mut report, finding.clone())
                    .map_err(CliError::classified)?;
            }
            report.sources.push(super::source(path, &bytes));
            crate::rendering::bounded_json_len(
                &crate::output::security::Report::from(&report),
                self.bounds.max_result_bytes,
            )
            .map_err(|e| e.into_cli_error(|| invalid("report exceeds --max-result-bytes")))?;
        }
        report
            .measurements
            .insert("html".into(), serde_json::json!(self.html));
        crate::rendering::bounded_json_len(
            &crate::output::security::Report::from(&report),
            self.bounds.max_result_bytes,
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
        super::publish(i, Command::Assessment, report, self.bounds)
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
    fn redacts_cookies() {
        let mut v = serde_json::json!({"cookies":[{"value":"secret","http_only":false}],"Set-Cookie":"sid=secret"});
        super::redact(&mut v);
        assert!(!v.to_string().contains("secret"));
    }
}
