// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Bounds, Command, CommandExit, Format, Invocation, Spec, invalid};
use crate::{errors::CliError, resources::Settings};
use clap::Args;
use packetcraftr_core::security::{Report, Source};
use sha2::{Digest, Sha256};
use std::{
    fmt::Write as _,
    io::Write,
    path::{Path, PathBuf},
};

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
            let envelope: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|e| invalid(e.to_string()))?;
            let command = envelope["command"].as_str().unwrap_or("");
            if envelope["schema"] != "packetcraftr.output/v1"
                || envelope["status"] != "success"
                || envelope["mode"] != "aggregate"
                || ![
                    "hunt",
                    "dns-anomalies",
                    "beacons",
                    "audit-tls",
                    "audit-http",
                    "scan-diff",
                ]
                .contains(&command)
            {
                return Err(invalid(
                    "report inputs must be successful aggregate JSON from one of the six security commands",
                ));
            }
            let mut result: Report = serde_json::from_value(envelope["result"].clone())
                .map_err(|e| invalid(e.to_string()))?;
            if result.kind != command {
                return Err(invalid("report kind does not match command"));
            }
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
            report.sources.push(source(path, &bytes));
            crate::rendering::bounded_json_len(&report, self.bounds.max_result_bytes)
                .map_err(|e| e.into_cli_error(|| invalid("report exceeds --max-result-bytes")))?;
        }
        report
            .measurements
            .insert("html".into(), serde_json::json!(self.html));
        crate::rendering::bounded_json_len(&report, self.bounds.max_result_bytes)
            .map_err(|e| e.into_cli_error(|| invalid("report exceeds --max-result-bytes")))?;
        let html = render(&report);
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
pub(super) fn source(path: &Path, bytes: &[u8]) -> Source {
    Source {
        path: path.display().to_string(),
        sha256: Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    }
}
fn escape(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&#39;"),
            _ => result.push(c),
        }
    }
    result
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
fn render(report: &Report) -> String {
    let mut html = String::from(
        r#"<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PacketcraftR assessment</title><style>body{font:16px system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem;background:#f5f7fa;color:#182539}article{background:white;border:1px solid #ccd5df;border-left:5px solid #537796;padding:1rem;margin:1rem 0;border-radius:5px}pre{white-space:pre-wrap;overflow-wrap:anywhere}code{overflow-wrap:anywhere}label{margin-right:1rem}.high,.critical{border-left-color:#b6233c}.medium{border-left-color:#bd7b00}small{color:#405775}</style><h1>PacketcraftR assessment</h1><p>Observed evidence from local results. Configuration and traffic patterns require contextual investigation.</p><fieldset><legend>Show severity</legend>"#,
    );
    for severity in ["critical", "high", "medium", "low", "info"] {
        let _ = write!(
            html,
            "<label><input type=\"checkbox\" checked data-level=\"{severity}\">{severity}</label>"
        );
    }
    let _ = write!(
        html,
        "</fieldset><p>{} findings. Evidence complete: {}.</p>",
        report.findings.len(),
        report.completeness.complete
    );
    for reason in &report.completeness.reasons {
        let _ = write!(html, "<p>{}</p>", escape(reason));
    }
    for f in &report.findings {
        let severity = format!("{:?}", f.severity).to_ascii_lowercase();
        let _ = write!(
            html,
            "<article class=\"{severity}\" data-severity=\"{severity}\"><small>{severity} · {}</small><h2>{}</h2><p>{}</p><p>Subject: <code>{}</code></p><p>Indicator: {}</p><p>Source frames: {}</p><p>Evidence complete: {}</p><details><summary>Observed evidence</summary><pre>{}</pre></details><p>Remediation: {}</p></article>",
            escape(&f.rule_id),
            escape(&f.summary),
            escape(&f.rule_id),
            escape(&f.subject),
            escape(f.indicator_id.as_deref().unwrap_or("—")),
            escape(&format!("{:?}", f.frames)),
            f.complete,
            escape(&serde_json::to_string_pretty(&f.evidence).unwrap_or_default()),
            escape(&f.remediation)
        );
    }
    html.push_str("<h2>Source files (SHA-256)</h2><ul>");
    for source in &report.sources {
        let _ = write!(
            html,
            "<li>{}<br><code>{}</code></li>",
            escape(&source.path),
            escape(&source.sha256)
        );
    }
    html.push_str(r#"</ul><script>document.querySelectorAll('input[data-level]').forEach(x=>x.addEventListener('change',()=>{document.querySelectorAll('article').forEach(a=>a.hidden=!document.querySelector('input[data-level="'+a.dataset.severity+'"]').checked)}))</script></html>"#);
    html
}
#[cfg(test)]
mod tests {
    #[test]
    fn escape_untrusted_markup() {
        assert_eq!(
            super::escape("<script>\"&'"),
            "&lt;script&gt;&quot;&amp;&#39;"
        );
    }
    #[test]
    fn redacts_cookies() {
        let mut v = serde_json::json!({"cookies":[{"value":"secret","http_only":false}],"Set-Cookie":"sid=secret"});
        super::redact(&mut v);
        assert!(!v.to_string().contains("secret"));
    }
}
