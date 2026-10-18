// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{errors::CliError, invocation::Invocation, output::security::Report};
use std::fmt::Write as _;

pub(crate) fn text(i: &Invocation, report: &Report<'_>) -> Result<(), CliError> {
    crate::rendering::write_stdout_line(
        i,
        format_args!(
            "{}: {} finding(s); evidence {}",
            report.kind,
            report.findings.len(),
            if report.completeness.complete {
                "complete within the selected input"
            } else {
                "incomplete"
            }
        ),
    )?;
    for key in [
        "endpoint",
        "protocol",
        "cipher",
        "certificate_sha256",
        "verification",
        "status",
        "frames_read",
        "thresholds",
        "before_endpoints",
        "after_endpoints",
        "unchanged_endpoints",
        "html",
    ] {
        if let Some(value) = report.measurements.get(key) {
            crate::rendering::write_stdout_line(i, format_args!("  {key}: {value}"))?;
        }
    }
    for f in &report.findings {
        crate::rendering::write_stdout_line(
            i,
            format_args!(
                "{:?} {} {}: {}",
                f.severity, f.rule_id, f.subject, f.summary
            ),
        )?;
        for key in [
            "responses",
            "nxdomain",
            "ratio",
            "distinct_labels",
            "attempts",
            "mean_interval_seconds",
            "coefficient_of_variation",
        ] {
            if let Some(value) = f.evidence.get(key) {
                crate::rendering::write_stdout_line(i, format_args!("  {key}: {value}"))?;
            }
        }
        if i.output.presentation().verbose {
            crate::rendering::write_stdout_line(
                i,
                format_args!(
                    "  frames: {:?}\n  evidence: {}\n  remediation: {}",
                    f.frames, f.evidence, f.remediation
                ),
            )?;
        }
    }
    for reason in report.completeness.reasons {
        crate::rendering::write_stdout_line(i, format_args!("  {reason}"))?;
    }
    Ok(())
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
pub(crate) fn html(report: &Report<'_>) -> String {
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
    for reason in report.completeness.reasons {
        let _ = write!(html, "<p>{}</p>", escape(reason));
    }
    for f in &report.findings {
        let severity = format!("{:?}", f.severity).to_ascii_lowercase();
        let _ = write!(
            html,
            "<article class=\"{severity}\" data-severity=\"{severity}\"><small>{severity} · {}</small><h2>{}</h2><p>{}</p><p>Subject: <code>{}</code></p><p>Indicator: {}</p><p>Source frames: {}</p><p>Evidence complete: {}</p><details><summary>Observed evidence</summary><pre>{}</pre></details><p>Remediation: {}</p></article>",
            escape(f.rule_id),
            escape(f.summary),
            escape(f.rule_id),
            escape(f.subject),
            escape(f.indicator_id.unwrap_or("—")),
            escape(&format!("{:?}", f.frames)),
            f.complete,
            escape(&serde_json::to_string_pretty(f.evidence).unwrap_or_default()),
            escape(f.remediation)
        );
    }
    html.push_str("<h2>Source files (SHA-256)</h2><ul>");
    for source in &report.sources {
        let _ = write!(
            html,
            "<li>{}<br><code>{}</code></li>",
            escape(source.path),
            escape(source.sha256)
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
}
