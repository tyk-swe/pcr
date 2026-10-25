// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Published security fields, independent of the library's Serde representation.

use std::collections::BTreeMap;

use packetcraftr_core::security as library;
use serde::Serialize;
use serde_json::Value;

published_enum! {
    pub enum Severity from library::Severity {
        Info => "info",
        Low => "low",
        Medium => "medium",
        High => "high",
        Critical => "critical",
    }
}

#[derive(Debug, Serialize)]
pub struct Completeness<'a> {
    pub complete: bool,
    pub reasons: &'a [String],
}

#[derive(Debug, Serialize)]
pub struct Finding<'a> {
    pub rule_id: &'a str,
    pub severity: Severity,
    pub subject: &'a str,
    pub summary: &'a str,
    pub indicator_id: Option<&'a str>,
    pub frames: &'a [u64],
    pub evidence: &'a Value,
    pub remediation: &'a str,
    pub complete: bool,
}

impl<'a> From<&'a library::Finding> for Finding<'a> {
    fn from(value: &'a library::Finding) -> Self {
        Self {
            rule_id: &value.rule_id,
            severity: value.severity.into(),
            subject: &value.subject,
            summary: &value.summary,
            indicator_id: value.indicator_id.as_deref(),
            frames: &value.frames,
            evidence: &value.evidence,
            remediation: &value.remediation,
            complete: value.complete,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Source<'a> {
    pub path: &'a str,
    pub sha256: &'a str,
}

#[derive(Debug, Serialize)]
pub struct Report<'a> {
    pub kind: &'a str,
    pub findings: Vec<Finding<'a>>,
    pub completeness: Completeness<'a>,
    pub measurements: &'a BTreeMap<String, Value>,
    pub sources: Vec<Source<'a>>,
}

impl<'a> From<&'a library::Report> for Report<'a> {
    fn from(value: &'a library::Report) -> Self {
        Self {
            kind: &value.kind,
            findings: value.findings.iter().map(Finding::from).collect(),
            completeness: Completeness {
                complete: value.completeness.complete,
                reasons: &value.completeness.reasons,
            },
            measurements: &value.measurements,
            sources: value
                .sources
                .iter()
                .map(|source| Source {
                    path: &source.path,
                    sha256: &source.sha256,
                })
                .collect(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct FindingRecord<'a>(pub(crate) &'a Finding<'a>);

impl super::stream::StreamRecord for FindingRecord<'_> {
    fn event_name(&self) -> &'static str {
        "finding"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn published_security_fields_and_nulls_are_frozen() {
        let digest = "a".repeat(64);
        let mut report = library::Report::new("hunt");
        let mut finding = library::Finding::new(
            "ioc.match",
            library::Severity::High,
            "example.test",
            "Observed indicator",
            json!({"value":"example.test"}),
            "Review the evidence.",
        );
        finding.frames = vec![2, 3];
        report.findings.push(finding);
        report.sources.push(library::Source {
            path: "indicators.json".into(),
            sha256: digest.clone(),
        });
        report.measurements.insert("frames_read".into(), 3.into());
        report.completeness.note("selected scope");
        let published = Report::from(&report);
        let expected = json!({
            "kind":"hunt", "findings":[{
                "rule_id":"ioc.match", "severity":"high", "subject":"example.test",
                "summary":"Observed indicator", "indicator_id":null, "frames":[2,3],
                "evidence":{"value":"example.test"}, "remediation":"Review the evidence.", "complete":true
            }],
            "completeness":{"complete":false,"reasons":["selected scope"]},
            "measurements":{"frames_read":3}, "sources":[{"path":"indicators.json","sha256":digest}]
        });
        assert_eq!(serde_json::to_value(&published).unwrap(), expected);
        assert_eq!(
            serde_json::to_value(FindingRecord(&published.findings[0])).unwrap(),
            expected["findings"][0]
        );
        for (severity, name) in [
            (library::Severity::Info, "info"),
            (library::Severity::Low, "low"),
            (library::Severity::Medium, "medium"),
            (library::Severity::High, "high"),
            (library::Severity::Critical, "critical"),
        ] {
            assert_eq!(
                serde_json::to_value(Severity::from(severity)).unwrap(),
                name
            );
        }
    }
}
