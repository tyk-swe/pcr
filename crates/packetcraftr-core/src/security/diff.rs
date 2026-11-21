// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use super::{Finding, Report, Severity};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FindingKey {
    pub rule_id: String,
    pub subject: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffRow {
    pub key: FindingKey,
    pub before: usize,
    pub after: usize,
    pub before_severities: Vec<Severity>,
    pub after_severities: Vec<Severity>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FindingsDiff {
    pub new_findings: Vec<DiffRow>,
    pub still_present: Vec<DiffRow>,
    pub fixed: Vec<DiffRow>,
    pub severity_changed: Vec<DiffRow>,
}

fn group(report: &Report) -> BTreeMap<FindingKey, Vec<&Finding>> {
    let mut groups: BTreeMap<FindingKey, Vec<&Finding>> = BTreeMap::new();
    for finding in &report.findings {
        groups
            .entry(FindingKey {
                rule_id: finding.rule_id.clone(),
                subject: finding.subject.clone(),
            })
            .or_default()
            .push(finding);
    }
    groups
}

fn severities(findings: &[&Finding]) -> Vec<Severity> {
    let mut values: Vec<Severity> = findings.iter().map(|finding| finding.severity).collect();
    values.sort();
    values
}

/// Compare two reports by rule and subject, preserving multiplicity. A
/// finding whose count falls is only fixed for the missing instances, so
/// paired counts use the smaller side rather than treating a key as a set.
#[must_use]
pub fn diff_reports(before: &Report, after: &Report) -> FindingsDiff {
    let before_groups = group(before);
    let after_groups = group(after);
    let mut diff = FindingsDiff::default();
    let keys: std::collections::BTreeSet<&FindingKey> =
        before_groups.keys().chain(after_groups.keys()).collect();
    for key in keys {
        let empty: Vec<&Finding> = Vec::new();
        let before_findings = before_groups.get(key).unwrap_or(&empty);
        let after_findings = after_groups.get(key).unwrap_or(&empty);
        let row = DiffRow {
            key: key.clone(),
            before: before_findings.len(),
            after: after_findings.len(),
            before_severities: severities(before_findings),
            after_severities: severities(after_findings),
        };
        if row.after > row.before {
            diff.new_findings.push(row.clone());
        }
        if row.before > row.after {
            diff.fixed.push(row.clone());
        }
        let paired = row.before.min(row.after);
        if paired > 0 {
            if row.before_severities[..paired] != row.after_severities[..paired] {
                diff.severity_changed.push(row.clone());
            }
            diff.still_present.push(row);
        }
    }
    diff
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::Finding;
    use serde_json::json;

    fn report(rows: &[(&str, &str, Severity)]) -> Report {
        let mut report = Report::new("hunt");
        for (rule, subject, severity) in rows {
            report.findings.push(Finding::new(
                rule,
                *severity,
                *subject,
                "observed",
                json!({}),
                "none",
            ));
        }
        report
    }

    #[test]
    fn diff_preserves_multiplicity_and_severity_changes() {
        let before = report(&[
            ("rule.a", "host-1", Severity::High),
            ("rule.a", "host-1", Severity::High),
            ("rule.b", "host-2", Severity::Low),
            ("rule.c", "host-3", Severity::Medium),
        ]);
        let after = report(&[
            ("rule.a", "host-1", Severity::Critical),
            ("rule.b", "host-2", Severity::Low),
            ("rule.d", "host-4", Severity::Info),
        ]);
        let diff = diff_reports(&before, &after);
        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.new_findings[0].key.rule_id, "rule.d");
        assert_eq!(diff.fixed.len(), 2);
        assert!(
            diff.fixed
                .iter()
                .any(|row| row.key.rule_id == "rule.a" && row.before == 2 && row.after == 1)
        );
        assert!(diff.fixed.iter().any(|row| row.key.rule_id == "rule.c"));
        assert_eq!(diff.still_present.len(), 2);
        assert_eq!(diff.severity_changed.len(), 1);
        let changed = &diff.severity_changed[0];
        assert_eq!((changed.before, changed.after), (2, 1));
        assert_eq!(
            changed.before_severities,
            vec![Severity::High, Severity::High]
        );
        assert_eq!(changed.after_severities, vec![Severity::Critical]);
    }

    #[test]
    fn identical_reports_have_no_changes() {
        let report = report(&[("rule.a", "host", Severity::Low)]);
        let diff = diff_reports(&report, &report);
        assert!(diff.new_findings.is_empty());
        assert!(diff.fixed.is_empty());
        assert!(diff.severity_changed.is_empty());
        assert_eq!(diff.still_present.len(), 1);
    }
}
