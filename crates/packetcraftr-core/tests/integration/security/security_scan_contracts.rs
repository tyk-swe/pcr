// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::security::{
    Error, Limits, Severity,
    scan::{Endpoint, Snapshot, State, compare_snapshots},
};
use serde_json::json;

fn endpoint(key: &str, state: Option<State>) -> Endpoint {
    Endpoint {
        key: key.into(),
        state,
        // Comparison must use typed observations, not infer a state from JSON.
        observation: json!({"observation": key}),
    }
}

fn snapshot(endpoints: Vec<Endpoint>) -> Snapshot {
    Snapshot {
        method: "fixture-method".into(),
        endpoints,
    }
}

#[test]
fn typed_comparison_preserves_evidence_and_distinguishes_inference_from_coverage() {
    let before = snapshot(vec![
        endpoint("unchanged", Some(State::Open)),
        endpoint("changed", Some(State::Closed)),
        endpoint("unavailable", None),
        endpoint("removed", Some(State::Open)),
    ]);
    let after = snapshot(vec![
        endpoint("unavailable", Some(State::Closed)),
        endpoint("changed", Some(State::Open)),
        endpoint("added", Some(State::Filtered)),
        endpoint("unchanged", Some(State::Open)),
    ]);
    let report = compare_snapshots(&before, &after, Limits::default()).unwrap();
    assert_eq!(report.measurements["unchanged_endpoints"], 1);
    assert_eq!(report.measurements["before_endpoints"], 4);
    assert_eq!(report.measurements["after_endpoints"], 4);
    assert!(!report.completeness.complete);
    assert_eq!(
        report
            .findings
            .iter()
            .map(|f| f.subject.as_str())
            .collect::<Vec<_>>(),
        ["added", "changed", "removed", "unavailable"]
    );
    let changed = &report.findings[1];
    assert_eq!(changed.rule_id, "scan.state_changed");
    assert_eq!(changed.severity, Severity::Medium);
    assert_eq!(
        changed.evidence,
        json!({"before":{"observation":"changed"},"after":{"observation":"changed"}})
    );
    let removed = &report.findings[2];
    assert_eq!(removed.rule_id, "scan.coverage_changed");
    assert_eq!(removed.evidence["after"], serde_json::Value::Null);
    assert_eq!(report.findings[3].rule_id, "scan.evidence_unavailable");
}

#[test]
fn typed_comparison_rejects_duplicates_incompatible_methods_and_exceeded_limits() {
    let empty = snapshot(Vec::new());
    let one = snapshot(vec![endpoint("a", Some(State::Open))]);
    let duplicate = snapshot(vec![endpoint("a", None), endpoint("a", None)]);
    assert!(matches!(
        compare_snapshots(&duplicate, &empty, Limits::default()),
        Err(Error::Invalid(_))
    ));
    let different_method = Snapshot {
        method: "other-method".into(),
        ..empty.clone()
    };
    assert!(matches!(
        compare_snapshots(&empty, &different_method, Limits::default()),
        Err(Error::Invalid(_))
    ));
    let limits = Limits {
        max_groups: 1,
        max_findings: 1,
        ..Limits::default()
    };
    assert!(compare_snapshots(&one, &empty, limits).is_ok());
    let two = snapshot(vec![endpoint("a", None), endpoint("b", None)]);
    assert!(matches!(
        compare_snapshots(&two, &empty, limits),
        Err(Error::Limit {
            field: "max_groups",
            limit: 1
        })
    ));
    let limits = Limits {
        max_findings: 1,
        ..Limits::default()
    };
    assert!(matches!(
        compare_snapshots(&two, &empty, limits),
        Err(Error::Limit {
            field: "max_findings",
            limit: 1
        })
    ));
    assert!(
        compare_snapshots(
            &empty,
            &empty,
            Limits {
                max_groups: 0,
                ..limits
            }
        )
        .is_err()
    );
}
