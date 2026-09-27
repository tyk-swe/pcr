// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Contracts for `analysis::expert::gate`: the declared predicate a completed
//! expert analysis is evaluated against — threshold counting, the ordered
//! verdict truth table, and typed, classified failures.

mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use common::{
    TcpSpec, client_tcp as client, reader, registry, server_tcp as server, tcp_frame as frame,
};
use packetcraftr_core::analysis::expert::gate::{
    Error as GateError, Gate, Options, Reason, Report, Verdict,
};
use packetcraftr_core::analysis::expert::{Collector, Finding};
use packetcraftr_core::analysis::{Options as AnalysisOptions, Session};
use packetcraftr_core::diagnostic::Severity;
use packetcraftr_core::error::{Classified, Kind};
use packetcraftr_core::protocol::transport::Tcp;
use packetcraftr_core::registry::Registry;

fn finding(severity: Severity, code: &'static str, number: u64) -> Finding {
    Finding {
        severity,
        code,
        number,
        stream: None,
        message: format!("{code} at frame {number}"),
    }
}

/// One note, two warnings, and one error: the mixed finding set the gate
/// acceptance cases count over. Two events share a revealing frame, because
/// one physical frame can yield several independent findings.
fn mixed_findings() -> Vec<Finding> {
    vec![
        finding(Severity::Info, "tcp.keep_alive", 4),
        finding(Severity::Warning, "tcp.previous_segment_not_captured", 5),
        finding(Severity::Warning, "tcp.retransmission", 5),
        finding(Severity::Error, "tcp.retransmission_conflicting", 5),
    ]
}

fn gate(min_severity: Severity, allow_findings: u64, minimum_frames: u64) -> Gate {
    Gate::new(Options {
        min_severity,
        allow_findings,
        minimum_frames,
    })
    .expect("fixture options are valid")
}

fn observe_all(gate: &mut Gate, findings: &[Finding]) {
    for finding in findings {
        gate.observe(finding)
            .expect("fixture volumes cannot overflow a counter");
    }
}

/// EG02: every threshold counts the same four events once, and counts as
/// triggering exactly the findings at or above its own severity floor.
#[test]
fn each_threshold_counts_observed_once_and_triggering_by_severity() {
    let findings = mixed_findings();
    for (min_severity, triggering) in [
        (Severity::Info, 4),
        (Severity::Warning, 3),
        (Severity::Error, 1),
    ] {
        let mut gate = gate(min_severity, u64::MAX, 1);
        observe_all(&mut gate, &findings);
        let report = gate.finish(10);
        assert_eq!(report.findings_observed, 4, "{min_severity}");
        assert_eq!(report.triggering_findings, triggering, "{min_severity}");
        assert_eq!(report.min_severity, min_severity);
        assert_eq!(report.verdict, Verdict::Pass, "{min_severity}");
        assert_eq!(report.reason, Reason::WithinAllowance, "{min_severity}");
    }
}

/// EG03: a trigger count below or exactly at the allowance passes; one
/// finding over it fails, given sufficient matched coverage.
#[test]
fn allowance_below_equal_and_above_the_trigger_count() {
    let findings = mixed_findings(); // 3 triggering at the warning threshold
    for (allowance, verdict, reason) in [
        (2, Verdict::Fail, Reason::FindingAllowanceExceeded),
        (3, Verdict::Pass, Reason::WithinAllowance),
        (4, Verdict::Pass, Reason::WithinAllowance),
    ] {
        let mut gate = gate(Severity::Warning, allowance, 1);
        observe_all(&mut gate, &findings);
        let report = gate.finish(10);
        assert_eq!(report.verdict, verdict, "allowance {allowance}");
        assert_eq!(report.reason, reason, "allowance {allowance}");
        assert_eq!(report.allow_findings, allowance);
        assert_eq!(report.triggering_findings, 3);
    }
}

/// EG04: matched coverage below the declared minimum is inconclusive, and
/// meeting or exceeding it passes when no violation was observed.
#[test]
fn matched_frames_below_equal_and_above_the_minimum() {
    let findings = [finding(Severity::Warning, "tcp.reset", 4)];
    for (frames_matched, verdict, reason) in [
        (4, Verdict::Inconclusive, Reason::InsufficientFrames),
        (5, Verdict::Pass, Reason::WithinAllowance),
        (6, Verdict::Pass, Reason::WithinAllowance),
    ] {
        let mut gate = gate(Severity::Warning, 1, 5);
        observe_all(&mut gate, &findings);
        let report = gate.finish(frames_matched);
        assert_eq!(report.verdict, verdict, "frames {frames_matched}");
        assert_eq!(report.reason, reason, "frames {frames_matched}");
        assert_eq!(report.frames_matched, frames_matched);
        assert_eq!(report.minimum_frames, 5);
        assert_eq!(report.triggering_findings, 1);
    }
}

/// EG05: an observed violation wins over insufficient coverage — the
/// verdict is fail with the allowance reason, not inconclusive.
#[test]
fn an_observed_violation_wins_over_insufficient_coverage() {
    let mut gate = gate(Severity::Warning, 0, 100);
    observe_all(&mut gate, &mixed_findings()); // 3 triggering, allowance 0
    let report = gate.finish(0); // no matched frames at all
    assert_eq!(report.verdict, Verdict::Fail);
    assert_eq!(report.reason, Reason::FindingAllowanceExceeded);
}

/// Equality with both criteria at once still passes.
#[test]
fn equality_at_both_boundaries_passes() {
    let mut gate = gate(Severity::Warning, 3, 4);
    observe_all(&mut gate, &mixed_findings()); // 3 triggering == allowance
    let report = gate.finish(4); // == minimum coverage
    assert_eq!(report.verdict, Verdict::Pass);
    assert_eq!(report.reason, Reason::WithinAllowance);
}

/// The counters do not depend on the order findings arrive in.
#[test]
fn counting_is_order_independent() {
    for severities in [
        [
            Severity::Info,
            Severity::Warning,
            Severity::Warning,
            Severity::Error,
        ],
        [
            Severity::Error,
            Severity::Warning,
            Severity::Info,
            Severity::Warning,
        ],
        [
            Severity::Warning,
            Severity::Error,
            Severity::Warning,
            Severity::Info,
        ],
    ] {
        let mut gate = gate(Severity::Warning, 3, 1);
        for (index, severity) in severities.iter().enumerate() {
            gate.observe(&finding(
                *severity,
                "test.finding",
                u64::try_from(index).expect("fixture index fits u64") + 1,
            ))
            .expect("observe");
        }
        let report = gate.finish(5);
        assert_eq!(report.findings_observed, 4);
        assert_eq!(report.triggering_findings, 3);
        assert_eq!(report.verdict, Verdict::Pass);
    }
}

/// The report echoes the configured options and observed counts verbatim.
#[test]
fn report_carries_the_configured_options_and_observed_counts() {
    let mut gate = gate(Severity::Error, 0, 2);
    observe_all(&mut gate, &mixed_findings());
    let report = gate.finish(7);
    assert_eq!(
        report,
        Report {
            verdict: Verdict::Fail,
            reason: Reason::FindingAllowanceExceeded,
            min_severity: Severity::Error,
            allow_findings: 0,
            minimum_frames: 2,
            frames_matched: 7,
            findings_observed: 4,
            triggering_findings: 1,
        }
    );
}

/// A zero coverage minimum is rejected through the public constructor with
/// the usage classification, before any analysis runs.
#[test]
fn zero_minimum_frames_is_a_typed_usage_error() {
    let error = Gate::new(Options {
        min_severity: Severity::Warning,
        allow_findings: 0,
        minimum_frames: 0,
    })
    .expect_err("a gate requires positive coverage");
    assert!(matches!(error, GateError::InvalidMinimum { value: 0 }));
    let classification = error.classification();
    assert_eq!(classification.code, "cli.expert_gate");
    assert_eq!(classification.kind, Kind::Usage);
}

/// Drives `frames` through a real analysis `Session`, observing the gate on
/// every produced finding — including the trailing events the collector
/// emits only when the pass finishes — then evaluates the run's matched
/// physical-frame count.
fn analyze_with_gate(
    registry: &Arc<Registry>,
    frames: &[packetcraftr_core::frame::Frame],
    options: Options,
) -> (Report, u64) {
    let mut capture = reader(frames);
    let mut gate = Gate::new(options).expect("fixture options are valid");
    let outcome = Session::new(
        Arc::clone(registry),
        AnalysisOptions::default(),
        Collector::new(),
        None,
    )
    .run(
        &mut capture,
        |_| Ok(()),
        |finding| {
            gate.observe(&finding)
                .expect("fixture volumes cannot overflow a counter");
            Ok(())
        },
    )
    .expect("fixture analysis completes");
    let frames_matched = outcome.run.frames_matched;
    (gate.finish(frames_matched), frames_matched)
}

/// The gap leaves bytes pending at end of capture, so the pass produces a
/// mid-run warning plus the `tcp.incomplete_at_end` note the per-frame
/// stream cannot carry: the gate's finished evaluation sees both.
fn gap_and_residue_frames(registry: &Arc<Registry>) -> Vec<packetcraftr_core::frame::Frame> {
    let segments: Vec<(TcpSpec, &[u8])> = vec![
        (client(100, 0, Tcp::SYN, 1_000), b""),
        (server(500, 101, Tcp::SYN | Tcp::ACK, 1_000), b""),
        (client(101, 501, Tcp::ACK, 1_000), b""),
        (client(101, 501, Tcp::ACK, 1_000), b"abc"),
        (client(106, 501, Tcp::ACK, 1_000), b"xy"),
    ];
    segments
        .iter()
        .enumerate()
        .map(|(index, (spec, payload))| {
            let timestamp = SystemTime::UNIX_EPOCH
                + Duration::from_secs(u64::try_from(index).expect("fixture index fits u64"));
            frame(registry, timestamp, spec.clone(), payload)
        })
        .collect()
}

#[test]
fn the_gate_observes_the_collector_stream_including_trailing_findings() {
    let registry = registry();
    let frames = gap_and_residue_frames(&registry);

    // The produced stream is one warning plus the trailing info finding: 2
    // observed events over 5 matched frames.
    let (report, frames_matched) = analyze_with_gate(
        &registry,
        &frames,
        Options {
            min_severity: Severity::Info,
            allow_findings: 1,
            minimum_frames: 5,
        },
    );
    assert_eq!(frames_matched, 5);
    assert_eq!(report.findings_observed, 2);
    assert_eq!(report.triggering_findings, 2);
    assert_eq!(report.frames_matched, 5);
    assert_eq!(report.verdict, Verdict::Fail);
    assert_eq!(report.reason, Reason::FindingAllowanceExceeded);

    // A warning threshold sees only the mid-run finding; the trailing note
    // stays observed but does not trigger.
    let (report, _) = analyze_with_gate(
        &registry,
        &frames,
        Options {
            min_severity: Severity::Warning,
            allow_findings: 1,
            minimum_frames: 5,
        },
    );
    assert_eq!(report.findings_observed, 2);
    assert_eq!(report.triggering_findings, 1);
    assert_eq!(report.verdict, Verdict::Pass);
    assert_eq!(report.reason, Reason::WithinAllowance);
}
