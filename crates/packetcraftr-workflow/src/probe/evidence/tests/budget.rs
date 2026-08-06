// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::budget::{checked_frame_bytes, checked_frame_count, checked_sent_frame_bytes};
use super::super::{
    EvidenceBudget, EvidenceDiagnosticDescriptor, ExchangeEvidenceError,
    format_exchange_evidence_error, push_undecoded_limit_diagnostic, retain_evidence,
};
use super::support::frame;

#[test]
fn checked_evidence_totals_fail_closed_on_overflow() {
    assert_eq!(checked_frame_count(&[2, 3, 5]), Some(10));
    assert_eq!(checked_frame_count(&[usize::MAX, 1]), None);

    let first = frame(&[1, 2]);
    let second = frame(&[3]);
    assert_eq!(checked_frame_bytes([&first, &second]), Some(3));
    assert_eq!(
        checked_sent_frame_bytes(&[first.clone(), second.clone()]),
        Some(3)
    );
}

#[test]
fn workflow_evidence_diagnostics_and_errors_preserve_exact_text() {
    let first = frame(&[1]);
    let second = frame(&[2]);
    let mut budget = EvidenceBudget::default();
    let mut diagnostics = Vec::new();
    assert!(retain_evidence(
        &mut budget,
        &first,
        EvidenceDiagnosticDescriptor::new("scan", "scan"),
        1,
        1,
        &mut diagnostics,
    ));
    assert!(!retain_evidence(
        &mut budget,
        &second,
        EvidenceDiagnosticDescriptor::new("scan", "scan"),
        1,
        1,
        &mut diagnostics,
    ));
    assert!(!retain_evidence(
        &mut budget,
        &second,
        EvidenceDiagnosticDescriptor::new("scan", "scan"),
        1,
        1,
        &mut diagnostics,
    ));
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].code, "scan.evidence_limit");
    assert_eq!(
        diagnostics[0].message,
        "scan evidence exceeded 1 frame(s) or 1 byte(s); later exact frames were omitted"
    );

    push_undecoded_limit_diagnostic(
        &mut diagnostics,
        EvidenceDiagnosticDescriptor::new("traceroute", "traceroute"),
        7,
    );
    assert_eq!(diagnostics[1].code, "traceroute.undecoded_limit");
    assert_eq!(
        diagnostics[1].message,
        "undecodable traceroute evidence limit 7 reached; later frames were omitted"
    );

    let mut dns_budget = EvidenceBudget::default();
    assert!(!retain_evidence(
        &mut dns_budget,
        &first,
        EvidenceDiagnosticDescriptor::new("dns", "DNS"),
        0,
        0,
        &mut diagnostics,
    ));
    assert!(!retain_evidence(
        &mut dns_budget,
        &second,
        EvidenceDiagnosticDescriptor::new("dns", "DNS"),
        0,
        0,
        &mut diagnostics,
    ));
    assert_eq!(diagnostics[2].code, "dns.evidence_limit");
    assert_eq!(
        diagnostics[2].message,
        "DNS evidence exceeded 0 frame(s) or 0 byte(s); later exact frames were omitted"
    );
    assert_eq!(diagnostics.len(), 3);

    let mut dns_undecoded_diagnostics = Vec::new();
    push_undecoded_limit_diagnostic(
        &mut dns_undecoded_diagnostics,
        EvidenceDiagnosticDescriptor::new("dns", "DNS"),
        4,
    );
    assert_eq!(dns_undecoded_diagnostics[0].code, "dns.undecoded_limit");
    assert_eq!(
        dns_undecoded_diagnostics[0].message,
        "undecodable DNS evidence limit 4 reached; later frames were omitted"
    );

    let mut frame_overflow_budget = EvidenceBudget {
        retained_frame_count: usize::MAX,
        retained_byte_count: 0,
    };
    let mut overflow_diagnostics = Vec::new();
    assert!(!retain_evidence(
        &mut frame_overflow_budget,
        &first,
        EvidenceDiagnosticDescriptor::new("dns", "DNS"),
        usize::MAX,
        usize::MAX,
        &mut overflow_diagnostics,
    ));
    assert_eq!(
        overflow_diagnostics[0].message,
        "DNS evidence frame accounting overflowed; later frames were omitted"
    );

    let mut byte_overflow_budget = EvidenceBudget {
        retained_frame_count: 0,
        retained_byte_count: usize::MAX,
    };
    let mut overflow_diagnostics = Vec::new();
    assert!(!retain_evidence(
        &mut byte_overflow_budget,
        &first,
        EvidenceDiagnosticDescriptor::new("scan", "scan"),
        usize::MAX,
        usize::MAX,
        &mut overflow_diagnostics,
    ));
    assert_eq!(
        overflow_diagnostics[0].message,
        "scan evidence byte accounting overflowed; later frames were omitted"
    );
    assert_eq!(
        format_exchange_evidence_error(
            ExchangeEvidenceError::MatchedResponseOutsideBatch,
            "hop batch",
            "traceroute",
        ),
        "matched response references a request outside the hop batch"
    );
    assert_eq!(
        format_exchange_evidence_error(
            ExchangeEvidenceError::IncompleteStatistics,
            "batch",
            "scan",
        ),
        "successful exchange statistics do not account for every scan probe"
    );
}
