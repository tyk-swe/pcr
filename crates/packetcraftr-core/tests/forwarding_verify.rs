// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `analysis::forwarding` contracts: explicit identity, bounded evidence,
//! and verdict semantics that never confuse missing proof with proof of loss.

mod common;

use std::error::Error as _;
use std::net::Ipv4Addr;
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr_core::analysis::forwarding::{
    CheckKind, Incomplete, Outcome, Side, SideInput, Verdict,
};
use packetcraftr_core::analysis::{self, forwarding};
use packetcraftr_core::budget::Cancellation;
use packetcraftr_core::error::{BoundaryError, Classified, Kind};
use packetcraftr_core::field::FieldValue;
use packetcraftr_core::filter::Filter;
use packetcraftr_core::frame::{Frame, Lengths, LinkType};
use packetcraftr_core::protocol::builtin;

const EVIDENCE_BUDGET: usize = 16 * 1024 * 1024;
const FIELD_BUDGET: usize = 64 * 1024;
const MAX_DETAILS: usize = 256;

fn rules(identity: &[&str], preserve: &[&str], expect: &[&str]) -> forwarding::Rules {
    let owned = |fields: &[&str]| fields.iter().map(ToString::to_string).collect::<Vec<_>>();
    forwarding::Rules::compile(
        &owned(identity),
        &owned(preserve),
        &owned(expect),
        &builtin::registry(),
        FIELD_BUDGET,
    )
    .expect("rules compile")
}

fn frame(
    timestamp: u64,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    ports: (u16, u16),
    payload: &[u8],
) -> Frame {
    common::udp_frame(
        &common::registry(),
        UNIX_EPOCH + Duration::from_secs(timestamp),
        source,
        destination,
        ports.0,
        ports.1,
        payload,
    )
}

/// A frame whose capture record retains fewer bytes than the wire length:
/// the last two payload bytes are absent, which breaks decode outright.
fn truncated_frame(timestamp: u64, payload: &[u8]) -> Frame {
    let full = frame(
        timestamp,
        common::CLIENT,
        common::SERVER,
        (53_000, 9_000),
        payload,
    );
    let keep = full.captured_length() - 2;
    let bytes = full.bytes()[..keep as usize].to_vec();
    Frame::try_with_lengths(
        UNIX_EPOCH + Duration::from_secs(timestamp),
        LinkType::IPV4,
        Lengths {
            captured: keep,
            original: full.original_length(),
        },
        bytes,
    )
    .expect("truncated fixture is valid")
}

/// A capture record that declares more wire bytes than it retains while
/// keeping internally consistent packet bytes: fields still resolve, but the
/// record admits truncation, so the evidence is incomplete.
fn short_record(timestamp: u64, payload: &[u8]) -> Frame {
    let full = frame(
        timestamp,
        common::CLIENT,
        common::SERVER,
        (53_000, 9_000),
        payload,
    );
    Frame::try_with_lengths(
        UNIX_EPOCH + Duration::from_secs(timestamp),
        LinkType::IPV4,
        Lengths {
            captured: full.captured_length(),
            original: full.original_length() + 2,
        },
        full.bytes().to_vec(),
    )
    .expect("short-record fixture is valid")
}

fn collect(
    rules: &forwarding::Rules,
    side: Side,
    frames: &[Frame],
    filter: Option<&Filter>,
) -> SideInput {
    let mut reader = common::reader(frames);
    let options = analysis::Options {
        filter,
        ..analysis::Options::default()
    };
    let mut collector = forwarding::Collector::new(rules, side, EVIDENCE_BUDGET);
    let summary = analysis::run(&mut reader, common::registry(), &options, |record| {
        collector
            .observe(&record)
            .map_err(BoundaryError::from_error)
    })
    .expect("analysis run completes");
    SideInput {
        frames_read: summary.frames_read,
        observations: collector.into_observations(),
    }
}

fn compare(rules: &forwarding::Rules, ingress: &[Frame], egress: &[Frame]) -> forwarding::Report {
    let ingress = collect(rules, Side::Ingress, ingress, None);
    let egress = collect(rules, Side::Egress, egress, None);
    forwarding::verify(rules, ingress, egress, MAX_DETAILS, None).expect("verification completes")
}

#[test]
fn exact_correspondence_passes() {
    let ingress = vec![
        frame(1, common::CLIENT, common::SERVER, (40_000, 9_000), b"one"),
        frame(2, common::CLIENT, common::SERVER, (40_000, 9_000), b"two"),
        frame(3, common::CLIENT, common::SERVER, (40_000, 9_000), b"three"),
    ];
    let egress = ingress.clone();
    let rules = rules(&["ipv4.source", "raw.bytes"], &["ipv4.ttl"], &[]);
    let report = compare(&rules, &ingress, &egress);

    assert_eq!(report.verdict, Verdict::Pass);
    assert_eq!(report.summary.unique_matches, 3);
    assert_eq!(report.summary.checks_violated, 0);
    assert_eq!(report.summary.checks_satisfied, 3);
    assert_eq!(report.sides.ingress.read, 3);
    assert_eq!(report.sides.ingress.selected, 3);
    assert!(report.violations.is_empty());
    assert!(report.ambiguous.is_empty());
    assert!(report.unmatched.ingress.is_empty() && report.unmatched.egress.is_empty());
    assert_eq!(report.rules.identity, ["ipv4.source", "raw.bytes"]);
}

#[test]
fn expected_address_translation_passes_and_preserved_fields_hold() {
    let ingress = vec![frame(
        1,
        common::CLIENT,
        common::SERVER,
        (40_000, 9_000),
        b"one",
    )];
    let egress = vec![frame(
        9,
        Ipv4Addr::new(10, 0, 0, 2),
        common::SERVER,
        (40_000, 9_000),
        b"one",
    )];
    let rules = rules(
        &["raw.bytes"],
        &["ipv4.destination", "udp.destination_port"],
        &["ipv4.source=10.0.0.2"],
    );
    let report = compare(&rules, &ingress, &egress);

    assert_eq!(report.verdict, Verdict::Pass);
    assert_eq!(report.summary.unique_matches, 1);
    let pair = &report.matches[0];
    assert_eq!(pair.ingress.frame, 1);
    assert_eq!(pair.egress.frame, 1);
    assert_eq!(pair.checks.len(), 3);
    assert!(
        pair.checks
            .iter()
            .all(|check| check.outcome == Outcome::Satisfied)
    );
}

#[test]
fn expected_port_translation_passes() {
    let ingress = vec![frame(
        1,
        common::CLIENT,
        common::SERVER,
        (40_000, 9_000),
        b"one",
    )];
    let egress = vec![frame(
        2,
        common::CLIENT,
        common::SERVER,
        (40_000, 8_080),
        b"one",
    )];
    let rules = rules(&["raw.bytes"], &[], &["udp.destination_port=8080"]);
    let report = compare(&rules, &ingress, &egress);

    assert_eq!(report.verdict, Verdict::Pass);
    assert_eq!(report.summary.checks_evaluated, 1);
}

#[test]
fn a_wrong_transformed_field_is_a_concrete_failure() {
    let ingress = vec![frame(
        1,
        common::CLIENT,
        common::SERVER,
        (40_000, 9_000),
        b"one",
    )];
    let egress = vec![frame(
        1,
        Ipv4Addr::new(10, 9, 9, 9),
        common::SERVER,
        (40_000, 9_000),
        b"one",
    )];
    let rules = rules(&["raw.bytes"], &[], &["ipv4.source=10.0.0.2"]);
    let report = compare(&rules, &ingress, &egress);

    assert_eq!(report.verdict, Verdict::Fail);
    assert_eq!(report.summary.unique_matches, 1);
    assert_eq!(report.summary.checks_violated, 1);
    assert_eq!(report.violations.len(), 1);
    let violation = &report.violations[0];
    assert_eq!(violation.check.kind, CheckKind::Expect);
    assert_eq!(violation.check.field, "ipv4.source");
    assert_eq!(
        violation.actual,
        Some(FieldValue::Ipv4(Ipv4Addr::new(10, 9, 9, 9)))
    );
    assert!(violation.ingress.is_some());
    // A pairing whose only problem is a wrong field still pairs: the identity
    // is what matched, the check is what failed.
    assert_eq!(report.matches[0].checks[0].outcome, Outcome::Violated);
}

#[test]
fn preservation_violations_name_expected_and_actual() {
    // A forwarder decrementing TTL is classic; the pair still matches by
    // identity but the preservation rule demonstrably fails.
    let mut bytes = frame(1, common::CLIENT, common::SERVER, (40_000, 9_000), b"one")
        .bytes()
        .to_vec();
    bytes[8] = 63;
    bytes[10] = 0;
    bytes[11] = 0;
    let checksum = ipv4_checksum(&bytes[..20]);
    bytes[10] = (checksum >> 8) as u8;
    bytes[11] = checksum as u8;
    let egress = Frame::new(UNIX_EPOCH + Duration::from_secs(1), LinkType::IPV4, bytes)
        .expect("modified fixture is valid");

    let ingress = vec![frame(
        1,
        common::CLIENT,
        common::SERVER,
        (40_000, 9_000),
        b"one",
    )];
    let rules = rules(&["raw.bytes"], &["ipv4.ttl"], &[]);
    let report = compare(&rules, &ingress, &[egress]);

    assert_eq!(report.verdict, Verdict::Fail);
    let violation = &report.violations[0];
    assert_eq!(violation.check.kind, CheckKind::Preserve);
    assert_eq!(violation.check.field, "ipv4.ttl");
    assert_eq!(violation.expected, Some(FieldValue::Unsigned(64)));
    assert_eq!(violation.actual, Some(FieldValue::Unsigned(63)));
}

/// RFC 791 header checksum for the modified fixture.
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for pair in header.as_chunks::<2>().0 {
        sum += u32::from(u16::from_be_bytes(*pair));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

#[test]
fn a_missing_egress_observation_is_inconclusive_not_loss() {
    let ingress = vec![
        frame(1, common::CLIENT, common::SERVER, (40_000, 9_000), b"one"),
        frame(2, common::CLIENT, common::SERVER, (40_000, 9_000), b"two"),
    ];
    let egress = vec![frame(
        1,
        common::CLIENT,
        common::SERVER,
        (40_000, 9_000),
        b"one",
    )];
    let rules = rules(&["raw.bytes"], &[], &[]);
    let report = compare(&rules, &ingress, &egress);

    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(report.summary.unique_matches, 1);
    assert_eq!(report.summary.ingress_only, 1);
    assert_eq!(report.unmatched.ingress[0].frame, 2);
}

#[test]
fn an_extra_egress_observation_is_inconclusive_not_duplication() {
    let ingress = vec![frame(
        1,
        common::CLIENT,
        common::SERVER,
        (40_000, 9_000),
        b"one",
    )];
    let egress = vec![
        frame(1, common::CLIENT, common::SERVER, (40_000, 9_000), b"one"),
        frame(2, common::CLIENT, common::SERVER, (40_000, 9_000), b"extra"),
    ];
    let rules = rules(&["raw.bytes"], &[], &[]);
    let report = compare(&rules, &ingress, &egress);

    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(report.summary.egress_only, 1);
    assert_eq!(report.unmatched.egress[0].frame, 2);
}

#[test]
fn repeated_identities_are_never_paired() {
    let repeated = frame(1, common::CLIENT, common::SERVER, (40_000, 9_000), b"same");
    let rules = rules(&["raw.bytes"], &[], &[]);

    // 2 against 1 cannot pair, even though one pairing would "fit".
    let report = compare(
        &rules,
        &[repeated.clone(), repeated.clone()],
        std::slice::from_ref(&repeated),
    );
    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(report.summary.unique_matches, 0);
    assert_eq!(report.summary.ambiguous_groups, 1);
    assert_eq!(report.summary.ambiguous_observations, 3);
    let group = &report.ambiguous[0];
    assert_eq!(group.ingress_total, 2);
    assert_eq!(group.egress_total, 1);
    assert!(group.ingress_indistinguishable);

    // Identical packets on both sides are equally unresolvable.
    let report = compare(
        &rules,
        &[repeated.clone(), repeated.clone()],
        &[repeated.clone(), repeated.clone()],
    );
    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(report.ambiguous[0].egress_total, 2);
    assert!(report.ambiguous[0].egress_indistinguishable);
}

#[test]
fn distinguishable_repetition_reports_multiplicity() {
    let shared = frame(1, common::CLIENT, common::SERVER, (40_000, 9_000), b"same");
    // Two egress copies of one keyed identity: ambiguity is preserved and
    // neither copy is claimed as the match.
    let rules = rules(&["raw.bytes"], &[], &[]);
    let report = compare(
        &rules,
        std::slice::from_ref(&shared),
        &[shared.clone(), shared.clone()],
    );
    assert_eq!(report.verdict, Verdict::Inconclusive);
    let group = &report.ambiguous[0];
    assert_eq!((group.ingress_total, group.egress_total), (1, 2));
}

#[test]
fn reordered_unique_identities_still_match() {
    let a = frame(1, common::CLIENT, common::SERVER, (40_000, 9_000), b"a");
    let b = frame(2, common::CLIENT, common::SERVER, (40_000, 9_000), b"b");
    let c = frame(3, common::CLIENT, common::SERVER, (40_000, 9_000), b"c");
    let rules = rules(&["raw.bytes"], &[], &[]);
    let report = compare(&rules, &[a.clone(), b.clone(), c.clone()], &[c, a, b]);

    assert_eq!(report.verdict, Verdict::Pass);
    assert_eq!(report.summary.unique_matches, 3);
    assert_eq!(report.summary.reordered_pairs, 1);
    // Matches publish in ingress order with per-capture evidence.
    assert_eq!(
        report
            .matches
            .iter()
            .map(|pair| (pair.ingress.frame, pair.egress.frame))
            .collect::<Vec<_>>(),
        vec![(1, 2), (2, 3), (3, 1)]
    );
    assert_eq!(
        report.matches.iter().filter(|pair| pair.reordered).count(),
        1
    );
    // Frame numbers are capture-local: the same number on each side is a
    // different observation.
    assert_eq!(report.matches[0].ingress.frame, 1);
    assert_eq!(report.matches[0].egress.frame, 2);
}

#[test]
fn unsynchronized_timestamps_are_evidence_never_latency() {
    let ingress = vec![frame(
        1,
        common::CLIENT,
        common::SERVER,
        (40_000, 9_000),
        b"one",
    )];
    // A completely unrelated capture clock still matches by identity.
    let egress = vec![frame(
        1_700_000_000,
        common::CLIENT,
        common::SERVER,
        (40_000, 9_000),
        b"one",
    )];
    let rules = rules(&["raw.bytes"], &[], &[]);
    let report = compare(&rules, &ingress, &egress);

    assert_eq!(report.verdict, Verdict::Pass);
    let pair = &report.matches[0];
    assert_ne!(pair.ingress.timestamp, pair.egress.timestamp);
    assert!(
        report
            .assumptions
            .iter()
            .any(|line| line.contains("latency"))
    );
}

#[test]
fn an_empty_selection_cannot_pass() {
    let frames = vec![frame(
        1,
        common::CLIENT,
        common::SERVER,
        (40_000, 9_000),
        b"one",
    )];
    let rules = rules(&["raw.bytes"], &[], &[]);
    let report = compare(&rules, &[], &frames);
    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(report.sides.ingress.selected, 0);
    assert_eq!(report.summary.egress_only, 1);

    let report = compare(&rules, &[], &[]);
    assert_eq!(report.verdict, Verdict::Inconclusive);
}

#[test]
fn a_selection_filter_applies_per_capture() {
    let registry = common::registry();
    let ingress_only_udp53 = Filter::compile(
        "udp.destination_port == 9000",
        &registry,
        packetcraftr_core::filter::Options::default(),
    )
    .expect("filter compiles");
    let rules = rules(&["raw.bytes"], &[], &[]);
    let ingress_frames = vec![
        frame(1, common::CLIENT, common::SERVER, (40_000, 9_000), b"one"),
        frame(2, common::CLIENT, common::SERVER, (40_000, 6_500), b"other"),
    ];
    let egress_frames = vec![frame(
        1,
        common::CLIENT,
        common::SERVER,
        (40_000, 9_000),
        b"one",
    )];
    let mut reader = common::reader(&ingress_frames);
    let options = analysis::Options {
        filter: Some(&ingress_only_udp53),
        ..analysis::Options::default()
    };
    let mut collector = forwarding::Collector::new(&rules, Side::Ingress, EVIDENCE_BUDGET);
    let summary = analysis::run(&mut reader, registry, &options, |record| {
        collector
            .observe(&record)
            .map_err(BoundaryError::from_error)
    })
    .expect("run completes");
    let ingress = SideInput {
        frames_read: summary.frames_read,
        observations: collector.into_observations(),
    };
    let egress = collect(&rules, Side::Egress, &egress_frames, None);
    let report = forwarding::verify(&rules, ingress, egress, MAX_DETAILS, None).unwrap();

    assert_eq!(report.verdict, Verdict::Pass);
    assert_eq!(report.sides.ingress.read, 2);
    assert_eq!(report.sides.ingress.selected, 1);
    assert_eq!(report.summary.unique_matches, 1);
}

#[test]
fn unkeyable_observations_are_listed_not_dropped() {
    let ingress = vec![
        frame(1, common::CLIENT, common::SERVER, (40_000, 9_000), b"one"),
        // No UDP layer: the declared identity cannot resolve.
        common::tcp_frame(
            &common::registry(),
            UNIX_EPOCH + Duration::from_secs(2),
            common::client_tcp(100, 0, 0x02, 65_535),
            b"orphan",
        ),
    ];
    let egress = vec![frame(
        1,
        common::CLIENT,
        common::SERVER,
        (40_000, 9_000),
        b"one",
    )];
    let rules = rules(&["udp.destination_port"], &[], &[]);
    let report = compare(&rules, &ingress, &egress);

    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(report.sides.ingress.unkeyed, 1);
    assert_eq!(report.unkeyed.ingress.len(), 1);
    assert_eq!(report.unkeyed.ingress[0].evidence.frame, 2);
    assert_eq!(report.unkeyed.ingress[0].key, vec![None]);
}

#[test]
fn truncated_evidence_is_explicit_and_unkeyable() {
    let ingress = vec![frame(
        1,
        common::CLIENT,
        common::SERVER,
        (53_000, 9_000),
        b"payload-data-here",
    )];
    // Two missing payload bytes break decode outright: the observation is
    // unkeyable and incomplete, never silently dropped or guessed.
    let egress = vec![truncated_frame(1, b"payload-data-here")];
    let rules = rules(&["raw.bytes"], &["raw.bytes"], &[]);
    let report = compare(&rules, &ingress, &egress);

    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(report.sides.egress.incomplete, 1);
    assert_eq!(report.sides.egress.unkeyed, 1);
    assert_eq!(report.summary.ingress_only, 1);
    let unkeyed = &report.unkeyed.egress[0];
    assert_eq!(unkeyed.evidence.incomplete, Some(Incomplete::Truncated));
    assert!(
        unkeyed
            .evidence
            .diagnostics
            .contains(&"decode.malformed_layer")
    );
}

#[test]
fn a_short_record_still_flags_incomplete_evidence() {
    // The keyed bytes decode consistently, but the capture record itself
    // admits it lost wire bytes. The header is readable, but capture-level
    // incompleteness still prevents an overall pass.
    let full = frame(1, common::CLIENT, common::SERVER, (53_000, 9_000), b"one");
    let short = short_record(1, b"one");
    let rules = rules(&["ipv4.source"], &["ipv4.ttl"], &[]);
    let report = compare(&rules, &[full], &[short]);

    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(report.summary.unique_matches, 1);
    assert_eq!(report.summary.checks_satisfied, 1);
    assert_eq!(report.summary.checks_unevaluable, 0);
    assert_eq!(
        report.matches[0].egress.incomplete,
        Some(Incomplete::Truncated)
    );
}

#[test]
fn the_evidence_budget_fails_loudly_instead_of_evicting() {
    let rules = rules(&["raw.bytes"], &[], &[]);
    let mut collector = forwarding::Collector::new(&rules, Side::Ingress, 200);
    let mut reader = common::reader(&[
        frame(1, common::CLIENT, common::SERVER, (40_000, 9_000), b"one"),
        frame(2, common::CLIENT, common::SERVER, (40_000, 9_000), b"two"),
    ]);
    let options = analysis::Options::default();
    let error = analysis::run(&mut reader, common::registry(), &options, |record| {
        collector
            .observe(&record)
            .map_err(BoundaryError::from_error)
    })
    .expect_err("the retained-evidence bound fails the run");
    let budgeted = error
        .source()
        .and_then(|boundary| boundary.source())
        .and_then(|source| source.downcast_ref::<forwarding::Error>())
        .expect("the sink error retains the budget refusal as its source");
    assert!(
        matches!(budgeted, forwarding::Error::EvidenceBudget { .. }),
        "{budgeted:?}"
    );
    assert_eq!(budgeted.classification().kind, Kind::Policy);
}

#[test]
fn cancellation_stops_verification() {
    let rules = rules(&["raw.bytes"], &[], &[]);
    let ingress = collect(
        &rules,
        Side::Ingress,
        &[frame(
            1,
            common::CLIENT,
            common::SERVER,
            (40_000, 9_000),
            b"one",
        )],
        None,
    );
    let egress = collect(
        &rules,
        Side::Egress,
        &[frame(
            1,
            common::CLIENT,
            common::SERVER,
            (40_000, 9_000),
            b"one",
        )],
        None,
    );
    let cancellation = Cancellation::default();
    cancellation.cancel();
    let error = forwarding::verify(&rules, ingress, egress, MAX_DETAILS, Some(&cancellation))
        .expect_err("a cancelled comparison cannot produce a verdict");
    assert_eq!(error.classification().code, "io.cancelled");
}

#[test]
fn report_detail_is_bounded_and_counts_omissions() {
    let ingress: Vec<Frame> = (0..8_u8)
        .map(|index| {
            frame(
                u64::from(index),
                common::CLIENT,
                common::SERVER,
                (40_000, 9_000),
                &[index],
            )
        })
        .collect();
    let egress: Vec<Frame> = ingress.iter().skip(4).cloned().collect();
    let rules = rules(&["raw.bytes"], &[], &[]);
    let ingress = collect(&rules, Side::Ingress, &ingress, None);
    let egress = collect(&rules, Side::Egress, &egress, None);
    let report = forwarding::verify(&rules, ingress, egress, 2, None).unwrap();

    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(report.summary.ingress_only, 4);
    assert_eq!(report.summary.unique_matches, 4);
    // The document lists two entries per category; the counters stay exact.
    assert_eq!(report.matches.len(), 2);
    assert_eq!(report.unmatched.ingress.len(), 2);
    assert_eq!(report.omitted.matches, 2);
    assert_eq!(report.omitted.unmatched_ingress, 2);
}

#[test]
fn capture_local_fields_cannot_name_identity() {
    for field in [
        "frame.number",
        "frame.interface_id",
        "frame.time_epoch",
        "tcp.stream",
        "udp.stream",
    ] {
        let error = forwarding::Rules::compile(
            &[field.to_owned()],
            &[],
            &[],
            &builtin::registry(),
            FIELD_BUDGET,
        )
        .expect_err("capture-local identity is rejected");
        assert!(
            matches!(error, forwarding::Error::CaptureLocal { .. }),
            "{field}: {error}"
        );
        assert_eq!(error.classification().kind, Kind::Cli);
    }
}

#[test]
fn rules_echo_exactly_what_was_requested() {
    let rules = rules(
        &["ipv4.source", "raw.bytes"],
        &["ipv4.ttl"],
        &[
            "udp.destination_port=9000",
            "ipv4.destination == 198.51.100.2",
        ],
    );
    let report = compare(
        &rules,
        &[frame(
            1,
            common::CLIENT,
            common::SERVER,
            (40_000, 9_000),
            b"one",
        )],
        &[frame(
            1,
            common::CLIENT,
            common::SERVER,
            (40_000, 9_000),
            b"one",
        )],
    );
    assert_eq!(report.rules.identity, ["ipv4.source", "raw.bytes"]);
    assert_eq!(report.rules.preserve, ["ipv4.ttl"]);
    let expect: Vec<_> = report
        .rules
        .expect
        .iter()
        .map(|rule| (rule.field.as_str(), rule.value.as_str()))
        .collect();
    assert_eq!(
        expect,
        [
            ("udp.destination_port", "9000"),
            ("ipv4.destination", "198.51.100.2")
        ]
    );
}

#[test]
fn empty_identity_is_rejected() {
    let error = forwarding::Rules::compile(&[], &[], &[], &builtin::registry(), FIELD_BUDGET)
        .expect_err("identity must not be empty");
    assert_eq!(error.classification().kind, Kind::Cli);
}

#[test]
fn malformed_expectations_are_rejected_before_input() {
    for rule in [
        "",
        "no-separator",
        "=53",
        "udp.destination_port=",
        "tcp.nosuch=1",
    ] {
        let error = forwarding::Rules::compile(
            &["raw.bytes".to_owned()],
            &[],
            &[rule.to_owned()],
            &builtin::registry(),
            FIELD_BUDGET,
        )
        .expect_err("invalid expectation must be rejected");
        assert_eq!(error.classification().kind, Kind::Cli, "{rule}");
    }
}

#[test]
fn exhausted_identity_cannot_fabricate_a_match() {
    let rules =
        forwarding::Rules::compile(&["raw.bytes".into()], &[], &[], &builtin::registry(), 1)
            .unwrap();
    let report = compare(
        &rules,
        &[frame(
            1,
            common::CLIENT,
            common::SERVER,
            (40_000, 9_000),
            b"one",
        )],
        &[frame(
            1,
            common::CLIENT,
            common::SERVER,
            (40_000, 9_000),
            b"two",
        )],
    );
    assert_eq!(report.summary.unique_matches, 0);
    assert_eq!(report.sides.ingress.unkeyed, 1);
    assert_eq!(report.sides.egress.unkeyed, 1);
    assert_eq!(report.unkeyed.ingress[0].key, vec![None]);
    assert_eq!(report.verdict, Verdict::Inconclusive);
}

#[test]
fn all_observation_projections_share_one_budget() {
    let frames = [frame(
        1,
        common::CLIENT,
        common::SERVER,
        (40_000, 9_000),
        b"one",
    )];
    for (preserve, expect, required) in [
        (vec!["ipv4.ttl".into()], vec![], 3),
        (vec![], vec!["ipv4.ttl=64".into(), "ipv4.ttl=64".into()], 5),
        (vec!["ipv4.ttl".into()], vec!["ipv4.ttl=64".into()], 5),
    ] {
        for budget in [required - 1, required] {
            let rules = forwarding::Rules::compile(
                &["ipv4.identification".into()],
                &preserve,
                &expect,
                &builtin::registry(),
                budget,
            )
            .unwrap();
            let report = compare(&rules, &frames, &frames);
            if budget < required {
                assert_eq!(report.verdict, Verdict::Inconclusive);
                assert_eq!(report.sides.egress.incomplete, 1);
                // Earlier readable fields remain evaluated when the final
                // field exhausts the shared observation budget.
                assert_eq!(
                    report.summary.checks_evaluated,
                    if required == 3 { 0 } else { 1 }
                );
                assert_eq!(
                    report.matches[0].egress.incomplete,
                    Some(Incomplete::FieldBudget)
                );
            } else {
                assert_eq!(report.verdict, Verdict::Pass);
            }
        }
    }
}

#[test]
fn reordering_counts_and_flags_survive_detail_limits() {
    let a = frame(1, common::CLIENT, common::SERVER, (40_000, 9_000), b"a");
    let b = frame(2, common::CLIENT, common::SERVER, (40_000, 9_000), b"b");
    let rules = rules(&["raw.bytes"], &[], &[]);
    // The lexically first identity is second in ingress, so its retained flag
    // depends on an earlier pair omitted by a one-detail limit.
    for limit in [0, 1, 2] {
        let report = forwarding::verify(
            &rules,
            collect(&rules, Side::Ingress, &[b.clone(), a.clone()], None),
            collect(&rules, Side::Egress, &[a.clone(), b.clone()], None),
            limit,
            None,
        )
        .unwrap();
        assert_eq!(report.summary.reordered_pairs, 1);
        assert_eq!(report.summary.unique_matches, 2);
        assert_eq!(report.omitted.matches, (2 - limit) as u64);
        for pair in report.matches {
            assert_eq!(pair.reordered, pair.ingress.frame == 2);
        }
    }
}

#[test]
fn expectations_accept_only_one_literal() {
    for value in ["63 or udp", "63 || udp", "64 and udp", "(64)", "64 == 64"] {
        assert!(
            forwarding::Rules::compile(
                &["raw.bytes".into()],
                &[],
                &[format!("ipv4.ttl={value}")],
                &builtin::registry(),
                FIELD_BUDGET,
            )
            .is_err(),
            "accepted {value}"
        );
    }
    // Operator text inside a quoted literal remains literal data.
    rules(&["raw.bytes"], &[], &[r#"raw.bytes="63 or udp""#]);
}

#[test]
fn forwarding_observations_ignore_reconstructed_children() {
    let fragments = common::ip_fragments::ipv4_fragments(&common::registry());
    let rules = rules(
        &["udp.source_port"],
        &["udp.destination_port"],
        &["udp.destination_port=9999"],
    );
    let side = collect(&rules, Side::Egress, &fragments, None);
    let completion = &side.observations[1];
    assert!(completion.key().is_none());
    assert_eq!(completion.preserved(), &[None]);
    assert_eq!(completion.expectations()[0].actual, None);
    assert!(!completion.expectations()[0].satisfied);
}

#[test]
fn two_missing_values_never_satisfy_ordinary_preservation() {
    let frames = [frame(
        1,
        common::CLIENT,
        common::SERVER,
        (40000, 9000),
        b"one",
    )];
    let rules = rules(&["ipv4.identification"], &["tcp.sequence"], &[]);
    let report = compare(&rules, &frames, &frames);
    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(report.summary.checks_satisfied, 0);
    assert_eq!(report.summary.checks_unevaluable, 1);
    assert_eq!(
        report.matches[0].checks[0].actual_state,
        forwarding::ValueState::Absent
    );
}

#[test]
fn explicit_decoder_view_absence_is_not_value_equality() {
    let identity = vec!["ipv4.identification".to_owned()];
    let presence = vec!["tcp.sequence".to_owned()];
    let rules = forwarding::Rules::compile_declarations(
        forwarding::Declarations {
            identity: &identity,
            preserve_presence: &presence,
            expect_absent: &presence,
            ..forwarding::Declarations::default()
        },
        &builtin::registry(),
        FIELD_BUDGET,
    )
    .unwrap();
    let frames = [frame(
        1,
        common::CLIENT,
        common::SERVER,
        (40000, 9000),
        b"one",
    )];
    let report = compare(&rules, &frames, &frames);
    assert_eq!(report.verdict, Verdict::Pass);
    assert_eq!(report.summary.checks_satisfied, 2);
    assert_eq!(
        report.matches[0].checks[0].check.kind,
        CheckKind::PreservePresence
    );
    assert_eq!(
        report.matches[0].checks[1].check.kind,
        CheckKind::ExpectAbsent
    );
}

#[test]
fn missing_value_expectations_require_readable_evidence() {
    let rules = rules(&["ipv4.identification"], &[], &["tcp.sequence=1"]);
    let frames = [frame(
        1,
        common::CLIENT,
        common::SERVER,
        (40000, 9000),
        b"one",
    )];
    let report = compare(&rules, &frames, &frames);
    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(report.summary.checks_violated, 0);
    assert_eq!(report.summary.checks_unevaluable, 1);
}

#[test]
fn rules_side_and_capture_order_cannot_be_substituted() {
    let first = rules(&["ipv4.identification"], &[], &[]);
    let second = rules(&["ipv4.identification"], &[], &["ipv4.ttl=1"]);
    let frames = [frame(
        1,
        common::CLIENT,
        common::SERVER,
        (40000, 9000),
        b"one",
    )];
    let ingress = collect(&first, Side::Ingress, &frames, None);
    let egress = collect(&first, Side::Egress, &frames, None);
    assert!(matches!(
        forwarding::verify(&second, ingress.clone(), egress.clone(), 256, None),
        Err(forwarding::Error::ObservationContract { .. })
    ));
    assert!(matches!(
        forwarding::verify(&first, egress, ingress, 256, None),
        Err(forwarding::Error::ObservationContract { .. })
    ));
    let mut ingress = collect(
        &first,
        Side::Ingress,
        &[frames[0].clone(), frames[0].clone()],
        None,
    );
    ingress.observations.reverse();
    let egress = collect(&first, Side::Egress, &frames, None);
    assert!(matches!(
        forwarding::verify(&first, ingress, egress, 256, None),
        Err(forwarding::Error::ObservationContract { .. })
    ));
}

#[test]
fn unrelated_projection_exhaustion_cannot_erase_a_header_violation() {
    let rules = forwarding::Rules::compile(
        &["ipv4.identification".to_owned()],
        &["udp.source_port".to_owned(), "raw.bytes".to_owned()],
        &[],
        &builtin::registry(),
        8,
    )
    .unwrap();
    let ingress = [frame(
        1,
        common::CLIENT,
        common::SERVER,
        (40000, 9000),
        b"large-payload",
    )];
    let egress = [frame(
        1,
        common::CLIENT,
        common::SERVER,
        (40001, 9000),
        b"large-payload",
    )];
    let report = compare(&rules, &ingress, &egress);
    assert_eq!(report.verdict, Verdict::Fail);
    assert_eq!(report.summary.checks_violated, 1);
    assert_eq!(report.summary.checks_unevaluable, 1);
}

#[test]
fn truncation_cannot_erase_a_readable_header_violation() {
    let rules = rules(&["ipv4.identification"], &["udp.source_port"], &[]);
    let ingress = [frame(
        1,
        common::CLIENT,
        common::SERVER,
        (40000, 9000),
        b"one",
    )];
    // This source port is 53000; the capture admits missing unrelated bytes.
    let egress = [short_record(1, b"one")];
    let report = compare(&rules, &ingress, &egress);
    assert_eq!(report.verdict, Verdict::Fail);
    assert_eq!(report.summary.checks_violated, 1);
    assert_eq!(report.sides.egress.incomplete, 1);
}

#[test]
fn details_are_presentation_and_scratch_is_a_separate_failure_domain() {
    let rules = rules(&["raw.bytes"], &["udp.source_port"], &[]);
    let ingress = [frame(
        1,
        common::CLIENT,
        common::SERVER,
        (40000, 9000),
        b"one",
    )];
    let egress = [frame(
        1,
        common::CLIENT,
        common::SERVER,
        (40001, 9000),
        b"one",
    )];
    let reference = compare(&rules, &ingress, &egress);
    for max_details in [0, 1, 256] {
        for max_detail_bytes in [0, 1, 4096] {
            let report = forwarding::verify_with_limits(
                &rules,
                collect(&rules, Side::Ingress, &ingress, None),
                collect(&rules, Side::Egress, &egress, None),
                forwarding::VerifyLimits {
                    max_details,
                    max_detail_bytes,
                    ..forwarding::VerifyLimits::default()
                },
                None,
                None,
            )
            .unwrap();
            assert_eq!(report.verdict, reference.verdict);
            assert_eq!(report.summary, reference.summary);
            assert_eq!(report.matches.len() as u64 + report.omitted.matches, 1);
            assert_eq!(
                report.violations.len() as u64 + report.omitted.violations,
                1
            );
        }
    }
    let error = forwarding::verify_with_limits(
        &rules,
        collect(&rules, Side::Ingress, &ingress, None),
        collect(&rules, Side::Egress, &egress, None),
        forwarding::VerifyLimits {
            max_scratch_bytes: 0,
            ..Default::default()
        },
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.verify_scratch_limit");
}

#[test]
fn identity_only_and_overlapping_rules_explain_their_scope() {
    let frames = [frame(
        1,
        common::CLIENT,
        common::SERVER,
        (40000, 9000),
        b"one",
    )];
    let identity_only = rules(&["raw.bytes"], &[], &[]);
    let report = compare(&identity_only, &frames, &frames);
    assert_eq!(
        report.rules.comparison,
        forwarding::ComparisonKind::CorrespondenceOnly
    );
    assert!(
        report
            .rules
            .warnings
            .iter()
            .any(|w| w.code == "verify.correspondence_only")
    );
    let overlap = rules(&["raw.bytes"], &["raw.bytes"], &[]);
    let report = compare(&overlap, &frames, &frames);
    assert!(
        report
            .rules
            .warnings
            .iter()
            .any(|w| w.code == "verify.identity_preservation_overlap")
    );
}

#[test]
fn an_expired_comparison_cannot_publish_a_verdict() {
    use packetcraftr_core::budget::Deadline;
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    use std::time::Instant;
    let rules = rules(&["ipv4.identification"], &["ipv4.ttl"], &[]);
    let frames = [frame(
        1,
        common::CLIENT,
        common::SERVER,
        (40000, 9000),
        b"one",
    )];
    let ingress = collect(&rules, Side::Ingress, &frames, None);
    let egress = collect(&rules, Side::Egress, &frames, None);
    let ticks = Arc::new(AtomicU64::new(0));
    let observed = ticks.clone();
    let start = Instant::now();
    let deadline = Deadline::with_time_source(Duration::from_millis(5), move || {
        start + Duration::from_millis(observed.load(Ordering::SeqCst))
    });
    ticks.store(6, Ordering::SeqCst);
    let error = forwarding::verify_with_limits(
        &rules,
        ingress,
        egress,
        Default::default(),
        None,
        Some(&deadline),
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.duration_limit");
}

#[test]
fn introducing_an_absent_field_breaks_the_explicit_absence_contract() {
    let identity = vec!["ipv4.identification".to_owned()];
    let absence = vec!["tcp.sequence".to_owned()];
    let rules = forwarding::Rules::compile_declarations(
        forwarding::Declarations {
            identity: &identity,
            expect_absent: &absence,
            ..Default::default()
        },
        &builtin::registry(),
        FIELD_BUDGET,
    )
    .unwrap();
    let before = frame(1, common::CLIENT, common::SERVER, (40000, 9000), b"one");
    let after = common::tcp_frame(
        &common::registry(),
        UNIX_EPOCH + Duration::from_secs(1),
        common::client_tcp(1, 0, packetcraftr_core::protocol::transport::Tcp::SYN, 1024),
        b"",
    );
    let report = compare(&rules, &[before], &[after]);
    assert_eq!(report.verdict, Verdict::Fail);
    assert_eq!(report.summary.checks_violated, 1);
}
