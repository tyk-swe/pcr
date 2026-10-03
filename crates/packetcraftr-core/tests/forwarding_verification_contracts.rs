// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use std::net::Ipv4Addr;
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr_core::analysis::forwarding::{Side, SideInput, Verdict};
use packetcraftr_core::analysis::{self, forwarding};
use packetcraftr_core::budget::Cancellation;
use packetcraftr_core::error::{BoundaryError, Classified, Kind};
use packetcraftr_core::filter::Filter;
use packetcraftr_core::frame::{Frame, LinkType};
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

fn collect(
    rules: &forwarding::Rules,
    side: Side,
    frames: &[Frame],
    filter: Option<&Filter>,
) -> SideInput {
    let mut reader = common::ip_fragments::reader_with_link_type(
        frames
            .first()
            .map_or(LinkType::IPV4, |frame| frame.link_type),
        frames,
    );
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
    let budgeted = common::sink_cause::<forwarding::Error>(&error);
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
        assert_eq!(error.classification().kind, Kind::Usage, "{rule}");
    }
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
