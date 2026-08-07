// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error as _;
use std::fmt;
use std::time::{Duration, SystemTime};

use packetcraftr_core::{
    budget::Deadline,
    error::{BoundaryError, Classification, Classified, Kind},
    frame::{Direction, Frame, LinkType},
};

#[derive(Debug)]
struct ClassifiedFailure;

impl fmt::Display for ClassifiedFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("classified failure")
    }
}

impl std::error::Error for ClassifiedFailure {}

impl Classified for ClassifiedFailure {
    fn classification(&self) -> Classification {
        Classification::new("test.failure", Kind::Packet, Some("repair the fixture"))
    }

    fn causes(&self) -> Vec<String> {
        vec!["wire cause".to_owned(), "schema cause".to_owned()]
    }
}

#[test]
fn deadline_accepts_bounded_phases_and_preserves_limit_on_failure() {
    let mut deadline = Deadline::new(Duration::from_secs(60));

    assert!(deadline.check().is_ok(), "fresh deadline must be available");
    assert!(
        deadline.check_additional(Duration::from_secs(1)).is_ok(),
        "bounded prospective work must fit"
    );
    assert!(
        deadline.start_accounting(Duration::from_secs(1)).is_ok(),
        "bounded phase must start"
    );
    assert!(
        deadline.account(Duration::from_secs(1)).is_ok(),
        "bounded phase must commit"
    );

    let error = deadline
        .check_additional(Duration::MAX)
        .expect_err("duration addition overflow must fail closed");
    assert_eq!(error.actual, Duration::MAX);
    assert_eq!(error.limit, Duration::from_secs(60));
}

#[test]
fn rejected_prospective_phase_does_not_spend_the_deadline() {
    let mut deadline = Deadline::new(Duration::from_secs(30));

    assert!(deadline.start_accounting(Duration::from_secs(31)).is_err());
    assert!(
        deadline.check_additional(Duration::from_secs(1)).is_ok(),
        "a rejected phase must not be committed"
    );
}

#[test]
fn frame_new_sets_exact_lengths_and_exposes_metadata() {
    let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(7);
    let mut frame = Frame::new(timestamp, LinkType::RAW, vec![1_u8, 2, 3])
        .expect("small frame must fit capture lengths");
    frame.interface = Some(9);
    frame.direction = Some(Direction::Outbound);

    assert_eq!(frame.timestamp, timestamp);
    assert_eq!(frame.link_type, LinkType::RAW);
    assert_eq!(frame.captured_length(), 3);
    assert_eq!(frame.original_length(), 3);
    assert_eq!(frame.bytes().as_ref(), [1, 2, 3]);
    assert_eq!(frame.interface, Some(9));
    assert_eq!(frame.direction, Some(Direction::Outbound));
}

#[test]
fn frame_accepts_truncated_capture_when_original_is_larger() {
    let frame = Frame::try_with_lengths(
        SystemTime::UNIX_EPOCH,
        LinkType::LINUX_SLL2,
        2,
        100,
        vec![0xaa_u8, 0xbb],
    )
    .expect("capture records may retain only a prefix of the original frame");

    assert_eq!(frame.captured_length(), 2);
    assert_eq!(frame.original_length(), 100);
    assert_eq!(frame.bytes().as_ref(), [0xaa, 0xbb]);
}

#[test]
fn link_type_constants_retain_open_numeric_values() {
    assert_eq!(LinkType::NULL.0, 0);
    assert_eq!(LinkType::ETHERNET.0, 1);
    assert_eq!(LinkType::BSD_RAW.0, 12);
    assert_eq!(LinkType::RAW.0, 101);
    assert_eq!(LinkType::LOOP.0, 108);
    assert_eq!(LinkType::LINUX_SLL.0, 113);
    assert_eq!(LinkType::IPV4.0, 228);
    assert_eq!(LinkType::IPV6.0, 229);
    assert_eq!(LinkType::LINUX_SLL2.0, 276);
    assert!(LinkType(65_535) > LinkType::ETHERNET);
}

#[test]
fn erased_classified_error_retains_source_classification_and_causes() {
    let error = BoundaryError::from_error(ClassifiedFailure);

    assert_eq!(error.to_string(), "classified failure");
    assert_eq!(error.classification().code, "test.failure");
    assert_eq!(error.classification().kind, Kind::Packet);
    assert_eq!(error.causes(), ["wire cause", "schema cause"]);
    assert_eq!(
        error.source().map(ToString::to_string).as_deref(),
        Some("classified failure")
    );
}

#[test]
fn boundary_constructors_distinguish_validation_from_internal_failures() {
    let validation =
        BoundaryError::execution_validation("bad request", "cli.test", "change the request");
    assert_eq!(validation.classification().kind, Kind::Cli);
    assert_eq!(validation.classification().code, "cli.test");
    assert_eq!(
        validation.classification().remediation,
        Some("change the request")
    );
    assert!(validation.source().is_none());

    let internal = BoundaryError::internal_execution(
        "broken executor",
        "internal.test",
        "replace the executor",
    );
    assert_eq!(internal.classification().kind, Kind::Internal);
    assert_eq!(internal.classification().code, "internal.test");
}

#[test]
fn every_error_kind_has_a_stable_machine_name() {
    let cases = [
        (Kind::Cli, "cli"),
        (Kind::Packet, "packet"),
        (Kind::Capability, "capability"),
        (Kind::Io, "io"),
        (Kind::Policy, "policy"),
        (Kind::Internal, "internal"),
    ];

    for (kind, expected) in cases {
        assert_eq!(kind.as_str(), expected);
    }
}
