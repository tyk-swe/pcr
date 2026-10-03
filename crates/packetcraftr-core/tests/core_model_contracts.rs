// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error as _;
use std::fmt;
use std::time::{Duration, SystemTime};

use packetcraftr_core::{
    budget::Deadline,
    error::{BoundaryError, Classification, Classified, Kind},
    frame::{Direction, Frame, Lengths, LinkType},
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
        .check_additional(Duration::from_secs(61))
        .expect_err("ordinary prospective work above the limit must fail");
    assert!(error.actual > error.limit);
    assert_eq!(error.limit, Duration::from_secs(60));

    let error = deadline
        .check_additional(Duration::MAX)
        .expect_err("duration addition overflow must fail closed");
    assert_eq!(error.actual, Duration::MAX);
    assert_eq!(error.limit, Duration::from_secs(60));

    let error = deadline
        .account(Duration::from_secs(61))
        .expect_err("committed accounting above the limit must fail");
    assert!(error.actual > error.limit);
}

#[test]
fn frame_lengths_fail_closed_during_construction_and_deserialization() {
    let cases = [
        (
            2,
            2,
            vec![0_u8],
            packetcraftr_core::frame::Error::CapturedLengthMismatch {
                declared: 2,
                actual: 1,
            },
        ),
        (
            2,
            1,
            vec![0_u8, 1],
            packetcraftr_core::frame::Error::OriginalLengthTooSmall {
                captured: 2,
                original: 1,
            },
        ),
    ];

    for (captured, original, bytes, expected) in cases {
        let error = Frame::try_with_lengths(
            SystemTime::UNIX_EPOCH,
            LinkType::ETHERNET,
            Lengths { captured, original },
            bytes,
        )
        .expect_err("invalid capture lengths must be rejected");
        assert_eq!(error, expected);
    }

    let invalid = serde_json::json!({
        "captured_length": 2,
        "original_length": 2,
        "link_type": LinkType::ETHERNET.0,
        "bytes": [0]
    });
    let error = serde_json::from_value::<Frame>(invalid)
        .expect_err("deserialization must revalidate capture lengths");
    assert!(error.to_string().contains("says 2 bytes but contains 1"));
}

#[test]
fn frame_truncation_reflects_capture_lengths_only() {
    let frame = |captured, original, bytes| {
        Frame::try_with_lengths(
            SystemTime::UNIX_EPOCH,
            LinkType::ETHERNET,
            Lengths { captured, original },
            bytes,
        )
        .expect("valid capture lengths")
    };

    assert!(!frame(2, 2, vec![0, 1]).is_truncated());
    assert!(!frame(0, 0, Vec::new()).is_truncated());
    assert!(frame(1, 2, vec![0]).is_truncated());
    assert!(frame(0, u32::MAX, Vec::new()).is_truncated());

    assert!(
        !Frame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, vec![0, 1])
            .expect("inferred lengths")
            .is_truncated()
    );
    assert!(
        !Frame::without_timestamp(LinkType::ETHERNET, Vec::new())
            .expect("inferred lengths")
            .is_truncated()
    );

    let mut decorated = frame(1, 3, vec![0]);
    decorated.interface = Some(2);
    decorated.direction = Some(Direction::Outbound);
    assert!(decorated.is_truncated());

    let untimestamped = Frame::try_with_optional_timestamp(
        None,
        LinkType(0xFFFF_0001),
        Lengths {
            captured: 1,
            original: 2,
        },
        vec![0],
    )
    .expect("link types are open");
    assert!(untimestamped.is_truncated());
    let untruncated_unknown = Frame::try_with_optional_timestamp(
        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1)),
        LinkType(0xFFFF_0001),
        Lengths {
            captured: 2,
            original: 2,
        },
        vec![0, 1],
    )
    .expect("valid capture lengths");
    assert!(!untruncated_unknown.is_truncated());

    for truncated in [true, false] {
        let frame = frame(1, if truncated { 2 } else { 1 }, vec![0]);
        let value = serde_json::to_value(&frame).expect("frame serializes");
        let restored = serde_json::from_value::<Frame>(value).expect("frame round-trips");
        assert_eq!(restored.is_truncated(), truncated);
    }
}

#[test]
fn erased_classified_error_retains_source_classification_and_causes() {
    let error = BoundaryError::from_error(ClassifiedFailure);

    assert_eq!(error.to_string(), "classified failure");
    assert_eq!(
        error.classification(),
        Classification::new("test.failure", Kind::Packet, Some("repair the fixture"))
    );
    assert_eq!(error.causes(), ["wire cause", "schema cause"]);
    assert_eq!(
        error.source().map(ToString::to_string).as_deref(),
        Some("classified failure")
    );
}
