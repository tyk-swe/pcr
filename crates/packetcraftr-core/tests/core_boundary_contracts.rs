// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, SystemTime};

use packetcraftr_core::{
    budget::Deadline,
    error::{BoundaryError, Classification, Classified, Kind},
    frame::{Frame, FrameError, LinkType},
};

#[test]
fn deadline_rejects_prospective_and_committed_overruns() {
    let mut deadline = Deadline::new(Duration::from_secs(10));

    let prospective = deadline
        .check_additional(Duration::from_secs(11))
        .expect_err("prospective time above the limit must fail");
    assert_eq!(prospective.limit, Duration::from_secs(10));
    assert!(prospective.actual > prospective.limit);

    let committed = deadline
        .account(Duration::from_secs(11))
        .expect_err("committed time above the limit must fail");
    assert!(committed.actual > committed.limit);
}

#[test]
fn frame_lengths_fail_closed() {
    let mismatch =
        Frame::try_with_lengths(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, 2, 2, vec![0_u8])
            .expect_err("declared and actual capture lengths must match");
    assert_eq!(
        mismatch,
        FrameError::CapturedLengthMismatch {
            declared: 2,
            actual: 1,
        }
    );

    let truncated = Frame::try_with_lengths(
        SystemTime::UNIX_EPOCH,
        LinkType::ETHERNET,
        2,
        1,
        vec![0_u8, 1],
    )
    .expect_err("original length cannot be smaller than captured length");
    assert_eq!(
        truncated,
        FrameError::OriginalLengthTooSmall {
            captured: 2,
            original: 1,
        }
    );
}

#[test]
fn boundary_error_retains_machine_classification_and_causes() {
    let classification = Classification::new("policy.test", Kind::Policy, Some("stop"));
    let error = BoundaryError::new("denied", classification, vec!["first".to_owned()]);

    assert_eq!(error.to_string(), "denied");
    assert_eq!(error.classification(), classification);
    assert_eq!(error.causes(), ["first"]);
    assert_eq!(Kind::Policy.as_str(), "policy");
}
