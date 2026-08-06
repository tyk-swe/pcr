// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::time::{Duration, SystemTime};

use super::super::{
    ResponseCandidate, ResponseSelector, response_within_deadline, select_response_candidate,
};
use super::support::{NoMatchedResponses, decoded_at};
use packetcraftr_packet::decode::Result as DecodedPacket;

#[derive(Clone, Copy)]
struct TestObservation {
    rank: u8,
    key: (u8, u16),
    identity: u8,
}

fn test_candidate<'a>(
    decoded: &'a DecodedPacket,
    rank: u8,
    key: (u8, u16),
    identity: u8,
    latency: Option<Duration>,
) -> ResponseCandidate<'a, TestObservation> {
    ResponseCandidate {
        observation: TestObservation {
            rank,
            key,
            identity,
        },
        decoded,
        latency,
    }
}

fn select_test_candidate<'a>(
    best: &mut Option<ResponseCandidate<'a, TestObservation>>,
    candidate: ResponseCandidate<'a, TestObservation>,
) {
    select_response_candidate(
        best,
        candidate,
        SystemTime::UNIX_EPOCH,
        Duration::from_millis(10),
        |observation| observation.rank,
        |observation| observation.key,
    );
}

#[test]
fn one_unsolicited_frame_can_satisfy_only_one_probe() {
    let response = decoded_at(Duration::from_millis(1), &[1]);
    let mut matched = Vec::<NoMatchedResponses>::new();
    let mut selector = ResponseSelector::new(&mut matched, std::slice::from_ref(&response));

    let first = selector
        .select(
            0,
            SystemTime::UNIX_EPOCH,
            Duration::from_millis(10),
            |_| Some(()),
            |_| 0,
            |_| (),
            || Ok::<(), Infallible>(()),
        )
        .unwrap();
    assert!(first.is_some());
    let second = selector
        .select(
            1,
            SystemTime::UNIX_EPOCH,
            Duration::from_millis(10),
            |_| Some(()),
            |_| 0,
            |_| (),
            || Ok::<(), Infallible>(()),
        )
        .unwrap();
    assert!(second.is_none());
}

#[test]
fn response_selector_rejects_monotonic_and_wall_clock_deadline_violations() {
    let within_wall_clock = decoded_at(Duration::from_millis(1), &[1]);
    let after_wall_clock = decoded_at(Duration::from_millis(11), &[2]);
    let mut best = None;

    select_test_candidate(
        &mut best,
        test_candidate(
            &within_wall_clock,
            1,
            (0, 0),
            1,
            Some(Duration::from_millis(11)),
        ),
    );
    select_test_candidate(
        &mut best,
        test_candidate(&after_wall_clock, 1, (0, 0), 2, None),
    );

    assert!(best.is_none());
}

#[test]
fn response_deadline_accepts_exact_boundary_and_rejects_pre_send_wall_time() {
    assert!(response_within_deadline(
        Some(Duration::from_millis(10)),
        SystemTime::UNIX_EPOCH + Duration::from_millis(99),
        SystemTime::UNIX_EPOCH,
        Duration::from_millis(10),
    ));
    assert!(response_within_deadline(
        None,
        SystemTime::UNIX_EPOCH + Duration::from_millis(10),
        SystemTime::UNIX_EPOCH,
        Duration::from_millis(10),
    ));
    assert!(!response_within_deadline(
        None,
        SystemTime::UNIX_EPOCH,
        SystemTime::UNIX_EPOCH + Duration::from_millis(1),
        Duration::from_millis(10),
    ));
}

#[test]
fn response_selector_prefers_rank_before_all_tie_breakers() {
    let earlier = decoded_at(Duration::from_millis(1), &[1]);
    let later = decoded_at(Duration::from_millis(9), &[9]);
    let mut best = None;
    select_test_candidate(
        &mut best,
        test_candidate(&earlier, 1, (0, 0), 1, Some(Duration::from_millis(1))),
    );
    select_test_candidate(
        &mut best,
        test_candidate(&later, 2, (9, 9), 2, Some(Duration::from_millis(9))),
    );

    assert_eq!(best.unwrap().observation.identity, 2);
}

#[test]
fn response_selector_prefers_earlier_timestamp_after_rank() {
    let later = decoded_at(Duration::from_millis(9), &[1]);
    let earlier = decoded_at(Duration::from_millis(1), &[9]);
    let mut best = None;
    select_test_candidate(&mut best, test_candidate(&later, 1, (0, 0), 1, None));
    select_test_candidate(&mut best, test_candidate(&earlier, 1, (9, 9), 2, None));

    assert_eq!(best.unwrap().observation.identity, 2);
}

#[test]
fn response_selector_accepts_a_generic_ordered_tie_break_key() {
    let first = decoded_at(Duration::from_millis(1), &[1]);
    let second = decoded_at(Duration::from_millis(1), &[9]);
    let mut best = None;
    select_test_candidate(&mut best, test_candidate(&first, 1, (2, 1), 1, None));
    select_test_candidate(&mut best, test_candidate(&second, 1, (1, 9), 2, None));

    assert_eq!(best.unwrap().observation.identity, 2);
}

#[test]
fn response_selector_prefers_lexicographically_smaller_exact_bytes() {
    let larger = decoded_at(Duration::from_millis(1), &[2]);
    let smaller = decoded_at(Duration::from_millis(1), &[1]);
    let mut best = None;
    select_test_candidate(&mut best, test_candidate(&larger, 1, (0, 0), 1, None));
    select_test_candidate(&mut best, test_candidate(&smaller, 1, (0, 0), 2, None));

    assert_eq!(best.unwrap().observation.identity, 2);
}

#[test]
fn response_selector_prefers_shorter_known_latency_last() {
    let response = decoded_at(Duration::from_millis(1), &[1]);
    let mut best = None;
    select_test_candidate(
        &mut best,
        test_candidate(&response, 1, (0, 0), 1, Some(Duration::from_millis(5))),
    );
    select_test_candidate(
        &mut best,
        test_candidate(&response, 1, (0, 0), 2, Some(Duration::from_millis(2))),
    );

    assert_eq!(best.unwrap().observation.identity, 2);
}

#[test]
fn response_selector_is_stable_when_candidates_are_fully_tied() {
    let response = decoded_at(Duration::from_millis(1), &[1]);
    let mut best = None;
    select_test_candidate(&mut best, test_candidate(&response, 1, (0, 0), 1, None));
    select_test_candidate(&mut best, test_candidate(&response, 1, (0, 0), 2, None));

    assert_eq!(best.unwrap().observation.identity, 1);
}
