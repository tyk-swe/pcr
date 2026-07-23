// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn established_fin_bounds_later_data_and_conflicting_fin() {
    let now = Instant::now();
    let mut reassembler = Reassembler::new(ReassemblyLimits::default());
    reassembler.open_flow(flow(), 100, now).unwrap();
    let mut fin = segment(105, b"x");
    fin.fin = true;
    reassembler.push(fin, now).unwrap();

    assert_eq!(
        reassembler.push(segment(106, b"y"), now).unwrap_err(),
        Error::BeyondFinalSequence { final_offset: 6 }
    );
    let mut conflicting = segment(104, b"");
    conflicting.fin = true;
    assert_eq!(
        reassembler.push(conflicting, now).unwrap_err(),
        Error::ConflictingFinalSequence {
            existing_offset: 6,
            new_offset: 4
        }
    );
}

#[test]
fn stale_fin_before_base_is_ignored_but_exact_and_partially_trimmed_fin_are_kept() {
    let now = Instant::now();
    let mut reassembler = Reassembler::new(ReassemblyLimits::default());
    reassembler.open_flow(flow(), 100, now).unwrap();
    reassembler.push(segment(100, b"abc"), now).unwrap();
    let mut stale = segment(90, b"12345");
    stale.fin = true;
    let events = reassembler.push(stale, now).unwrap();
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::Closed { .. }))
    );
    assert!(
        reassembler
            .push(segment(103, b"d"), now)
            .unwrap()
            .iter()
            .any(|event| matches!(event, Event::Data { sequence: 103, .. }))
    );

    let mut exact = Reassembler::new(ReassemblyLimits::default());
    exact.open_flow(flow(), 100, now).unwrap();
    let mut at_base = segment(90, b"0123456789");
    at_base.fin = true;
    assert!(
        exact
            .push(at_base, now)
            .unwrap()
            .iter()
            .any(|event| matches!(event, Event::Closed { reset: false, .. }))
    );

    let mut partial = Reassembler::new(ReassemblyLimits::default());
    partial.open_flow(flow(), 100, now).unwrap();
    let mut crosses_base = segment(98, b"abcd");
    crosses_base.fin = true;
    let events = partial.push(crosses_base, now).unwrap();
    assert!(events.iter().any(
        |event| matches!(event, Event::Data { sequence: 100, bytes, .. } if bytes.as_ref() == b"cd")
    ));
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::Closed { reset: false, .. }))
    );
}

#[test]
fn a_new_syn_replaces_an_incompatible_tuple_generation() {
    let now = Instant::now();
    let mut reassembler = Reassembler::new(ReassemblyLimits::default());
    let mut original = segment(99, b"old");
    original.syn = true;
    reassembler.push(original.clone(), now).unwrap();

    let retransmission = reassembler.push(original, now).unwrap();
    assert!(retransmission.iter().any(|event| matches!(
        event,
        Event::Retransmission {
            bytes: 3,
            conflicting: false,
            ..
        }
    )));

    let mut replacement = segment(999, b"new");
    replacement.syn = true;
    let events = reassembler.push(replacement, now).unwrap();
    assert!(events.iter().any(
        |event| matches!(event, Event::Data { sequence: 1000, bytes, .. } if bytes.as_ref() == b"new")
    ));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::Retransmission { .. }))
    );
}
