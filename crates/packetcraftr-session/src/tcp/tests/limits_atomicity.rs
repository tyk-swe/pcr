// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn byte_limit_bounds_buffered_window_not_flow_lifetime() {
    let now = Instant::now();
    let limits = ReassemblyLimits {
        max_bytes_per_flow: 4,
        ..ReassemblyLimits::default()
    };
    let mut reassembler = Reassembler::new(limits);
    reassembler.open_flow(flow(), 100, now).unwrap();

    for (sequence, payload) in [(100, b"abcd"), (104, b"efgh"), (108, b"ijkl")] {
        assert!(
            reassembler
                .push(segment(sequence, payload), now)
                .unwrap()
                .iter()
                .any(|event| matches!(event, Event::Data { .. }))
        );
    }
    assert_eq!(reassembler.aggregate_bytes(), 4);
    assert_eq!(reassembler.aggregate_memory_charge(), 4);
}

#[test]
fn emitted_history_shares_per_flow_and_aggregate_limits_with_pending_data() {
    let now = Instant::now();
    let limits = ReassemblyLimits {
        max_bytes_per_flow: 4,
        ..ReassemblyLimits::default()
    };
    let mut reassembler = Reassembler::new(limits);
    reassembler.open_flow(flow(), 100, now).unwrap();
    reassembler.push(segment(100, b"abcd"), now).unwrap();
    assert_eq!(reassembler.aggregate_bytes(), 4);
    assert_eq!(reassembler.aggregate_memory_charge(), 4);

    reassembler.push(segment(106, b"x"), now).unwrap();
    assert_eq!(reassembler.aggregate_bytes(), 4);
    assert_eq!(reassembler.aggregate_memory_charge(), 68);

    let evicted = reassembler.push(segment(100, b"X"), now).unwrap();
    assert!(evicted.iter().any(|event| matches!(
        event,
        Event::Retransmission {
            conflicting: false,
            ..
        }
    )));
    let retained = reassembler.push(segment(101, b"X"), now).unwrap();
    assert!(retained.iter().any(|event| matches!(
        event,
        Event::Retransmission {
            conflicting: true,
            ..
        }
    )));
}

#[test]
fn pending_data_releases_excess_history_allocation() {
    let now = Instant::now();
    let limits = ReassemblyLimits {
        max_bytes_per_flow: 8,
        max_aggregate_bytes: 72,
        ..ReassemblyLimits::default()
    };
    let mut reassembler = Reassembler::new(limits);
    reassembler.open_flow(flow(), 100, now).unwrap();
    reassembler.push(segment(100, b"abcdefgh"), now).unwrap();

    reassembler.push(segment(109, b"1234567"), now).unwrap();

    let state = reassembler.flows.get(&flow()).unwrap();
    assert_eq!(state.pending_bytes, 7);
    assert_eq!(state.emitted_history.len(), 1);
    assert!(state.emitted_history.capacity() <= 1);
    assert_eq!(reassembler.aggregate_memory_charge(), 72);
}

#[test]
fn aggregate_limit_rejects_emitted_history_atomically() {
    let now = Instant::now();
    let limits = ReassemblyLimits {
        max_bytes_per_flow: 4,
        max_aggregate_bytes: 3,
        ..ReassemblyLimits::default()
    };
    let mut reassembler = Reassembler::new(limits);
    reassembler.open_flow(flow(), 100, now).unwrap();
    assert_eq!(
        reassembler.push(segment(100, b"abcd"), now).unwrap_err(),
        Error::AggregateByteLimit { limit: 3 }
    );
    assert_eq!(reassembler.aggregate_bytes(), 0);
    assert_eq!(reassembler.aggregate_memory_charge(), 0);

    let events = reassembler.push(segment(100, b"abc"), now).unwrap();
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::Data { sequence: 100, .. }))
    );
    assert_eq!(reassembler.aggregate_bytes(), 3);
}

#[test]
fn reset_still_must_pass_prospective_resource_check() {
    let now = Instant::now();
    let limits = ReassemblyLimits {
        max_bytes_per_flow: 4,
        max_aggregate_bytes: 3,
        ..ReassemblyLimits::default()
    };
    let mut reassembler = Reassembler::new(limits);
    reassembler.open_flow(flow(), 100, now).unwrap();
    let mut reset = segment(100, b"abcd");
    reset.rst = true;

    assert_eq!(
        reassembler.push(reset, now).unwrap_err(),
        Error::AggregateByteLimit { limit: 3 }
    );
    assert_eq!(reassembler.aggregate_bytes(), 0);
    assert!(matches!(
        reassembler.flush().as_slice(),
        [Event::Evicted {
            pending_bytes: 0,
            ..
        }]
    ));
}

#[test]
fn rejected_first_segment_does_not_leave_an_empty_flow() {
    let now = Instant::now();
    let limits = ReassemblyLimits {
        max_bytes_per_flow: 4,
        max_aggregate_bytes: 3,
        ..ReassemblyLimits::default()
    };
    let mut reassembler = Reassembler::new(limits);

    assert_eq!(
        reassembler.push(segment(100, b"abcd"), now).unwrap_err(),
        Error::AggregateByteLimit { limit: 3 }
    );
    assert_eq!(reassembler.aggregate_bytes(), 0);
    assert_eq!(reassembler.aggregate_memory_charge(), 0);
    assert!(reassembler.flush().is_empty());
}

#[test]
fn rejected_replacement_syn_restores_the_established_generation() {
    let now = Instant::now();
    let mut reassembler = Reassembler::new(ReassemblyLimits {
        max_bytes_per_flow: 4,
        ..ReassemblyLimits::default()
    });
    reassembler.open_flow(flow(), 100, now).unwrap();
    reassembler
        .push(segment(102, b"cd"), now + Duration::from_millis(1))
        .unwrap();
    let before = {
        let state = &reassembler.flows[&flow()];
        (
            state.base_sequence,
            state.next_offset,
            state.history_start_offset,
            state.emitted_history.clone(),
            state.pending.clone(),
            state.pending_bytes,
            state.fin_offset,
            state.last_update,
            reassembler.aggregate_bytes(),
            reassembler.aggregate_memory_charge(),
        )
    };

    let mut replacement = segment(199, b"abcde");
    replacement.syn = true;
    assert_eq!(
        reassembler
            .push(replacement, now + Duration::from_millis(2))
            .unwrap_err(),
        Error::FlowByteLimit { limit: 4 }
    );
    let after = {
        let state = &reassembler.flows[&flow()];
        (
            state.base_sequence,
            state.next_offset,
            state.history_start_offset,
            state.emitted_history.clone(),
            state.pending.clone(),
            state.pending_bytes,
            state.fin_offset,
            state.last_update,
            reassembler.aggregate_bytes(),
            reassembler.aggregate_memory_charge(),
        )
    };
    assert_eq!(after, before);

    let events = reassembler.push(segment(100, b"ab"), now).unwrap();
    assert!(events.iter().any(
        |event| matches!(event, Event::Data { sequence: 100, bytes, .. } if bytes.as_ref() == b"abcd")
    ));
}

#[test]
fn older_accepted_timestamp_does_not_regress_expiry_state() {
    let start = Instant::now();
    let expiry = Duration::from_millis(10);
    let mut reassembler = Reassembler::new(ReassemblyLimits {
        tcp_idle_expiry: expiry,
        ..ReassemblyLimits::default()
    });
    reassembler.open_flow(flow(), 100, start).unwrap();
    let latest = start + Duration::from_millis(8);
    reassembler.push(segment(102, b"b"), latest).unwrap();

    reassembler
        .push(segment(104, b"d"), start + Duration::from_millis(2))
        .unwrap();

    assert_eq!(reassembler.flows[&flow()].last_update, latest);
    assert!(
        reassembler
            .expire(start + Duration::from_millis(12))
            .is_empty()
    );
    assert!(!reassembler.expire(latest + expiry).is_empty());
}

#[test]
fn pending_segment_limit_is_typed_and_atomic() {
    let now = Instant::now();
    let limits = ReassemblyLimits {
        max_tcp_segments_per_flow: 2,
        ..ReassemblyLimits::default()
    };
    let mut reassembler = Reassembler::new(limits);
    reassembler.open_flow(flow(), 100, now).unwrap();

    reassembler.push(segment(101, b"a"), now).unwrap();
    reassembler.push(segment(103, b"b"), now).unwrap();
    assert_eq!(reassembler.aggregate_bytes(), 2);

    assert_eq!(
        reassembler.push(segment(105, b"c"), now).unwrap_err(),
        Error::SegmentLimit { limit: 2 }
    );
    assert_eq!(reassembler.aggregate_bytes(), 2);

    let flushed = reassembler.flush();
    assert!(matches!(
        flushed.as_slice(),
        [
            Event::Gap { .. },
            Event::Evicted {
                pending_bytes: 2,
                ..
            }
        ]
    ));
}

#[test]
fn in_order_data_at_pending_segment_limit_uses_final_retained_count() {
    let now = Instant::now();
    let limits = ReassemblyLimits {
        max_tcp_segments_per_flow: 2,
        ..ReassemblyLimits::default()
    };
    let mut reassembler = Reassembler::new(limits);
    reassembler.open_flow(flow(), 100, now).unwrap();
    reassembler.push(segment(102, b"b"), now).unwrap();
    reassembler.push(segment(104, b"d"), now).unwrap();

    let events = reassembler.push(segment(100, b"a"), now).unwrap();

    assert!(events.iter().any(
        |event| matches!(event, Event::Data { sequence: 100, bytes, .. } if bytes.as_ref() == b"a")
    ));
    assert_eq!(reassembler.flows[&flow()].pending.len(), 2);
    assert_eq!(
        reassembler.push(segment(106, b"f"), now).unwrap_err(),
        Error::SegmentLimit { limit: 2 }
    );
    assert_eq!(reassembler.flows[&flow()].pending.len(), 2);
}

#[test]
fn aggregate_limit_charges_sparse_segment_metadata() {
    let now = Instant::now();
    let limits = ReassemblyLimits {
        max_aggregate_bytes: 130,
        ..ReassemblyLimits::default()
    };
    let mut reassembler = Reassembler::new(limits);
    reassembler.open_flow(flow(), 100, now).unwrap();
    reassembler.push(segment(101, b"a"), now).unwrap();
    reassembler.push(segment(103, b"b"), now).unwrap();
    assert_eq!(reassembler.aggregate_bytes(), 2);
    assert_eq!(reassembler.aggregate_memory_charge(), 130);
    assert_eq!(
        reassembler.push(segment(105, b"c"), now).unwrap_err(),
        Error::AggregateByteLimit { limit: 130 }
    );
    assert_eq!(reassembler.aggregate_bytes(), 2);
    assert_eq!(reassembler.aggregate_memory_charge(), 130);
}

#[test]
fn serial_half_space_limits_are_rejected_at_public_entry_points() {
    let now = Instant::now();
    let mut invalid = Reassembler::new(ReassemblyLimits {
        max_bytes_per_flow: TCP_SERIAL_HALF_SPACE,
        ..ReassemblyLimits::default()
    });
    assert_eq!(
        invalid.open_flow(flow(), 100, now),
        Err(Error::InvalidWindowLimit {
            limit: TCP_SERIAL_HALF_SPACE
        })
    );
    assert_eq!(
        invalid.push(segment(100, b"a"), now),
        Err(Error::InvalidWindowLimit {
            limit: TCP_SERIAL_HALF_SPACE
        })
    );

    let mut valid = Reassembler::new(ReassemblyLimits {
        max_bytes_per_flow: TCP_SERIAL_HALF_SPACE - 1,
        ..ReassemblyLimits::default()
    });
    valid.open_flow(flow(), 100, now).unwrap();
}

#[test]
fn sparse_aggregate_rejection_precedes_span_sized_scratch_allocation() {
    let now = Instant::now();
    let limits = ReassemblyLimits {
        max_bytes_per_flow: 10_000_001,
        max_aggregate_bytes: PENDING_SEGMENT_METADATA_CHARGE,
        ..ReassemblyLimits::default()
    };
    let mut reassembler = Reassembler::new(limits);
    reassembler.open_flow(flow(), 100, now).unwrap();
    assert_eq!(
        reassembler
            .push(segment(10_000_100, b"x"), now)
            .unwrap_err(),
        Error::AggregateByteLimit {
            limit: PENDING_SEGMENT_METADATA_CHARGE
        }
    );
    assert_eq!(reassembler.aggregate_bytes(), 0);
}
