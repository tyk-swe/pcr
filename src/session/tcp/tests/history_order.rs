// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn emitted_history_wraparound_preserves_byte_order() {
    let mut state = TcpFlowState::new(100, Instant::now());
    state.emitted_history.reserve_exact(4);
    let capacity = state.emitted_history.capacity();
    let initial = (0..capacity).map(|value| value as u8).collect::<Vec<_>>();

    append_emitted_history(&mut state, 0, &initial, capacity);
    append_emitted_history(&mut state, capacity as u64, &[0xfe, 0xff], capacity);

    let mut expected = initial[2..].to_vec();
    expected.extend_from_slice(&[0xfe, 0xff]);
    assert_eq!(emitted_bytes(&state), expected);
    assert_eq!(state.history_start_offset, 2);
    assert!(!state.emitted_history.as_slices().1.is_empty());
}

#[test]
fn emitted_history_trimming_discards_the_oldest_bytes() {
    let mut state = TcpFlowState::new(100, Instant::now());
    append_emitted_history(&mut state, 0, b"abcdef", 6);

    trim_emitted_history(&mut state, 3);

    assert_eq!(state.history_start_offset, 3);
    assert_eq!(emitted_bytes(&state), b"def");
}

#[test]
fn emitted_history_conflict_detection_crosses_wraparound() {
    let mut state = TcpFlowState::new(100, Instant::now());
    state.emitted_history.reserve_exact(4);
    let capacity = state.emitted_history.capacity();
    let initial = vec![b'a'; capacity];
    append_emitted_history(&mut state, 0, &initial, capacity);
    append_emitted_history(&mut state, capacity as u64, b"bc", capacity);
    assert!(!state.emitted_history.as_slices().1.is_empty());
    let retained = emitted_bytes(&state);

    assert!(!emitted_history_conflicts(
        &state,
        state.history_start_offset,
        &retained
    ));
    let mut conflicting = retained;
    conflicting[capacity - 2] = b'x';
    assert!(emitted_history_conflicts(
        &state,
        state.history_start_offset,
        &conflicting
    ));
}

#[test]
fn emitted_history_zero_capacity_retains_no_bytes() {
    let mut state = TcpFlowState::new(100, Instant::now());
    append_emitted_history(&mut state, 0, b"abc", 3);

    trim_emitted_history(&mut state, 0);
    assert!(state.emitted_history.is_empty());
    assert_eq!(state.history_start_offset, 3);

    append_emitted_history(&mut state, 3, b"de", 0);

    assert!(state.emitted_history.is_empty());
    assert_eq!(state.history_start_offset, 5);
    assert!(!emitted_history_conflicts(&state, 3, b"XX"));
}

#[test]
fn out_of_order_segments_emit_in_sequence() {
    let now = Instant::now();
    let mut reassembler = Reassembler::new(ReassemblyLimits::default());
    reassembler.open_flow(flow(), 100, now).unwrap();
    assert!(
        reassembler
            .push(segment(103, b"def"), now)
            .unwrap()
            .is_empty()
    );
    let events = reassembler.push(segment(100, b"abc"), now).unwrap();
    let data = events
        .into_iter()
        .filter_map(|event| match event {
            Event::Data { bytes, .. } => Some(bytes),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(data, [Bytes::from_static(b"abcdef")]);
}

#[test]
fn in_order_data_emits_the_input_bytes_without_pending_storage() {
    let now = Instant::now();
    let mut reassembler = Reassembler::new(ReassemblyLimits::default());
    reassembler.open_flow(flow(), 100, now).unwrap();
    let payload = Bytes::from_static(b"abc");
    let pointer = payload.as_ptr();

    let events = reassembler
        .push(
            Segment {
                flow: flow(),
                sequence: 100,
                payload,
                syn: false,
                fin: false,
                rst: false,
            },
            now,
        )
        .unwrap();

    let output = events
        .into_iter()
        .find_map(|event| match event {
            Event::Data { bytes, .. } => Some(bytes),
            _ => None,
        })
        .unwrap();
    assert_eq!(output.as_ref(), b"abc");
    assert_eq!(output.as_ptr(), pointer);
    assert!(reassembler.flows[&flow()].pending.is_empty());
}

#[test]
fn ack_only_segment_leaves_pending_data_intact() {
    let now = Instant::now();
    let mut reassembler = Reassembler::new(ReassemblyLimits::default());
    reassembler.open_flow(flow(), 100, now).unwrap();
    reassembler.push(segment(103, b"def"), now).unwrap();

    assert!(reassembler.push(segment(100, b""), now).unwrap().is_empty());
    let events = reassembler.push(segment(100, b"abc"), now).unwrap();
    assert!(events.iter().any(
        |event| matches!(event, Event::Data { sequence: 100, bytes, .. } if bytes.as_ref() == b"abcdef")
    ));
}

#[test]
fn retransmission_is_reported_without_duplicate_data() {
    let now = Instant::now();
    let mut reassembler = Reassembler::new(ReassemblyLimits::default());
    reassembler.open_flow(flow(), 100, now).unwrap();
    reassembler.push(segment(100, b"abc"), now).unwrap();
    let events = reassembler.push(segment(101, b"bc"), now).unwrap();
    assert!(events.iter().any(|event| matches!(
        event,
        Event::Retransmission {
            bytes: 2,
            conflicting: false,
            ..
        }
    )));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::Data { .. }))
    );
}

#[test]
fn fully_covered_pending_retransmission_keeps_the_retained_segment() {
    let now = Instant::now();
    let mut reassembler = Reassembler::new(ReassemblyLimits::default());
    reassembler.open_flow(flow(), 100, now).unwrap();
    reassembler.push(segment(102, b"abc"), now).unwrap();
    let pointer = reassembler.flows[&flow()].pending[&2].as_ptr();

    let events = reassembler.push(segment(102, b"abc"), now).unwrap();

    assert!(events.iter().any(|event| matches!(
        event,
        Event::Retransmission {
            bytes: 3,
            conflicting: false,
            ..
        }
    )));
    assert_eq!(reassembler.flows[&flow()].pending[&2].as_ptr(), pointer);
}

#[test]
fn contradictory_retransmission_of_emitted_bytes_is_reported() {
    let now = Instant::now();
    let mut reassembler = Reassembler::new(ReassemblyLimits::default());
    reassembler.open_flow(flow(), 100, now).unwrap();
    reassembler.push(segment(100, b"abcdef"), now).unwrap();

    let events = reassembler.push(segment(102, b"cX"), now).unwrap();
    assert!(events.iter().any(|event| matches!(
        event,
        Event::Retransmission {
            sequence: 102,
            bytes: 2,
            conflicting: true,
            ..
        }
    )));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::Data { .. }))
    );
}

#[test]
fn sequence_numbers_unwrap_across_u32_boundary() {
    let now = Instant::now();
    let mut reassembler = Reassembler::new(ReassemblyLimits::default());
    reassembler.open_flow(flow(), u32::MAX - 1, now).unwrap();
    reassembler.push(segment(u32::MAX - 1, b"ab"), now).unwrap();
    let events = reassembler.push(segment(0, b"cd"), now).unwrap();
    assert!(events.iter().any(
        |event| matches!(event, Event::Data { sequence: 0, bytes, .. } if bytes.as_ref() == b"cd")
    ));

    let events = reassembler.push(segment(u32::MAX, b"bX"), now).unwrap();
    assert!(events.iter().any(|event| matches!(
        event,
        Event::Retransmission {
            sequence: u32::MAX,
            bytes: 2,
            conflicting: true,
            ..
        }
    )));
}

#[test]
fn data_before_capture_base_is_old_not_a_four_gibibyte_gap() {
    let now = Instant::now();
    let mut reassembler = Reassembler::new(ReassemblyLimits::default());
    reassembler.open_flow(flow(), 100, now).unwrap();
    reassembler.push(segment(100, b"abc"), now).unwrap();
    let events = reassembler.push(segment(99, b"z"), now).unwrap();
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::Retransmission { bytes: 1, .. }))
    );
}
