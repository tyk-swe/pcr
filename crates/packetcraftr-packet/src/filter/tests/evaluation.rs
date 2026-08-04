// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    Context, Duration, Error, Filter, Options, Packet, Padding, Raw, UNIX_EPOCH, decoded,
    fixture_registry, matches, sample,
};

#[test]
fn a_bare_protocol_name_tests_layer_presence() {
    let packet = sample();
    assert!(matches("raw", &packet));
    assert!(matches("padding", &packet));

    let mut empty = Packet::new();
    empty.push(Raw::new(Vec::new()));
    let without_padding = decoded(empty, &[]);
    assert!(!matches("padding", &without_padding));
}

#[test]
fn an_occurrence_selects_one_layer_while_a_bare_path_matches_any() {
    let packet = sample();
    // Two raw layers with different bytes; unqualified matches either.
    assert!(matches("raw.bytes == 47:45:54:20", &packet));
    assert!(matches("raw.bytes == 01:02", &packet));
    // Occurrences count outermost first.
    assert!(matches("raw#1.bytes == 47:45:54:20", &packet));
    assert!(!matches("raw#1.bytes == 01:02", &packet));
    assert!(matches("raw#2.bytes == 01:02", &packet));
    assert!(!matches("raw#3.bytes == 01:02", &packet));
}

#[test]
fn a_bare_field_path_tests_whether_a_value_is_present() {
    let with_index = sample();
    assert!(matches("padding.outside_layer", &with_index));

    let mut packet = Packet::new();
    packet.push(Padding::new(vec![0x00]));
    let without_index = decoded(packet, &[0x00]);
    // `Padding::new` leaves the index unset, so the field yields no value.
    assert!(!matches("padding.outside_layer", &without_index));
    assert!(matches("padding.bytes", &without_index));
}

#[test]
fn numbers_compare_with_full_ordering() {
    let packet = sample();
    assert!(matches("padding.outside_layer == 5", &packet));
    assert!(matches("padding.outside_layer != 4", &packet));
    assert!(matches("padding.outside_layer > 4", &packet));
    assert!(matches("padding.outside_layer >= 5", &packet));
    assert!(matches("padding.outside_layer < 6", &packet));
    assert!(matches("padding.outside_layer <= 5", &packet));
    assert!(!matches("padding.outside_layer > 5", &packet));
    // Worded spellings mean exactly the same thing.
    assert!(matches("padding.outside_layer eq 5", &packet));
    assert!(matches("padding.outside_layer ge 5", &packet));
    // Hexadecimal literals are accepted for numbers.
    assert!(matches("padding.outside_layer == 0x05", &packet));
}

#[test]
fn boolean_operators_honour_precedence_and_parentheses() {
    let packet = sample();
    // `&&` binds tighter than `||`, so this is true via the right operand.
    assert!(matches(
        "padding.outside_layer == 99 || padding.outside_layer == 5 && raw",
        &packet
    ));
    // Parenthesising flips which operand decides it.
    assert!(!matches(
        "(padding.outside_layer == 99 || padding.outside_layer == 5) && padding.outside_layer == 1",
        &packet
    ));
    assert!(matches("!padding.outside_layer == 99", &packet));
    assert!(matches("not (padding.outside_layer == 99)", &packet));
    assert!(!matches("!raw", &packet));
    assert!(matches("raw and padding", &packet));
}

#[test]
fn an_unknown_field_fails_compilation_even_inside_a_disjunction() {
    // A typo must be reported rather than short-circuited past, so the whole
    // filter is resolved before any packet is read.
    let error = Filter::compile(
        "raw || nothing_here_at_all",
        &fixture_registry(),
        Options::default(),
    )
    .unwrap_err();
    assert!(matches!(error, Error::UnknownField { .. }));
}

#[test]
fn membership_accepts_a_braced_set() {
    let packet = sample();
    assert!(matches("padding.outside_layer in {4, 5, 6}", &packet));
    assert!(!matches("padding.outside_layer in {4, 6}", &packet));
    assert!(matches("padding.outside_layer in 5", &packet));
}

#[test]
fn contains_searches_byte_fields() {
    let packet = sample();
    assert!(matches("raw.bytes contains 45:54", &packet));
    assert!(!matches("raw.bytes contains 99:98", &packet));
    // Quoted text is compared as its bytes, so `GET` finds the same run.
    assert!(matches("raw.bytes contains \"GET\"", &packet));
}

#[test]
fn byte_slices_read_a_prefix_of_a_field() {
    let packet = sample();
    assert!(matches("raw.bytes[0:2] == 47:45", &packet));
    assert!(!matches("raw.bytes[0:2] == 45:54", &packet));
    assert!(matches("raw.bytes[2:] == 54:20", &packet));
    assert!(matches("raw.bytes[:2] == 47:45", &packet));
    // An out-of-range end clamps to the field rather than failing.
    assert!(matches("raw.bytes[0:99] == 47:45:54:20", &packet));
    // A start past the end yields no value, so nothing matches.
    assert!(!matches("raw.bytes[99:] == 47:45", &packet));
}

#[test]
fn a_bit_binding_masks_and_shifts_the_underlying_field() {
    let packet = sample();
    // `outside_layer` is 5, and the binding keeps its low nibble.
    assert!(matches("pad.layer.low == 5", &packet));
    assert!(!matches("pad.layer.low == 0", &packet));
}

#[test]
fn an_either_binding_matches_when_any_named_field_does() {
    let packet = sample();
    assert!(matches("any.bytes == aa:bb", &packet));
    assert!(matches("any.bytes == 5", &packet));
    assert!(!matches("any.bytes == 9", &packet));
}

#[test]
fn a_registered_spelling_reads_the_same_value_as_the_canonical_path() {
    let packet = sample();
    assert!(matches("pad.tail == aa:bb", &packet));
    assert!(matches("padding.bytes == aa:bb", &packet));
}

#[test]
fn frame_fields_read_the_capture_record_rather_than_any_layer() {
    let packet = sample();
    assert!(matches("frame.number == 7", &packet));
    assert!(matches("frame.len == 8", &packet));
    assert!(matches("frame.cap_len == 8", &packet));
    assert!(matches("frame.interface_id == 3", &packet));
    assert!(matches("frame.link_type == 1", &packet));
    assert!(matches("frame.time_epoch == 1700000000", &packet));
    assert!(matches("frame.time_epoch > 1699999999", &packet));
}

#[test]
fn frame_time_epoch_preserves_pre_epoch_seconds() {
    let mut packet = sample();
    packet.frame.timestamp = UNIX_EPOCH - Duration::from_millis(500);
    assert!(matches("frame.time_epoch == -1", &packet));
    assert!(matches("frame.time_epoch < 0", &packet));
}

#[test]
fn an_absent_interface_id_matches_nothing_rather_than_zero() {
    let mut packet = Packet::new();
    packet.push(Raw::new(vec![0x00]));
    let mut record = decoded(packet, &[0x00]);
    record.frame.interface = None;
    assert!(!matches("frame.interface_id == 0", &record));
    assert!(!matches("frame.interface_id", &record));
}

#[test]
fn a_stream_path_matches_only_when_the_caller_supplies_an_index() {
    let packet = sample();
    let filter = Filter::compile("tcp.stream == 2", &fixture_registry(), Options::default())
        .expect("stream paths compile");
    assert!(filter.requirements().stream_index);

    assert!(!filter.matches(&Context {
        decoded: &packet,
        number: 1,
        tcp_stream: None,
        udp_stream: None,
    }));
    assert!(filter.matches(&Context {
        decoded: &packet,
        number: 1,
        tcp_stream: Some(2),
        udp_stream: None,
    }));
    assert!(!filter.matches(&Context {
        decoded: &packet,
        number: 1,
        tcp_stream: Some(3),
        udp_stream: None,
    }));
    // Each transport reads its own slot: a UDP conversation index can never
    // satisfy a `tcp.stream` comparison, even on a frame that has both.
    assert!(!filter.matches(&Context {
        decoded: &packet,
        number: 1,
        tcp_stream: None,
        udp_stream: Some(2),
    }));
    let udp_filter = Filter::compile("udp.stream == 2", &fixture_registry(), Options::default())
        .expect("stream paths compile");
    assert!(udp_filter.matches(&Context {
        decoded: &packet,
        number: 1,
        tcp_stream: None,
        udp_stream: Some(2),
    }));
    assert!(!udp_filter.matches(&Context {
        decoded: &packet,
        number: 1,
        tcp_stream: Some(2),
        udp_stream: None,
    }));
}

#[test]
fn a_bare_flag_path_reads_the_flag_rather_than_its_presence() {
    // `outside_layer` is 5, so its low nibble is set.
    let set = sample();
    assert!(matches("pad.layer.low", &set));
    assert!(!matches("!pad.layer.low", &set));

    // With the low nibble clear, the same bare path is false even though the
    // underlying field is still present. A presence test would be true here,
    // which is exactly the trap this rule avoids for `!tcp.flags.ack`.
    let mut packet = Packet::new();
    packet.push(Padding::after_layer(vec![0xaa], 0x10));
    let clear = decoded(packet, &[0xaa]);
    assert!(matches("padding.outside_layer", &clear));
    assert!(!matches("pad.layer.low", &clear));
    assert!(matches("!pad.layer.low", &clear));
}
