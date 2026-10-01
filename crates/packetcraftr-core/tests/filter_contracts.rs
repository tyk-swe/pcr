// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::decoded::{context, decoded, ipv6_tcp, protocols, tunnelled};
use common::packets::{build, dissect};
use common::registry;
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr_core::decode;
use packetcraftr_core::field::FieldValue;
use packetcraftr_core::filter::{Context, DerivedPacket, Error, Filter, Limits, Projection};
use packetcraftr_core::frame::{Direction, Frame, LinkType};
use packetcraftr_core::layer::{Layer, Raw};
use packetcraftr_core::layout::PacketLayout;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::{Tcp, Udp};
use packetcraftr_core::protocol::tunnel::Gre;

fn assert_filters(decoded: &decode::DecodedPacket, cases: &[(&str, bool)]) {
    let registry = registry();
    for (source, expected) in cases {
        let filter = Filter::compile(source, &registry, Limits::default())
            .unwrap_or_else(|error| panic!("{source} must compile: {error}"));
        let matched = filter
            .matches(&context(decoded))
            .unwrap_or_else(|error| panic!("{source} must evaluate: {error}"));
        assert_eq!(matched, *expected, "{source}");
    }
}

fn assert_rejected(cases: &[(&str, &str)]) {
    let registry = registry();
    for (source, expected) in cases {
        let error = match Filter::compile(source, &registry, Limits::default()) {
            Ok(_) => panic!("{source} must not compile"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains(expected),
            "{source}: {error} does not mention {expected}"
        );
    }
}

#[test]
fn numeric_comparisons_order_values_and_cross_the_signed_boundary() {
    assert_filters(
        &tunnelled(),
        &[
            ("udp.dstport == 9999", true),
            ("udp.dstport != 9999", true),
            ("udp.srcport > 12345", true),
            ("udp.srcport >= 40000", true),
            ("udp.srcport < 12346", true),
            ("udp.srcport <= 12345", true),
            ("udp.dstport > 65535", false),
            ("udp.dstport < 0", false),
            ("udp.dstport > -1", true),
            ("udp.dstport == -1", false),
            ("vxlan.vni == 74565", true),
            ("vxlan.vni == 0x12345", true),
        ],
    );
}

#[test]
fn address_comparisons_test_equality_and_prefix_membership() {
    assert_filters(
        &tunnelled(),
        &[
            ("ip.src == 192.0.2.1", true),
            ("ip.src in 192.0.2.0/24", true),
            ("ip.src in 198.51.100.0/24", false),
            ("ip.src in 0.0.0.0/0", true),
            // A prefix describes a set, so `!=` asks for exclusion from it.
            ("ip.src != 192.0.2.0/24", true),
            ("ip.addr in {10.0.0.2, 203.0.113.9}", true),
            ("ip.addr in {203.0.113.9}", false),
        ],
    );
    assert_filters(
        &ipv6_tcp(),
        &[
            ("ipv6.src == 2001:db8::1", true),
            ("ipv6.src in 2001:db8::/32", true),
            ("ipv6.src in 2001:db8:1::/48", false),
            ("ipv6.dst in 2001:db8:1::/48", true),
            ("ipv6.addr in 2001:db8::/32", true),
        ],
    );
}

#[test]
fn byte_and_mac_comparisons_accept_every_spelling_of_a_byte_run() {
    assert_filters(
        &tunnelled(),
        &[
            ("eth.src == 06:07:08:09:0a:0b", true),
            ("eth.addr == 00:01:02:03:04:05", true),
            ("eth.addr == 0a:0b:0c:0d:0e:0f", true),
            ("eth.src == 06:07:08:09:0a:0c", false),
            ("raw.bytes == \"GET /index HTTP/1.1\"", true),
            ("raw.bytes > \"GET\"", true),
            ("ethernet.source[0:2] == 06:07", true),
            ("ethernet.source[1] == 7", true),
            ("ethernet.source[1] == 8", false),
            ("ipv4.source[0:2] == c0:00", true),
            // Eight groups read as bytes, not as an uncompressed IPv6 address.
            ("raw.bytes[0:8] == 47:45:54:20:2f:69:6e:64", true),
        ],
    );
    assert_filters(
        &ipv6_tcp(),
        &[("ipv6.src[0:8] == 20:01:0d:b8:00:00:00:00", true)],
    );
}

#[test]
fn slices_past_the_last_byte_select_no_value() {
    assert_filters(
        &tunnelled(),
        &[
            ("ethernet.source[5]", true),
            ("ethernet.source[6]", false),
            ("ethernet.source[6:8]", false),
            ("ethernet.source[7:]", false),
            ("ethernet.source[4:9] == 0a:0b", true),
            ("ethernet.source[6:] == \"\"", true),
        ],
    );
}

#[test]
fn contains_searches_byte_text_and_mac_haystacks() {
    assert_filters(
        &tunnelled(),
        &[
            ("raw.bytes contains \"index\"", true),
            ("raw.bytes contains \"INDEX\"", false),
            ("raw.bytes contains 47:45:54", true),
            ("raw.bytes contains 47:45:55", false),
            ("raw.bytes contains 47:45:54:20:2f:69:6e:64", true),
            ("raw.bytes contains \"\"", true),
            ("eth.src contains 07:08", true),
            ("eth.src contains 08:07", false),
        ],
    );
}

#[test]
fn unquoted_hex_words_on_byte_fields_are_compile_errors_not_ascii_needles() {
    let registry = registry();
    for source in [
        "raw.bytes contains 160301ff",
        "raw.bytes contains deadbeef",
        "raw.bytes contains DEADBEEF",
        "raw.bytes == ff",
        "raw.bytes > deadbeef",
        "raw.bytes in {47:45:54, deadbeef}",
        "ethernet.source[0:2] == c000",
        "ethernet.source[1] == ff",
        "eth.src contains deadbeef",
        "eth.src == c0ffee",
        "raw.bytes contains 47:45:5",
        "raw.bytes contains 47:45:",
        "raw.bytes == aa:bb-cc",
        "ethernet.source[0:2] == c0:0",
        "eth.src contains c0:0",
    ] {
        let error = Filter::compile(source, &registry, Limits::default())
            .expect_err("an unquoted hex-looking word on a byte field must not compile");
        assert!(
            matches!(error, Error::UnquotedByteWord { .. }),
            "{source}: {error}"
        );
    }
}

#[test]
fn unquoted_byte_word_errors_name_the_word_instead_of_a_type_mismatch() {
    let registry = registry();
    for (source, word) in [
        ("raw.bytes contains deadbeef", "deadbeef"),
        ("raw.bytes contains 47:45:5", "47:45:5"),
        ("ethernet.source[0:2] == c0:0", "c0:0"),
    ] {
        let message = Filter::compile(source, &registry, Limits::default())
            .expect_err("an unquoted hex-looking word on a byte field must not compile")
            .to_string();
        assert!(message.contains(word), "{source}: {message}");
        assert!(
            !message.contains("cannot be compared"),
            "{source}: {message}"
        );
    }
}

#[test]
fn byte_fields_still_take_separated_bytes_quoted_text_and_non_hex_words() {
    assert_filters(
        &tunnelled(),
        &[
            ("raw.bytes contains 47:45:54", true),
            ("raw.bytes contains 47-45-54", true),
            ("raw.bytes contains \"160301ff\"", false),
            ("raw.bytes contains \"GET\"", true),
            ("raw.bytes contains GET", true),
            ("raw.bytes contains HTTP", true),
            ("raw.bytes contains 2026-09-29", false),
            ("raw.bytes == GET", false),
            ("raw.bytes in {GET, 47:45:54}", false),
            ("ethernet.source[0:2] == 06:07", true),
            ("ethernet.source[0:2] == \"c000\"", false),
            ("ethernet.source[1] == 0x07", true),
            ("eth.src contains 07:08", true),
        ],
    );
}

#[test]
fn text_fields_keep_taking_hex_looking_words() {
    let registry = registry();
    for source in ["tls.sni == deadbeef", "tls.sni contains cafe"] {
        Filter::compile(source, &registry, Limits::default())
            .unwrap_or_else(|error| panic!("{source} must compile: {error}"));
    }
}

#[test]
fn layer_occurrences_select_one_layer_of_a_tunnelled_stack() {
    assert_filters(
        &tunnelled(),
        &[
            ("ipv4#1.source == 192.0.2.1", true),
            ("ipv4#2.source == 10.0.0.1", true),
            ("ipv4#1.source == 10.0.0.1", false),
            ("ipv4#2.source == 192.0.2.1", false),
            ("ipv4.source == 10.0.0.1", true),
            ("ip.src == 192.0.2.1", true),
            ("udp#1.dstport == 4789", true),
            ("udp#2.dstport == 9999", true),
            ("ipv4#3", false),
            ("ethernet#2", true),
            ("ipv4#2", true),
        ],
    );
}

#[test]
fn occurrence_selectors_reject_every_malformed_spelling() {
    assert_rejected(&[
        ("ipv4.source#2 == 192.0.2.1", "must follow the protocol"),
        ("ipv4#x.source == 192.0.2.1", "is not a number"),
        ("ipv4#0.source == 192.0.2.1", "occurrences start at 1"),
        ("ipv4#-0.source == 192.0.2.1", "is not a number"),
        ("ipv4#-2.source == 192.0.2.1", "is not a number"),
        ("ipv4#LAST.source == 192.0.2.1", "is not a number"),
        ("ipv4#.source == 192.0.2.1", "is not a number"),
        ("ipv4#0", "occurrences start at 1"),
        ("ipv4#-2", "is not a number"),
        ("ipv4#LAST", "is not a number"),
        ("ipv4.source#last == 192.0.2.1", "must follow the protocol"),
        ("frame#last.len > 0", "not a protocol layer"),
        ("udp#-1.stream == 2", "not a protocol layer"),
        ("frame#1.len > 0", "not a protocol layer"),
        ("tcp#1.stream == 2", "not a protocol layer"),
    ]);
}

#[test]
fn flag_paths_read_the_bit_and_bare_field_paths_read_presence() {
    assert_filters(
        &ipv6_tcp(),
        &[
            ("tcp.flags.syn", true),
            ("tcp.flags.ack", true),
            ("tcp.flags.fin", false),
            ("!tcp.flags.fin", true),
            ("tcp.flags.syn == 1", true),
            ("tcp.flags.fin == 0", true),
            ("tcp.options", true),
            ("raw.bytes", true),
            ("udp.dstport", false),
        ],
    );
}

#[test]
fn frame_and_stream_facts_are_reserved_and_read_from_the_caller() {
    let decoded = tunnelled();
    assert_filters(
        &decoded,
        &[
            ("frame.number == 7", true),
            ("frame.time_epoch == 123", true),
            ("frame.interface_id == 4", true),
            ("frame.interface_id == 5", false),
            ("frame.link_type == 1", true),
            ("frame.len > 0", true),
            ("frame.cap_len > 0", true),
            ("tcp.stream == 2", true),
            ("udp.stream == 3", true),
            ("udp.stream == 2", false),
        ],
    );
    assert_filters(
        &decoded,
        &[
            ("Frame.number == 7", true),
            ("FRAME.len > 0", true),
            ("TCP.stream == 2", true),
            ("Udp.stream == 3", true),
            ("UDP.stream == 2", false),
        ],
    );

    let udp_only = Filter::compile("udp.stream == 3", &registry(), Limits::default())
        .expect("stream filter compiles");
    let requirements = udp_only.requirements();
    assert!(requirements.stream_index);
    assert!(requirements.udp_stream);
    assert!(!requirements.tcp_stream);

    let filter = Filter::compile("frame.time_epoch >= 0", &registry(), Limits::default())
        .expect("timestamp filter compiles");
    assert!(filter.requirements().timestamp);
    assert!(!filter.requirements().stream_index);
    let mut undated = decoded;
    undated.frame.timestamp = None;
    assert!(matches!(
        filter.matches(&context(&undated)),
        Err(Error::TimestampUnavailable)
    ));
}

#[test]
fn time_epoch_floors_instants_before_the_epoch() {
    let mut decoded = tunnelled();
    decoded.frame.timestamp = Some(UNIX_EPOCH - Duration::new(1, 500_000_000));
    assert_filters(
        &decoded,
        &[
            ("frame.time_epoch == -2", true),
            ("frame.time_epoch == -1", false),
            ("frame.time_epoch < 0", true),
        ],
    );
}

#[test]
fn impossible_paths_slices_and_literals_are_compile_errors() {
    assert_rejected(&[
        ("ipv4.unknown == 1", "unknown"),
        ("nosuchproto", "unknown"),
        ("dns.answers[0].bogus == 1", "unknown"),
        ("dns.answers[0].nme == \"x\"", "unknown"),
        ("ipv4.source == 7", "cannot be compared"),
        ("ipv4.source > 192.0.2.0/24", "prefix"),
        ("tcp.srcport contains \"x\"", "cannot be compared"),
        ("udp.dstport[0] == 1", "cannot be sliced"),
        ("frame.len[0] == 1", "cannot be sliced"),
        ("ethernet.source[3:1] == 00", "precedes start"),
    ]);
}

#[test]
fn syntax_errors_name_the_pasted_character_not_its_first_byte() {
    assert_rejected(&[
        (
            "tls.sni == \u{201c}example\u{201d}",
            "unexpected character `\u{201c}`",
        ),
        ("tls.sni == \"a\\\u{e9}\"", "unsupported escape `\\\u{e9}`"),
    ]);
}

#[test]
fn either_endpoint_inequality_matches_even_when_the_other_endpoint_is_equal() {
    assert_filters(
        &ipv6_tcp(),
        &[
            ("tcp.port == 443", true),
            ("tcp.port != 443", true),
            ("tcp.dstport != 443", false),
            ("!(tcp.port == 443)", false),
        ],
    );
    assert_filters(
        &tunnelled(),
        &[
            ("udp.port == 4789", true),
            ("udp.port != 4789", true),
            ("!(udp.port == 4789)", false),
        ],
    );
}

fn recipe(source: &str) -> decode::DecodedPacket {
    dissect(build(source).bytes)
}

fn payload(bytes: &[u8]) -> decode::DecodedPacket {
    let mut packet = Packet::new();
    packet.push(Ethernet::default());
    packet.push(Ipv4 {
        source: "192.0.2.1".parse().expect("source"),
        destination: "198.51.100.2".parse().expect("destination"),
        ..Ipv4::default()
    });
    packet.push(Udp {
        source_port: 12_345,
        destination_port: 9_999,
        ..Udp::default()
    });
    packet.push(Raw::new(bytes.to_vec()));
    decoded(packet)
}

fn syntax_offset(source: &str) -> usize {
    match Filter::compile(source, &registry(), Limits::default()) {
        Err(Error::Syntax { offset, .. }) => offset,
        other => panic!("{source}: expected a syntax error, got {other:?}"),
    }
}

#[test]
fn quoted_escapes_and_byte_strings_match_exact_payload_bytes() {
    let http = payload(b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody");
    assert_filters(
        &http,
        &[
            ("raw.bytes contains \"\\r\\n\\r\\n\"", true),
            ("raw.bytes contains \"\\n\\n\"", false),
            ("raw.bytes contains \"GET\\x20/\"", true),
            ("raw.bytes contains \"GET\\x2f\"", false),
            ("raw.bytes contains \"\\tbody\"", false),
            ("raw.bytes contains \"\\0\"", false),
            ("raw.bytes startswith \"GET\\x20\"", true),
        ],
    );
    let binary = payload(&[0x16, 0x03, 0x01, 0xff, 0x00, 0x41]);
    assert_filters(
        &binary,
        &[
            ("raw.bytes contains b\"\\x16\\x03\\x01\"", true),
            ("raw.bytes contains b\"\\x16\\x03\\x02\"", false),
            ("raw.bytes contains b\"\\xff\"", true),
            ("raw.bytes contains b\"\\xfe\"", false),
            ("raw.bytes contains b\"\\xff\\0A\"", true),
            ("raw.bytes == b\"\\x16\\x03\\x01\\xff\\x00A\"", true),
            ("raw.bytes != b\"\\x16\\x03\\x01\\xff\\x00A\"", false),
            ("raw.bytes[0:3] == b\"\\x16\\x03\\x01\"", true),
            ("raw.bytes[3:4] == b\"\\xff\"", true),
            ("raw.bytes[3:4] in {b\"\\x00\", b\"\\xff\"}", true),
            ("raw.bytes[3:4] in {b\"\\x00\", b\"\\xfe\"}", false),
            ("raw.bytes contains b\"\"", true),
            ("raw.bytes contains b\"A\"", true),
        ],
    );
}

#[test]
fn escapes_keep_plain_text_ascii_and_report_the_escape_offset() {
    let registry = registry();
    let error = Filter::compile("raw.bytes contains \"\\xc3\"", &registry, Limits::default())
        .expect_err("a non-ASCII escape in plain text must not compile");
    assert!(
        matches!(&error, Error::Syntax { offset: 20, message } if message.contains("not ASCII")),
        "{error}"
    );
    assert_eq!(syntax_offset("raw.bytes contains b\"\\x1"), 21);
    assert_eq!(syntax_offset("raw.bytes contains b\"\\xZZ\""), 21);
    assert_eq!(syntax_offset("raw.bytes contains b\"ab\\q\""), 23);
    assert_eq!(syntax_offset("raw.bytes contains b\"ab\\"), 23);
    assert_eq!(syntax_offset("raw.bytes contains \"\\x4\""), 20);
    assert_eq!(syntax_offset("raw.bytes contains b\"abc"), 19);
    assert_rejected(&[
        ("raw.bytes contains \"\\q\"", "unsupported escape `\\q`"),
        ("raw.bytes contains \"ab\\", "trailing escape"),
    ]);
}

#[test]
fn a_lone_b_before_a_quote_is_the_only_byte_string_spelling() {
    assert_rejected(&[
        ("b", "unknown display filter field b"),
        ("b == 1", "unknown display filter field b"),
        ("ab\"x\"", "unknown display filter field ab"),
    ]);
    assert_filters(
        &payload(b"b"),
        &[
            ("raw.bytes == \"b\"", true),
            ("raw.bytes == b\"b\"", true),
            ("raw.bytes == b", true),
            ("raw.bytes contains b", true),
        ],
    );
}

#[test]
fn len_and_count_are_functions_only_when_the_parenthesis_follows_directly() {
    assert_rejected(&[
        ("len (raw.bytes) > 1400", "unknown display filter field len"),
        (
            "count (tcp.options) > 4",
            "unknown display filter field count",
        ),
        ("LEN\t(raw.bytes) > 1", "unknown display filter field LEN"),
    ]);
    assert!(measured("len(raw.bytes) > 1400", &payload(&[0; 1500])));
}

fn tcp_with(flags: &str, dsfield: u8) -> decode::DecodedPacket {
    recipe(&format!(
        "ipv4(source=192.0.2.1,destination=192.0.2.2,dscp_ecn={dsfield})/tcp(source_port=44000,destination_port=443,flags={flags})"
    ))
}

#[test]
fn bitmasks_test_flag_bits_and_header_fields() {
    let syn_ack = tcp_with("0x12", 184);
    let ack = tcp_with("0x10", 0);
    assert_filters(
        &syn_ack,
        &[
            ("tcp.flags & 0x12 == 0x12", true),
            ("tcp.flags & 0x12 == 0x10", false),
            ("tcp.flags & 0x12 != 0x12", false),
            ("tcp.flags & 0x02", true),
            ("tcp.flags & 0x01", false),
            ("tcp.flags & 18 == 18", true),
            ("tcp.flags & 0x12 >= 0x12", true),
            ("tcp.flags & 0x12 > 0x12", false),
            ("tcp.flags & 0x12 < 0x13", true),
            ("ip.dsfield & 0xfc == 184", true),
            ("ip.dsfield & 0x03 != 0", false),
            ("ip.dsfield & 0x03 == 0", true),
            ("ip.dsfield & 0xfc > 100", true),
            ("tcp.flags.syn & 1", true),
            ("tcp.flags.fin & 1", false),
            ("frame.len & 0xffff != 0", true),
            ("udp.srcport & 1", false),
            ("udp.srcport & 1 == 0", false),
            ("tcp.flags & 0x12 == 0x12 && ip.dsfield & 0xfc == 184", true),
            (
                "tcp.flags & 0x12 == 0x12 && !(ip.dsfield & 0xfc == 184)",
                false,
            ),
            ("tcp.flags & 0x01 || tcp.flags & 0x02", true),
        ],
    );
    assert_filters(
        &ack,
        &[
            ("tcp.flags & 0x12 == 0x12", false),
            ("tcp.flags & 0x12 == 0x10", true),
            ("tcp.flags & 0x02", false),
            ("ip.dsfield & 0xfc == 184", false),
        ],
    );
}

#[test]
fn masks_apply_to_either_endpoint_and_nothing_else() {
    assert_filters(
        &tcp_with("0x02", 0),
        &[
            // 44000 is even and 443 is odd, so either parity has a witness.
            ("tcp.port & 1 == 1", true),
            ("tcp.port & 1 == 0", true),
            ("tcp.port & 0x8000 == 0x8000", true),
            ("tcp.port & 0x8000 == 0x0001", false),
            ("tcp.srcport & 0xff00 == 0xab00", true),
        ],
    );
}

#[test]
fn the_bare_mask_form_matches_the_dhcp_broadcast_flag_only() {
    let broadcast = recipe(
        "ipv4(source=0.0.0.0,destination=255.255.255.255)/udp(source_port=68,destination_port=67)/dhcpv4(flags=0x8000)",
    );
    let unicast = recipe(
        "ipv4(source=0.0.0.0,destination=255.255.255.255)/udp(source_port=68,destination_port=67)/dhcpv4(flags=0)",
    );
    assert_filters(
        &broadcast,
        &[
            ("dhcpv4.flags & 0x8000", true),
            ("dhcpv4.flags & 0x8000 == 0x8000", true),
            ("dhcpv4.flags & 0x7fff", false),
        ],
    );
    assert_filters(
        &unicast,
        &[
            ("dhcpv4.flags & 0x8000", false),
            ("dhcpv4.flags & 0x8000 == 0", true),
        ],
    );
}

#[test]
fn bad_masks_fail_at_compile_time_naming_the_field_and_offset() {
    let registry = registry();
    let cases: [(&str, &str, usize); 10] = [
        ("dns.qname & 1", "dns.qname", 10),
        ("ip.src & 0xff", "ip.src", 7),
        ("tcp.flags.syn == 1 && eth.src & 1", "eth.src", 30),
        ("frame.time_epoch & 1", "frame.time_epoch", 17),
        ("tcp.flags &", "tcp.flags", 10),
        ("tcp.flags & abc", "tcp.flags", 12),
        ("tcp.flags & \"1\"", "tcp.flags", 12),
        ("tcp.flags & -1", "tcp.flags", 12),
        ("tcp.flags & 0x12 == abc", "tcp.flags", 20),
        ("tcp.flags & 0x12 == 1..5", "tcp.flags", 20),
    ];
    for (source, path, offset) in cases {
        let error = Filter::compile(source, &registry, Limits::default())
            .expect_err("a malformed mask must not compile");
        match error {
            Error::MaskedField {
                offset: actual_offset,
                path: actual_path,
                ..
            }
            | Error::MaskOperand {
                offset: actual_offset,
                path: actual_path,
                ..
            } => {
                assert_eq!(actual_path, path, "{source}");
                assert_eq!(actual_offset, offset, "{source}");
            }
            other => panic!("{source}: unexpected error {other}"),
        }
    }
    assert_rejected(&[
        ("tcp & 1", "names a layer"),
        ("tcp.flags & 0x12 in 0x12", "expected `&&`"),
        ("tcp.flags & 0x12 == ", "needs an unsigned number"),
    ]);
}

#[test]
fn and_still_tokenises_and_a_lone_pipe_is_still_an_error() {
    assert_filters(
        &tcp_with("0x12", 0),
        &[("tcp&&ip", true), ("tcp && !ip", false)],
    );
    assert_rejected(&[("tcp | ip", "expected `||`")]);
}

#[test]
fn numeric_ranges_are_inclusive_on_both_ends() {
    let decoded = tunnelled();
    assert_filters(
        &decoded,
        &[
            ("udp.dstport in 9999..9999", true),
            ("udp.dstport in 9999..10000", true),
            ("udp.dstport in 9998..9998", false),
            ("udp.dstport in 10000..20000", false),
            ("udp.srcport in 40000..65535", true),
            ("udp.srcport in 40001..65535", false),
            ("udp.port in 1024..65535", true),
            ("udp.port in 0x2000..0x2100", false),
            ("frame.number in 7..7", true),
            ("frame.number in 1..6", false),
            ("frame.number in 8..9", false),
            ("udp.dstport in {53, 5353, 9990..9999}", true),
            ("udp.dstport in {53, 5353, 49152..65535}", false),
            ("udp.dstport in {9999..9999}", true),
            ("udp.dstport == 9000..10000", true),
            ("udp.dstport == 80..90", false),
            ("vxlan.vni in 74565..74565", true),
        ],
    );
    assert_filters(
        &ipv6_tcp(),
        &[
            ("tcp.dstport == 400..500", true),
            ("tcp.dstport != 400..500", false),
            ("tcp.dstport != 80..90", true),
            ("tcp.dstport == 80..90", false),
            ("tcp.port in 1024..65535", true),
        ],
    );
}

#[test]
fn address_ranges_are_inclusive_and_family_checked() {
    assert_filters(
        &tunnelled(),
        &[
            ("ip.src in 192.0.2.1..192.0.2.1", true),
            ("ip.src in 192.0.2.0..192.0.2.50", true),
            ("ip.src in 192.0.2.1..192.0.2.50", true),
            ("ip.src in 192.0.2.2..192.0.2.50", false),
            ("ip.src in 10.0.0.0..10.0.0.1", true),
            ("ip.src in 10.0.0.2..10.0.0.9", false),
            ("ip.dst in {203.0.113.1, 198.51.100.0..198.51.100.2}", true),
            ("ip.dst in {203.0.113.1, 198.51.100.3..198.51.100.9}", false),
            ("ip.addr in 10.0.0.2..10.0.0.2", true),
            ("ip.src != 192.0.2.0..192.0.2.9", true),
        ],
    );
    assert_filters(
        &ipv6_tcp(),
        &[
            ("ipv6.src in 2001:db8::..2001:db8::ff", true),
            ("ipv6.src in 2001:db8::1..2001:db8::1", true),
            ("ipv6.src in 2001:db8::2..2001:db8::ff", false),
            ("ipv6.addr in 2001:db8:1::..2001:db8:1::3", true),
        ],
    );
    let registry = registry();
    for (source, path, kind, offset) in [
        (
            "ipv6.src in 192.0.2.1..192.0.2.9",
            "ipv6.src",
            "an IPv6 address",
            9,
        ),
        (
            "ip.src in 2001:db8::1..2001:db8::9",
            "ip.src",
            "an IPv4 address",
            7,
        ),
        ("ip.src in 1..9", "ip.src", "an IPv4 address", 7),
        (
            "udp.dstport in 192.0.2.1..192.0.2.9",
            "udp.dstport",
            "an unsigned number",
            12,
        ),
    ] {
        match Filter::compile(source, &registry, Limits::default()) {
            Err(Error::IncompatibleLiteral {
                offset: actual_offset,
                path: actual_path,
                kind: actual_kind,
                ..
            }) => {
                assert_eq!(actual_offset, offset, "{source}");
                assert_eq!(actual_path, path, "{source}");
                assert_eq!(actual_kind, kind, "{source}");
            }
            other => panic!("{source}: expected IncompatibleLiteral, got {other:?}"),
        }
    }
    match Filter::compile(
        "ip.src == 192.0.2.1..2001:db8::9",
        &registry,
        Limits::default(),
    ) {
        Err(Error::InvalidRange {
            offset: 10,
            path,
            reason,
            ..
        }) => {
            assert_eq!(path, "ip.src");
            assert!(reason.contains("same kind"), "{reason}");
        }
        other => panic!("expected InvalidRange for mixed ends, got {other:?}"),
    }
}

#[test]
fn signed_fields_take_non_negative_ranges_and_never_match_negative_values() {
    let mut decoded = tunnelled();
    assert_filters(
        &decoded,
        &[
            ("frame.time_epoch in 123..123", true),
            ("frame.time_epoch in 100..200", true),
            ("frame.time_epoch in 124..200", false),
            ("frame.time_epoch == 0..122", false),
            ("frame.time_epoch != 0..122", true),
        ],
    );
    decoded.frame.timestamp = Some(UNIX_EPOCH - Duration::new(1, 500_000_000));
    assert_filters(
        &decoded,
        &[
            ("frame.time_epoch in 0..10", false),
            ("frame.time_epoch in 0..18446744073709551615", false),
            ("frame.time_epoch != 0..10", true),
        ],
    );
}

#[test]
fn malformed_and_misused_ranges_are_typed_errors_with_offsets() {
    let registry = registry();
    for (source, offset) in [
        ("tcp.port in 200..100", 12),
        ("tcp.port in 1..", 12),
        ("tcp.port in ..9", 12),
        ("tcp.port in 1...5", 12),
        ("tcp.port in -5..5", 12),
        ("tcp.port in 1..a", 12),
        ("tcp.port == 200..100", 12),
        ("tcp.port in {1, 5..2}", 16),
        ("ip.src in 192.0.2.9..192.0.2.1", 10),
        ("ip.src in 192.0.2.1..::1", 10),
    ] {
        match Filter::compile(source, &registry, Limits::default()) {
            Err(Error::InvalidRange {
                offset: actual,
                path,
                ..
            }) => {
                assert_eq!(actual, offset, "{source}");
                assert_eq!(path, source.split(' ').next().expect("path"), "{source}");
            }
            other => panic!("{source}: expected InvalidRange, got {other:?}"),
        }
    }
    for source in [
        "tcp.port >= 1..5",
        "tcp.port < 1..5",
        "ip.src > 1.1.1.1..2.2.2.2",
    ] {
        assert!(
            matches!(
                Filter::compile(source, &registry, Limits::default()),
                Err(Error::OrderedRangeComparison { .. })
            ),
            "{source}"
        );
    }
    assert_rejected(&[
        ("tcp.port in a..b", "cannot be compared"),
        ("tcp.port == a..b", "cannot be compared"),
        ("tcp.port >= 1..5", "only `==`, `!=`, and `in`"),
    ]);
}

#[test]
fn ranges_leave_text_and_byte_fields_alone() {
    let registry = registry();
    for source in [
        "tls.sni == a..b",
        "tls.sni == 1..5",
        "tls.sni == \"1..5\"",
        "dns.qname == \"a..b\"",
        "raw.bytes == 1..5",
    ] {
        Filter::compile(source, &registry, Limits::default())
            .unwrap_or_else(|error| panic!("{source} must compile: {error}"));
    }
    assert_filters(
        &payload(b"x..y"),
        &[
            ("raw.bytes == \"x..y\"", true),
            ("raw.bytes contains \"..\"", true),
            ("raw.bytes == x..y", true),
        ],
    );
}

#[test]
fn a_range_counts_as_one_set_member_toward_the_cap() {
    let registry = registry();
    let limits = |max_set_members| Limits {
        max_set_members,
        ..Limits::default()
    };
    Filter::compile("udp.port in {1, 2, 10..20}", &registry, limits(3))
        .expect("one range and two exact members fit a cap of three");
    assert!(matches!(
        Filter::compile("udp.port in {1, 2, 10..20}", &registry, limits(2)),
        Err(Error::SetMemberLimit { limit: 2 })
    ));
    Filter::compile("udp.port in {0..65535}", &registry, limits(1))
        .expect("a single range is one member however wide");
}

fn dns_query(name: &str) -> decode::DecodedPacket {
    recipe(&format!(
        "ipv4(source=192.0.2.1,destination=192.0.2.53)/udp(source_port=12345,destination_port=53)/dns(id=7,questions=[{{name=\"{name}\",type=1,class=1}}])"
    ))
}

#[test]
fn text_operators_read_list_fields_elementwise_and_decide_on_exact_names() {
    assert_filters(
        &dns_query("www.example.com."),
        &[
            // Names render fully qualified, so the trailing dot is part of the text.
            ("dns.qname endswith \".example.com.\"", true),
            ("dns.qname endswith \".example.com\"", false),
            ("dns.qname endswith \"EXAMPLE.COM.\"", false),
            ("dns.qname startswith \"www.\"", true),
            ("dns.qname startswith \"example\"", false),
            ("dns.qname icontains \"EXAMPLE\"", true),
            ("dns.qname contains \"EXAMPLE\"", false),
            ("dns.qname contains \"example\"", true),
            ("dns.qname iequals \"WWW.Example.COM.\"", true),
            ("dns.qname iequals \"www.example.com\"", false),
            ("dns.questions[0].name iequals \"WWW.EXAMPLE.COM.\"", true),
            ("dns.questions[0].name endswith \".com.\"", true),
        ],
    );
    assert_filters(
        &dns_query("example.com.evil."),
        &[
            ("dns.qname endswith \".example.com.\"", false),
            ("dns.qname startswith \"example.com\"", true),
            ("dns.qname icontains \"EVIL\"", true),
        ],
    );
}

#[test]
fn escapes_in_plain_text_compare_exactly_on_text_fields() {
    let query = dns_query("www.example.com.");
    assert_filters(
        &query,
        &[
            ("dns.questions[0].name == \"\\x77ww.example.com.\"", true),
            ("dns.questions[0].name != \"\\x77ww.example.com.\"", false),
            ("dns.questions[0].name == \"www\\x2eexample.com.\"", true),
            ("dns.questions[0].name == \"www\\x2fexample.com.\"", false),
            ("dns.questions[0].name != \"www\\x2fexample.com.\"", true),
            ("dns.questions[0].name == \"www\\nexample.com.\"", false),
            ("dns.questions[0].name != \"www\\nexample.com.\"", true),
            ("dns.questions[0].name == \"www.example.com.\\x20\"", false),
        ],
    );
    // A space in a qname is stored escaped on the wire and read back as a space.
    assert_filters(
        &dns_query("a b.example."),
        &[
            ("dns.qname == \"a\\x20b.example.\"", true),
            ("dns.qname != \"a\\x20b.example.\"", false),
            ("dns.qname == \"a\\x20c.example.\"", false),
            ("dns.qname != \"a\\x20c.example.\"", true),
            ("dns.qname == \"a\\nb.example.\"", false),
        ],
    );
}

#[test]
fn text_operators_accept_lists_of_scalars_and_refuse_lists_of_objects() {
    let query = dns_query("www.example.com.");
    let registry = registry();
    for source in [
        "dns.questions startswith \"w\"",
        "dns.questions contains \"w\"",
        "dns.questions iequals \"w\"",
        "dns.answers endswith \"w\"",
        "tcp.options icontains \"w\"",
    ] {
        let error = Filter::compile(source, &registry, Limits::default())
            .expect_err("a list of objects cannot hold a text match");
        let Error::IncompatibleLiteral { path, kind, .. } = &error else {
            panic!("{source}: unexpected error {error}");
        };
        assert_eq!(path, source.split(' ').next().expect("path"), "{source}");
        assert_eq!(*kind, "a list", "{source}");
    }
    // The schema does not name a scalar list's element kind, so these compile and select nothing.
    assert_filters(
        &query,
        &[
            ("dns.qtype startswith \"1\"", false),
            ("dns.qtype icontains \"1\"", false),
            ("dns.qname startswith \"www\"", true),
        ],
    );
}

#[test]
fn text_operators_fold_ascii_only_on_bytes_and_text() {
    assert_filters(
        &tunnelled(),
        &[
            ("raw.bytes startswith \"GET \"", true),
            ("raw.bytes startswith \"GET  \"", false),
            ("raw.bytes startswith \"get \"", false),
            ("raw.bytes startswith 47:45:54", true),
            ("raw.bytes startswith \"\"", true),
            (
                "raw.bytes startswith \"GET /index HTTP/1.1 and more\"",
                false,
            ),
            ("raw.bytes endswith \"HTTP/1.1\"", true),
            ("raw.bytes endswith \"http/1.1\"", false),
            ("raw.bytes endswith \"\"", true),
            ("raw.bytes icontains \"index http\"", true),
            ("raw.bytes icontains \"INDEX HTTP\"", true),
            ("raw.bytes icontains \"index  http\"", false),
            ("raw.bytes icontains \"\"", true),
            ("raw.bytes iequals \"get /INDEX http/1.1\"", true),
            ("raw.bytes iequals \"get /index\"", false),
            ("raw.bytes iequals \"\"", false),
            ("eth.src startswith 06:07", true),
            ("eth.src endswith 0a:0b", true),
            ("eth.src startswith 07:06", false),
        ],
    );
    assert_filters(
        &payload(&[0xe9, b'A', b'b']),
        &[
            ("raw.bytes icontains b\"\\xe9\"", true),
            ("raw.bytes icontains b\"\\xc9\"", false),
            ("raw.bytes iequals b\"\\xe9ab\"", true),
            ("raw.bytes iequals b\"\\xc9ab\"", false),
            ("raw.bytes startswith b\"\\xe9A\"", true),
            ("raw.bytes startswith b\"\\xe9a\"", false),
            ("raw.bytes endswith b\"\\xe9\"", false),
            ("raw.bytes endswith b\"Ab\"", true),
            ("raw.bytes icontains \"aB\"", true),
        ],
    );
}

#[test]
fn text_operators_refuse_numeric_fields_at_compile_time() {
    let registry = registry();
    for source in [
        "tcp.port startswith \"8\"",
        "tcp.srcport endswith 80",
        "ip.src icontains \"1\"",
        "frame.len iequals \"1\"",
        "tcp.flags.syn startswith \"1\"",
    ] {
        let error = Filter::compile(source, &registry, Limits::default())
            .expect_err("a numeric field must not take a text operator");
        let Error::IncompatibleLiteral { path, .. } = &error else {
            panic!("{source}: unexpected error {error}");
        };
        assert_eq!(path, source.split(' ').next().expect("path"), "{source}");
    }
    assert_rejected(&[
        ("raw.bytes startswith", "expected a value"),
        ("tcp startswith \"x\"", "names a layer"),
    ]);
}

#[test]
fn text_operator_keywords_collide_with_no_registered_name() {
    let registry = registry();
    let reserved = ["contains", "startswith", "endswith", "icontains", "iequals"];
    let mut names: Vec<String> = registry
        .protocols()
        .map(|protocol| protocol.as_str().to_owned())
        .collect();
    for protocol in registry.protocols() {
        if let Some(schema) = registry.schema(protocol.as_str()) {
            names.extend(schema.fields.iter().map(|field| field.name.to_owned()));
        }
    }
    for (path, _) in registry.filter_fields() {
        names.extend(path.split('.').map(str::to_owned));
    }
    for name in names {
        assert!(
            !reserved.iter().any(|word| word.eq_ignore_ascii_case(&name)),
            "{name} collides with a filter operator"
        );
    }
}

const DNS_ENDPOINTS: &str =
    "ipv4(source=192.0.2.53,destination=192.0.2.1)/udp(source_port=53,destination_port=12345)";

fn dns_response(answers: &str) -> decode::DecodedPacket {
    recipe(&format!(
        "{DNS_ENDPOINTS}/dns(id=7,response=true,questions=[{{name=\"example.test.\",type=1,class=1}}],answers=[{answers}])"
    ))
}

const A_THEN_CNAME: &str = concat!(
    "{owner=\"a.test.\",ttl=60,value={kind=a,address=192.0.2.8}},",
    "{owner=\"b.test.\",ttl=30,value={kind=cname,name=\"c.test.\"}}"
);

fn tcp_options(options: &str) -> decode::DecodedPacket {
    recipe(&format!(
        "ipv4(source=192.0.2.1,destination=198.51.100.2)/tcp(source_port=40000,destination_port=443,flags=2,options=[{options}])"
    ))
}

#[test]
fn all_element_and_last_element_selectors_match_any_selected_list_element() {
    assert_filters(
        &dns_response(A_THEN_CNAME),
        &[
            ("dns.answers[*].type == 1", true),
            ("dns.answers[*].type == 5", true),
            ("dns.answers[*].type == 28", false),
            ("dns.answers[*].type != 1", true),
            ("dns.answers[-1].type == 5", true),
            ("dns.answers[-1].type == 1", false),
            ("dns.answers[-1].ttl > 20", true),
            ("dns.answers[-1].ttl > 60", false),
            ("dns.answers[0].type == 1", true),
            ("dns.answers[*].owner iequals \"B.TEST.\"", true),
            ("dns.answers[-1].owner iequals \"A.TEST.\"", false),
            ("dns.answers[*].value.kind == cname", true),
            ("dns.answers[-1].value.name == \"c.test.\"", true),
            ("dns.answers[*].value.address == 192.0.2.8", true),
            // Each side of `&&` selects independently, so different elements can satisfy each term.
            ("dns.answers[*].ttl == 60 && dns.answers[*].ttl == 30", true),
            ("dns.answers[*].ttl in 61..100", false),
            ("dns.answers[*].owner", true),
            ("!dns.answers[*].owner", false),
            ("dns.qname[*] == \"example.test.\"", true),
            ("dns.qname[-1] startswith \"example\"", true),
            ("dns.answers[*].owner[0:1] == \"a\"", true),
            ("dns.answers[*].owner[0:1] == \"c\"", false),
        ],
    );
    assert_filters(
        &dns_response(""),
        &[
            ("dns.answers[*].type == 1", false),
            ("dns.answers[-1].type == 5", false),
            ("dns.answers[*].type != 1", false),
            ("dns.answers[*].owner", false),
            ("dns.answers[-1].owner", false),
            ("!(dns.answers[*].type == 1)", true),
        ],
    );
    assert_filters(
        &tcp_options("{kind=2,mss=1460},{kind=8,tsval=1,tsecr=2},{kind=1},{kind=1}"),
        &[
            ("tcp.options[*].kind == 8", true),
            ("tcp.options[*].kind in {8, 9}", true),
            ("tcp.options[*].kind == 3", false),
            ("tcp.options[-1].kind == 1", true),
            ("tcp.options[-1].kind == 8", false),
        ],
    );
    assert_filters(
        &tcp_options("{kind=2,mss=1460}"),
        &[("tcp.options[*].kind == 8", false)],
    );
}

#[test]
fn list_selectors_on_anything_but_a_list_fail_at_compile_time_with_offsets() {
    let registry = registry();
    for (source, offset, expected) in [
        ("ipv4.ttl[*] == 1", 0, "not a list"),
        ("dns.id[-1] == 1", 0, "not a list"),
        ("ethernet.source[-1] == 7", 0, "not a list"),
        ("ipv4[*]", 0, "a protocol is not a list"),
        ("ipv4 && tcp.flags[-1]", 8, "not a list"),
        (
            "dns.answers[*].owner[*] == \"a\"",
            0,
            "more than one list selector",
        ),
    ] {
        let error = Filter::compile(source, &registry, Limits::default())
            .expect_err("a selector needs a list");
        let Error::Syntax {
            offset: actual,
            message,
        } = &error
        else {
            panic!("{source}: unexpected error {error}");
        };
        assert_eq!(*actual, offset, "{source}");
        assert!(message.contains(expected), "{source}: {error}");
    }
    assert_rejected(&[
        ("dns.answers[*].bogus == 1", "unknown"),
        ("dns.bogus[*].type == 1", "unknown"),
        ("dns.answers[*].type == \"x\"", "cannot be compared"),
        ("dns.answers[*].type contains \"x\"", "cannot be compared"),
        ("frame.protocols[*] == \"ipv4\"", "unknown"),
        ("dns.answers[-2].type == 1", "is not a number"),
    ]);
    // Literal indexes keep their old meaning.
    assert_filters(
        &dns_response(A_THEN_CNAME),
        &[
            ("dns.answers[1].type == 5", true),
            ("dns.answers[2].type == 5", false),
        ],
    );
}

#[test]
fn projections_gather_all_elements_into_a_list_within_the_cell_budget() {
    let registry = registry();
    let projection = Projection::compile(
        [
            "dns.answers[*].owner",
            "dns.answers[-1].owner",
            "dns.answers[*].ttl",
        ],
        &registry,
    )
    .expect("selector projection compiles");
    assert_eq!(
        projection.columns(),
        [
            "dns.answers[*].owner",
            "dns.answers[-1].owner",
            "dns.answers[*].ttl"
        ]
    );
    let text = |value: &str| FieldValue::Text(value.to_owned());
    let response = dns_response(A_THEN_CNAME);
    assert_eq!(
        projection
            .values(&context(&response), 4096)
            .expect("projection within budget"),
        [
            Some(FieldValue::List(vec![text("a.test."), text("b.test.")])),
            Some(text("b.test.")),
            Some(FieldValue::List(vec![
                FieldValue::Unsigned(60),
                FieldValue::Unsigned(30)
            ])),
        ]
    );

    // A one-element list stays a list, and an empty one has no value.
    let single = dns_response("{owner=\"a.test.\",ttl=60,value={kind=a,address=192.0.2.8}}");
    let row = projection
        .values(&context(&single), 4096)
        .expect("projection within budget");
    assert_eq!(row[0], Some(FieldValue::List(vec![text("a.test.")])));
    assert_eq!(row[1], Some(text("a.test.")));
    let empty = dns_response("");
    assert_eq!(
        projection
            .values(&context(&empty), 4096)
            .expect("projection within budget"),
        [None, None, None]
    );

    let error = projection
        .values(&context(&response), 24)
        .expect_err("the selected elements count toward the cell budget");
    assert!(matches!(error, Error::ProjectionLimit { .. }), "{error:?}");
}

fn gre_tunnel() -> decode::DecodedPacket {
    let mut packet = Packet::new();
    packet.push(Ethernet::default());
    packet.push(Ipv4 {
        source: "203.0.113.1".parse().expect("outer source"),
        destination: "203.0.113.2".parse().expect("outer destination"),
        ..Ipv4::default()
    });
    packet.push(Gre::default());
    packet.push(Ipv4 {
        source: "10.0.0.1".parse().expect("inner source"),
        destination: "10.0.0.2".parse().expect("inner destination"),
        ..Ipv4::default()
    });
    packet.push(Tcp {
        source_port: 40_000,
        destination_port: 443,
        ..Tcp::default()
    });
    decoded(packet)
}

fn layered(layers: Vec<Box<dyn Layer>>) -> decode::DecodedPacket {
    let mut packet = Packet::new();
    for layer in layers {
        packet.push_boxed(layer);
    }
    decode::DecodedPacket {
        packet,
        frame: Frame::new(UNIX_EPOCH, LinkType::IPV4, Vec::new()).expect("fixture frame"),
        layout: PacketLayout::new(Vec::new()),
        diagnostics: Vec::new(),
    }
}

fn ipv4_from(source: &str) -> Box<dyn Layer> {
    Box::new(Ipv4 {
        source: source.parse().expect("fixture source"),
        ..Ipv4::default()
    })
}

#[test]
fn innermost_occurrence_selects_the_last_matching_layer() {
    assert_filters(
        &gre_tunnel(),
        &[
            ("ipv4#-1.destination == 10.0.0.2", true),
            ("ipv4#last.destination == 10.0.0.2", true),
            ("ipv4#-1.destination == 203.0.113.2", false),
            ("ipv4#1.destination == 203.0.113.2", true),
            ("ipv4#1.destination == 10.0.0.2", false),
            ("ipv4#2.destination == 10.0.0.2", true),
            ("ip#last.dst == 10.0.0.2", true),
            ("ip#last.dst == 203.0.113.2", false),
            ("ip#last.addr == 10.0.0.1", true),
            ("ipv4#last", true),
            ("ipv4#-1", true),
            ("tcp#last.dstport == 443", true),
            ("udp#last", false),
            ("!ipv4#last.source == 203.0.113.1", true),
        ],
    );
    // On a stack with one matching layer both ends select it.
    let plain = payload(b"x");
    assert_filters(
        &plain,
        &[
            ("ipv4#1.source == 192.0.2.1", true),
            ("ipv4#last.source == 192.0.2.1", true),
            ("ipv4#-1.source == 192.0.2.1", true),
            ("ipv4#last", true),
            ("tcp#last", false),
            ("ipv4#2", false),
        ],
    );
    assert_filters(
        &tunnelled(),
        &[
            ("udp#last.dstport == 9999", true),
            ("udp#last.dstport == 4789", false),
            ("ethernet#-1.source == aa:bb:cc:dd:ee:ff", true),
        ],
    );
}

#[test]
fn innermost_occurrence_follows_the_chained_order_of_derived_packets() {
    let physical = layered(vec![ipv4_from("192.0.2.1")]);
    let completed = layered(vec![
        ipv4_from("192.0.2.1"),
        ipv4_from("198.51.100.7"),
        Box::new(Udp::default()),
    ]);
    let derived = [DerivedPacket {
        decoded: &completed,
        replayed_prefix_layers: 1,
    }];
    let context = Context {
        decoded: &physical,
        derived: &derived,
        number: 1,
        tcp_stream: None,
        udp_stream: None,
    };
    for (source, expected) in [
        ("ipv4#1.source == 192.0.2.1", true),
        ("ipv4#2.source == 198.51.100.7", true),
        ("ipv4#last.source == 198.51.100.7", true),
        ("ipv4#-1.source == 198.51.100.7", true),
        ("ipv4#last.source == 192.0.2.1", false),
        ("ipv4#3", false),
        ("udp#last", true),
    ] {
        let filter = Filter::compile(source, &registry(), Limits::default())
            .unwrap_or_else(|error| panic!("{source} must compile: {error}"));
        assert_eq!(
            filter.matches(&context).expect("filter evaluates"),
            expected,
            "{source}"
        );
    }
}

#[test]
fn innermost_occurrence_projects_the_last_layer() {
    let projection = Projection::compile(
        ["ipv4#last.destination", "ipv4#-1.source", "ipv4#1.source"],
        &registry(),
    )
    .expect("innermost projection compiles");
    let tunnel = gre_tunnel();
    assert_eq!(
        projection
            .values(&context(&tunnel), 4096)
            .expect("projection within budget"),
        [
            Some(FieldValue::Ipv4("10.0.0.2".parse().expect("address"))),
            Some(FieldValue::Ipv4("10.0.0.1".parse().expect("address"))),
            Some(FieldValue::Ipv4("203.0.113.1".parse().expect("address"))),
        ]
    );
}

fn measured(source: &str, decoded: &decode::DecodedPacket) -> bool {
    Filter::compile(source, &registry(), Limits::default())
        .unwrap_or_else(|error| panic!("{source} must compile: {error}"))
        .matches(&context(decoded))
        .unwrap_or_else(|error| panic!("{source} must evaluate: {error}"))
}

#[test]
fn len_measures_bytes_text_addresses_and_each_list_element() {
    assert!(measured("len(raw.bytes) > 1400", &payload(&[0; 1500])));
    assert!(!measured("len(raw.bytes) > 1400", &payload(&[0; 100])));
    let tunnelled = tunnelled();
    assert_filters(
        &tunnelled,
        &[
            ("len(raw.bytes) == 19", true),
            ("len(raw.bytes) == 0x13", true),
            ("len(raw.bytes) != 19", false),
            ("len(raw.bytes) >= 19", true),
            ("len(raw.bytes) < 19", false),
            ("len(raw.bytes) <= 19", true),
            ("len(raw.bytes) gt 18", true),
            ("LEN(raw.bytes) == 19", true),
            ("len( raw.bytes ) == 19", true),
            ("len(raw.bytes[0:4]) == 4", true),
            ("len(raw.bytes[0:100]) == 19", true),
            ("len(raw.bytes[30:40]) == 0", false),
            ("len(eth.src) == 6", true),
            ("len(ipv4.source) == 4", true),
            ("len(ip.addr) == 4", true),
            ("len(ipv4#2.source) == 4 && len(ipv4#1.source) == 4", true),
            // Grouping and boolean structure around a measurement behave as before.
            ("(len(raw.bytes) == 19) && (ipv4 || (udp && !tcp))", true),
            ("!(len(raw.bytes) == 19) || len(raw.bytes) == 18", false),
            ("frame.len > 0 && len(raw.bytes) == 19", true),
        ],
    );
    assert_filters(&ipv6_tcp(), &[("len(ipv6.src) == 16", true)]);

    let short = dns_query("a.test.");
    let long = dns_query(&format!(
        "{}.{}.{}.",
        "a".repeat(30),
        "b".repeat(30),
        "c".repeat(30)
    ));
    for (source, short_matches, long_matches) in [
        ("len(dns.qname) > 63", false, true),
        ("len(dns.qname[0]) > 63", false, true),
        ("len(dns.qname) == 7", true, false),
        ("len(dns.questions[0].name) > 63", false, true),
        ("len(dns.qname[*]) > 63", false, true),
    ] {
        assert_eq!(measured(source, &short), short_matches, "{source}");
        assert_eq!(measured(source, &long), long_matches, "{source}");
    }
    // A missing value has no length, so even `== 0` and `!=` do not select it.
    let response = dns_response(A_THEN_CNAME);
    assert_filters(
        &response,
        &[
            ("len(raw.bytes) == 0", false),
            ("len(raw.bytes) != 0", false),
            ("!(len(raw.bytes) == 0)", true),
            ("len(dns.answers[*].owner) == 7", true),
            ("len(dns.answers[-1].owner) == 8", false),
        ],
    );
}

#[test]
fn count_measures_whole_lists() {
    let response = dns_response(A_THEN_CNAME);
    assert_filters(
        &response,
        &[
            ("count(dns.answers) == 2", true),
            ("count(dns.answers) == 0", false),
            ("count(dns.answers) >= 2 && count(dns.answers) < 3", true),
            ("count(dns.qname) == 1", true),
            ("count(dns.questions) == 1", true),
            ("count(dns.authorities) == 0", true),
        ],
    );
    assert_filters(
        &dns_response(""),
        &[
            ("count(dns.answers) == 0", true),
            ("count(dns.answers) > 0", false),
        ],
    );
    assert_filters(
        &tunnelled(),
        &[
            ("count(frame.protocols) == 8", true),
            ("count(frame.protocols) > 8", false),
        ],
    );
    assert_filters(&response, &[("count(frame.protocols) == 3", true)]);
    let stuffed = tcp_options("{kind=1},{kind=1},{kind=1},{kind=1},{kind=1}");
    assert!(measured("count(tcp.options) > 4", &stuffed));
    let mss_only = tcp_options("{kind=2,mss=1460}");
    assert!(!measured("count(tcp.options) > 4", &mss_only));
    assert!(measured("count(tcp.options) == 1", &mss_only));
}

#[test]
fn measurement_misuse_fails_at_compile_time_and_ordinary_words_are_unaffected() {
    for (source, offset, expected) in [
        ("count(ipv4.ttl) > 1", 5, "a whole list"),
        ("len(tcp.port) > 1", 3, "bytes, text, an address"),
        ("len(dns.answers) > 1", 3, "bytes, text, an address"),
        ("count(dns.answers[*]) > 1", 5, "a whole list"),
        ("count(dns.qname[0]) > 1", 5, "a whole list"),
        ("count(raw.bytes[0:2]) > 1", 5, "a whole list"),
        (
            "len(frame.protocols) > 3",
            3,
            "use `count(frame.protocols)` or `frame.layer_count`",
        ),
        ("len(", 3, "needs a field path"),
        ("len()", 3, "needs a field path"),
        ("len(raw.bytes", 3, "expected `)`"),
        ("len(raw.bytes > 5", 14, "expected `)`"),
        ("len(raw.bytes) && ipv4", 15, "must be compared"),
        ("len(raw.bytes)", 3, "must be compared"),
        ("len(raw.bytes) > -1", 17, "unsigned number"),
        ("len(raw.bytes) > abc", 17, "unsigned number"),
        ("len(raw.bytes) > 1..5", 17, "unsigned number"),
        ("len(raw.bytes) > \"1\"", 17, "unsigned number"),
        ("len(raw.bytes) >", 15, "end of the filter"),
        ("len(ipv4) > 1", 4, "takes a field, not a layer"),
    ] {
        let error = Filter::compile(source, &registry(), Limits::default())
            .expect_err("a malformed measurement must not compile");
        let Error::Syntax {
            offset: actual,
            message,
        } = &error
        else {
            panic!("{source}: unexpected error {error}");
        };
        assert!(message.contains(expected), "{source}: {error}");
        assert_eq!(*actual, offset, "{source}: {error}");
    }
    assert_rejected(&[
        ("len(nosuch.field) > 1", "unknown"),
        ("len == 1", "unknown"),
        ("count > 1", "unknown"),
        ("len(raw.bytes) in 1..5", "must be compared"),
    ]);
    for source in [
        "count(ip.ttl) > 1",
        "len(frame.len) > 1",
        "len(tcp.srcport) > 1",
    ] {
        assert!(
            Filter::compile(source, &registry(), Limits::default()).is_err(),
            "{source}"
        );
    }
    // Without a following `(` the words stay ordinary, and a measurement adds no nesting depth.
    assert_filters(
        &tunnelled(),
        &[("frame.len > 0", true), ("(frame.len > 0)", true)],
    );
    let shallow = Limits {
        max_nesting: 1,
        ..Limits::default()
    };
    Filter::compile("(len(raw.bytes) > 1)", &registry(), shallow.clone())
        .expect("the measurement's parenthesis is not a grouping level");
    assert!(matches!(
        Filter::compile("((len(raw.bytes) > 1))", &registry(), shallow),
        Err(Error::NestingLimit { limit: 1 })
    ));
    // Projections take field paths only.
    assert!(Projection::compile(["len(raw.bytes)"], &registry()).is_err());
}

#[test]
fn frame_time_nsec_is_the_sub_second_part_of_the_floored_timestamp() {
    let mut decoded = tunnelled();
    decoded.frame.timestamp = Some(UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789));
    assert_filters(
        &decoded,
        &[
            ("frame.time_nsec == 123456789", true),
            ("frame.time_epoch == 1700000000", true),
            ("frame.time_nsec == 123456788", false),
            (
                "frame.time_nsec > 123456788 && frame.time_nsec < 123456790",
                true,
            ),
            ("frame.time_nsec in 0..123456789", true),
            ("FRAME.time_nsec == 123456789", true),
        ],
    );
    decoded.frame.timestamp = Some(UNIX_EPOCH - Duration::new(1, 500_000_000));
    assert_filters(
        &decoded,
        &[
            ("frame.time_epoch == -2", true),
            ("frame.time_nsec == 500000000", true),
        ],
    );
    decoded.frame.timestamp = Some(UNIX_EPOCH + Duration::new(5, 0));
    assert_filters(&decoded, &[("frame.time_nsec == 0", true)]);

    let filter = Filter::compile("frame.time_nsec >= 0", &registry(), Limits::default())
        .expect("nanosecond filter compiles");
    assert!(filter.requirements().timestamp);
    assert!(!filter.requirements().stream_index);
    decoded.frame.timestamp = None;
    assert!(matches!(
        filter.matches(&context(&decoded)),
        Err(Error::TimestampUnavailable)
    ));
    // Facts that do not read the timestamp still evaluate without one.
    assert!(measured("frame.layer_count > 0", &decoded));
}

#[test]
fn frame_direction_truncation_layers_and_protocols_read_the_decoded_frame() {
    let mut decoded = tunnelled();
    let unrecorded = ["frame.direction == inbound", "frame.direction != inbound"];
    for source in unrecorded {
        assert!(!measured(source, &decoded), "{source}");
    }
    assert!(!measured("frame.direction", &decoded));
    for (direction, name) in [
        (Direction::Inbound, "inbound"),
        (Direction::Outbound, "outbound"),
        (Direction::Unknown, "unknown"),
    ] {
        decoded.frame.direction = Some(direction);
        assert!(measured(
            &format!("frame.direction == \"{name}\""),
            &decoded
        ));
        assert!(measured(
            &format!("frame.direction iequals \"{name}\""),
            &decoded
        ));
        assert!(measured("frame.direction", &decoded));
        assert!(!measured("frame.direction == \"sideways\"", &decoded));
    }
    decoded.frame.direction = Some(Direction::Inbound);
    assert!(measured(
        "frame.direction == \"inbound\" && !(frame.direction == \"outbound\")",
        &decoded
    ));

    assert_filters(
        &decoded,
        &[
            ("frame.truncated", false),
            ("!frame.truncated", true),
            ("frame.truncated == false", true),
        ],
    );
    let captured = decoded.frame.captured_length();
    decoded.frame = Frame::try_with_lengths(
        UNIX_EPOCH,
        LinkType::ETHERNET,
        packetcraftr_core::frame::Lengths {
            captured,
            original: captured + 10,
        },
        decoded.frame.bytes().clone(),
    )
    .expect("a snapped frame");
    decoded.frame.direction = Some(Direction::Inbound);
    assert_filters(
        &decoded,
        &[
            ("frame.truncated", true),
            ("frame.truncated == true", true),
            ("!frame.truncated", false),
            ("frame.len > 0 && frame.truncated", true),
        ],
    );

    let layers = protocols(&decoded).len();
    assert_eq!(layers, 8);
    assert_filters(
        &decoded,
        &[
            ("frame.layer_count == 8", true),
            ("frame.layer_count >= 4", true),
            ("frame.layer_count > 8", false),
            ("frame.protocols == \"vxlan\"", true),
            ("frame.protocols == \"ipv4\"", true),
            ("frame.protocols == \"tls\"", false),
            ("frame.protocols startswith \"vx\"", true),
            ("frame.protocols contains \"tls\"", false),
            ("frame.protocols in {\"tls\", \"udp\"}", true),
        ],
    );
    assert_filters(
        &dns_response(A_THEN_CNAME),
        &[
            ("frame.protocols == \"dns\"", true),
            ("frame.protocols == \"vxlan\"", false),
            ("frame.layer_count >= 3", true),
        ],
    );
    assert_filters(&ipv6_tcp(), &[("frame.protocols == \"dns\"", false)]);

    let projection = Projection::compile(
        [
            "frame.direction",
            "frame.truncated",
            "frame.layer_count",
            "frame.protocols",
        ],
        &registry(),
    )
    .expect("frame facts project");
    let row = projection
        .values(&context(&decoded), 4096)
        .expect("projection within budget");
    assert_eq!(row[0], Some(FieldValue::Text("inbound".to_owned())));
    assert_eq!(row[1], Some(FieldValue::Bool(true)));
    assert_eq!(row[2], Some(FieldValue::Unsigned(8)));
    let Some(FieldValue::List(names)) = &row[3] else {
        panic!("frame.protocols projects a list: {:?}", row[3]);
    };
    assert_eq!(names.len(), 8);
    assert_eq!(names[0], FieldValue::Text("ethernet".to_owned()));
}

#[test]
fn new_frame_facts_are_reserved_and_take_no_slice_or_occurrence() {
    assert_rejected(&[
        ("frame.time_nsec[0] == 1", "cannot be sliced"),
        ("frame.direction[0] == 1", "cannot be sliced"),
        ("frame.truncated[0]", "cannot be sliced"),
        ("frame.layer_count[0] == 1", "cannot be sliced"),
        ("frame.layer_count#2 == 1", "must follow the protocol"),
        ("frame#2.layer_count == 1", "not a protocol layer"),
        ("frame#last.protocols == \"dns\"", "not a protocol layer"),
        ("frame.time_nsec == \"x\"", "cannot be compared"),
        ("frame.direction == 1", "cannot be compared"),
        ("frame.truncated == \"x\"", "cannot be compared"),
        ("frame.layer_count == \"x\"", "cannot be compared"),
        ("frame.timestamp_nsec == 1", "unknown"),
        // Whether a frame reassembled into derived packets is not a frame fact the filter reads.
        ("frame.reassembled", "unknown"),
        ("frame.protocols[0] == \"ipv4\"", "cannot be sliced"),
    ]);
}
