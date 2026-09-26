// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Performance-oriented contracts for filter evaluation and projection.
//!
//! Short-circuit evaluation is observable only through which reflective
//! fields a packet is asked for, so a field-read-counting layer proves that a
//! decisive `&&`/`||` operand skips the other side. A per-leaf oracle —
//! each predicate compiled alone and combined by the documented boolean
//! structure — replaces the eager interpreter as the reference for
//! differential testing. Projection tests pin the cell-byte budget at its
//! exact boundary and the values that flow through it.

mod common;

use common::registry;
use std::hint::black_box;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};

use bytes::Bytes;
use packetcraftr_core::decode::{self, DecodedPacket};
use packetcraftr_core::field::{self, FieldValue};
use packetcraftr_core::filter::{
    Context, DerivedPacket, Error, Filter, MAX_FILTER_TERMS, Options, Projection,
};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::{Layer, Malformed, Raw, Schema};
use packetcraftr_core::layout::PacketLayout;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::application::dns::{Dns, Question, Record, RecordValue};
use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::protocol::network::{Ipv4, Ipv6};
use packetcraftr_core::protocol::transport::{Tcp, Udp};
use packetcraftr_core::protocol::tunnel::Vxlan;
use packetcraftr_core::{build, codec};

const PAYLOAD: &[u8] = b"GET /index HTTP/1.1";

/// Builds one Ethernet-rooted packet and dissects the exact bytes back.
fn decoded(packet: Packet) -> DecodedPacket {
    let registry = registry();
    let built = build::Builder::new(Arc::clone(&registry))
        .build(packet, codec::Context::default(), build::Options::default())
        .unwrap_or_else(|error| panic!("fixture build: {error}"));
    let frame = Frame::new(
        UNIX_EPOCH + Duration::from_secs(123),
        LinkType::ETHERNET,
        built.bytes,
    )
    .expect("fixture frame");
    let mut decoded = decode::Dissector::new(registry)
        .decode(frame, decode::Options::default())
        .unwrap_or_else(|error| panic!("fixture decode: {error}"));
    decoded.frame.interface = Some(4);
    decoded
}

/// A packet assembled from layers directly, without a wire round trip: the
/// filter evaluator only reads `packet` and `frame`, so instrumented layers
/// can stand in for decoded ones.
fn layered(layers: Vec<Box<dyn Layer>>) -> DecodedPacket {
    let mut packet = Packet::new();
    for layer in layers {
        packet.push_boxed(layer);
    }
    DecodedPacket {
        packet,
        original: Bytes::new(),
        frame: Frame::new(
            UNIX_EPOCH + Duration::from_secs(123),
            LinkType::IPV4,
            Vec::new(),
        )
        .expect("fixture frame"),
        layout: PacketLayout::new(Vec::new()),
        diagnostics: Vec::new(),
    }
}

/// Outer `ethernet/ipv4/udp`, a VXLAN tunnel, then an inner
/// `ethernet/ipv4/udp/raw`: every protocol this file filters appears twice.
fn tunnelled() -> DecodedPacket {
    let mut packet = Packet::new();
    packet.push(Ethernet {
        destination: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
        source: [0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b],
        ..Ethernet::default()
    });
    packet.push(Ipv4 {
        source: "192.0.2.1".parse().expect("outer source"),
        destination: "198.51.100.2".parse().expect("outer destination"),
        ..Ipv4::default()
    });
    packet.push(Udp {
        source_port: 12_345,
        destination_port: 4_789,
        ..Udp::default()
    });
    packet.push(Vxlan {
        vni: 0x12345,
        ..Vxlan::default()
    });
    packet.push(Ethernet {
        destination: [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
        source: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        ..Ethernet::default()
    });
    packet.push(Ipv4 {
        source: "10.0.0.1".parse().expect("inner source"),
        destination: "10.0.0.2".parse().expect("inner destination"),
        ..Ipv4::default()
    });
    packet.push(Udp {
        source_port: 40_000,
        destination_port: 9_999,
        ..Udp::default()
    });
    packet.push(Raw::new(PAYLOAD.to_vec()));
    decoded(packet)
}

fn ipv6_tcp() -> DecodedPacket {
    let mut packet = Packet::new();
    packet.push(Ethernet::default());
    packet.push(Ipv6 {
        source: "2001:db8::1".parse().expect("source"),
        destination: "2001:db8:1::2".parse().expect("destination"),
        ..Ipv6::default()
    });
    packet.push(Tcp {
        source_port: 44_000,
        destination_port: 443,
        flags: Tcp::SYN | Tcp::ACK,
        ..Tcp::default()
    });
    packet.push(Raw::new(PAYLOAD.to_vec()));
    decoded(packet)
}

/// A DNS layer carrying nested values: a list of question objects and answer
/// objects whose `value` member is itself an object with a text list.
fn dns_layered() -> DecodedPacket {
    let questions = vec![
        Question {
            name: "example.test.".parse().expect("name"),
            query_type: 1,
            class: 1,
        },
        Question {
            name: "sub.domain.example.".parse().expect("name"),
            query_type: 28,
            class: 1,
        },
    ];
    let answers = vec![
        Record {
            owner: "example.test.".parse().expect("owner"),
            class: 1,
            ttl: 60,
            value: RecordValue::A("192.0.2.8".parse().expect("answer")),
        },
        Record {
            owner: "example.test.".parse().expect("owner"),
            class: 1,
            ttl: 60,
            value: RecordValue::Txt(vec![
                Bytes::from_static(b"plain text chunk"),
                Bytes::from_static(b"escaped \"quoted\" \\ chunk"),
            ]),
        },
    ];
    let mut dns = Dns::default();
    dns.edit(|dns| {
        dns.id = 7;
        dns.response = true;
        dns.questions = questions;
        dns.answers = answers;
    });
    layered(vec![Box::new(dns)])
}

fn context(decoded: &DecodedPacket) -> Context<'_> {
    Context {
        decoded,
        derived: &[],
        number: 7,
        tcp_stream: Some(2),
        udp_stream: Some(3),
    }
}

/// Compiles `source`, which must be a valid filter for the fixture registry.
fn compiled(source: &str) -> Filter {
    Filter::compile(source, &registry(), Options::default())
        .unwrap_or_else(|error| panic!("{source} must compile: {error}"))
}

/// The answer `source` gives against `decoded` as a standalone filter.
fn leaf_value(source: &str, context: &Context<'_>) -> Result<bool, Error> {
    compiled(source).matches(context)
}

/// A layer that records every reflective field read, so a test can prove
/// which predicates evaluation actually ran.
#[derive(Debug)]
struct CountedLayer {
    inner: Box<dyn Layer>,
    reads: Arc<Mutex<Vec<String>>>,
}

impl CountedLayer {
    fn wrapped(inner: impl Layer + 'static, reads: &Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            inner: Box::new(inner),
            reads: Arc::clone(reads),
        }
    }

    fn names(reads: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
        reads.lock().expect("reads lock").clone()
    }
}

impl Layer for CountedLayer {
    fn schema(&self) -> &'static Schema {
        self.inner.schema()
    }
    fn clone_box(&self) -> Box<dyn Layer> {
        Box::new(Self {
            inner: self.inner.clone_box(),
            reads: Arc::clone(&self.reads),
        })
    }
    fn field(&self, name: &str) -> Option<FieldValue> {
        self.reads.lock().expect("reads lock").push(name.to_owned());
        self.inner.field(name)
    }
    fn set_field(&mut self, name: &str, value: FieldValue) -> Result<(), field::Error> {
        self.inner.set_field(name, value)
    }
}

/// Runs `filter` against a packet whose TCP layer counts field reads,
/// returning the verdict and the ordered list of field names read.
fn counted_match(source: &str, tcp: Tcp, extra_layers: Vec<Box<dyn Layer>>) -> (bool, Vec<String>) {
    let reads = Arc::new(Mutex::new(Vec::new()));
    let mut layers: Vec<Box<dyn Layer>> = vec![Box::new(CountedLayer::wrapped(tcp, &reads))];
    layers.extend(extra_layers);
    let packet = layered(layers);
    let matched = compiled(source)
        .matches(&context(&packet))
        .unwrap_or_else(|error| panic!("{source} must evaluate: {error}"));
    (matched, CountedLayer::names(&reads))
}

fn tcp_fixture() -> Tcp {
    Tcp {
        source_port: 1_234,
        window: 1_024,
        ..Tcp::default()
    }
}

#[test]
fn decisive_left_operands_skip_right_side_field_reads() {
    // A false `&&` left operand: the comparison on the right never asks the
    // layer for its field.
    let (matched, reads) = counted_match(
        "tcp.srcport == 9 && tcp.window_size == 1024",
        tcp_fixture(),
        Vec::new(),
    );
    assert!(!matched);
    assert_eq!(reads, ["source_port"]);

    // A true `||` left operand skips the same way.
    let (matched, reads) = counted_match(
        "tcp.srcport == 1234 || tcp.window_size == 1",
        tcp_fixture(),
        Vec::new(),
    );
    assert!(matched);
    assert_eq!(reads, ["source_port"]);

    // A skipped right operand is skipped as a whole subtree.
    let (matched, reads) = counted_match(
        "tcp.srcport == 9 && (tcp.window_size == 1024 || tcp.urgent_pointer == 0)",
        tcp_fixture(),
        Vec::new(),
    );
    assert!(!matched);
    assert_eq!(reads, ["source_port"]);

    let (matched, reads) = counted_match(
        "tcp.srcport == 1234 || (tcp.window_size == 5 && tcp.urgent_pointer == 9)",
        tcp_fixture(),
        Vec::new(),
    );
    assert!(matched);
    assert_eq!(reads, ["source_port"]);

    // `!` preserves the skip direction: a false operand inverted is true, so
    // the right side must run; a true operand inverted short-circuits out.
    let (matched, reads) = counted_match(
        "!tcp.srcport == 9 && tcp.window_size == 1024",
        tcp_fixture(),
        Vec::new(),
    );
    assert!(matched);
    assert_eq!(reads, ["source_port", "window"]);

    let (matched, reads) = counted_match(
        "!tcp.srcport == 1234 && tcp.window_size == 1024",
        tcp_fixture(),
        Vec::new(),
    );
    assert!(!matched);
    assert_eq!(reads, ["source_port"]);
}

#[test]
fn undecided_left_operands_still_read_the_right_side() {
    let (matched, reads) = counted_match(
        "tcp.srcport == 1234 && tcp.window_size == 1024",
        tcp_fixture(),
        Vec::new(),
    );
    assert!(matched);
    assert_eq!(reads, ["source_port", "window"]);

    let (matched, reads) = counted_match(
        "tcp.srcport == 9 || tcp.window_size == 1024",
        tcp_fixture(),
        Vec::new(),
    );
    assert!(matched);
    assert_eq!(reads, ["source_port", "window"]);

    // A layer-presence left operand reads no fields at all; it is decided by
    // protocol id before any `field` call.
    let (matched, reads) =
        counted_match("tcp && tcp.window_size == 1024", tcp_fixture(), Vec::new());
    assert!(matched);
    assert_eq!(reads, ["window"]);

    // A guard on a different layer entirely still gates the counted layer's
    // fields.
    let reads = Arc::new(Mutex::new(Vec::new()));
    let packet = layered(vec![Box::new(CountedLayer::wrapped(
        Raw::new(b"needle in a haystack".to_vec()),
        &reads,
    ))]);
    for (source, expected_reads) in [
        ("frame.number == 5 && raw.bytes contains \"needle\"", 0usize),
        ("frame.number == 7 && raw.bytes contains \"needle\"", 1),
        ("frame.number == 7 || raw.bytes contains \"needle\"", 0),
        ("frame.number == 5 || raw.bytes contains \"needle\"", 1),
    ] {
        reads.lock().expect("reads lock").clear();
        let matched = compiled(source)
            .matches(&context(&packet))
            .expect("evaluates");
        let observed = CountedLayer::names(&reads).len();
        assert_eq!(observed, expected_reads, "{source} (matched={matched})");
    }
}

#[test]
fn missing_timestamp_fails_the_whole_filter_before_any_short_circuit() {
    let mut undated = tunnelled();
    undated.frame.timestamp = None;
    for source in [
        // The timestamp leaf sits behind a decisively false `&&` and a
        // decisively true `||`; the filter-level requirement is diagnosed
        // either way.
        "frame.number == 999 && frame.time_epoch == 0",
        "udp.dstport == 9999 || frame.time_epoch == 0",
        "frame.time_epoch == 123",
        "frame.number == 7 || (frame.time_epoch == 0 && udp)",
    ] {
        assert!(
            matches!(
                compiled(source).matches(&context(&undated)),
                Err(Error::TimestampUnavailable)
            ),
            "{source} must report the missing timestamp"
        );
    }
    // The same filters evaluate normally once the frame carries a timestamp.
    for (source, expected) in [
        ("frame.number == 999 && frame.time_epoch == 0", false),
        ("udp.dstport == 9999 || frame.time_epoch == 0", true),
        ("frame.time_epoch == 123", true),
        ("frame.number == 7 || (frame.time_epoch == 0 && udp)", true),
    ] {
        assert_eq!(
            compiled(source).matches(&context(&tunnelled())),
            Ok(expected),
            "{source}"
        );
    }
}

#[test]
fn unreachable_branches_are_still_validated_at_compile_time() {
    for source in [
        "udp.dstport == 9999 && nosuchproto.field == 1",
        "nosuchproto.field == 1 || udp.dstport == 9999",
        "udp.dstport == 9999 || (nosuchproto && ipv4)",
        "!(ipv4.nosuchfield == 1) && udp",
        "udp && !nosuchproto.field",
    ] {
        let error = Filter::compile(source, &registry(), Options::default())
            .expect_err("dead branches must still validate");
        assert!(
            error.to_string().contains("unknown"),
            "{source}: {error} must name the unknown field"
        );
    }
}

/// Leaf predicates spanning every value source: layer presence, direct and
/// either-endpoint fields, flags, comparisons in both directions, membership,
/// `contains`, byte slices, occurrences, nested paths, and frame/stream facts.
const LEAVES: &[&str] = &[
    "ipv4",
    "ipv6",
    "udp",
    "tcp",
    "ethernet#2",
    "udp.dstport == 9999",
    "udp.dstport != 9999",
    "udp.srcport >= 40000",
    "ipv4.source == 10.0.0.1",
    "ip.src in 192.0.2.0/24",
    "udp.dstport in {53, 9999}",
    "raw.bytes contains \"index\"",
    "raw.bytes contains \"absent\"",
    "tcp.flags.syn",
    "tcp.flags.fin",
    "frame.number == 7",
    "frame.len >= 14",
    "ethernet.source[0:2] == 06:07",
    "ipv4#2.source == 10.0.0.1",
    "tcp.stream == 2",
];

/// Asserts `source` agrees with `expected` on every fixture packet.
fn assert_on_all(source: &str, expected: bool, contexts: &[(&str, Context<'_>)]) {
    let filter = compiled(source);
    for (name, context) in contexts {
        assert_eq!(filter.matches(context), Ok(expected), "{source} on {name}");
    }
}

#[test]
fn two_leaf_combinations_match_per_leaf_semantics() {
    let tunnelled = tunnelled();
    let ipv6_tcp = ipv6_tcp();
    let dns = dns_layered();
    let contexts: Vec<(&str, Context<'_>)> = vec![
        ("tunnelled", context(&tunnelled)),
        ("ipv6_tcp", context(&ipv6_tcp)),
        ("dns", context(&dns)),
    ];

    // Each leaf's standalone answer on this packet is the oracle; the combined
    // filter must produce the same boolean whether or not evaluation can stop
    // early.
    for (name, context) in &contexts {
        let values: Vec<bool> = LEAVES
            .iter()
            .map(|leaf| {
                leaf_value(leaf, context)
                    .unwrap_or_else(|error| panic!("{leaf} must evaluate on {name}: {error}"))
            })
            .collect();
        for (left_index, &left) in LEAVES.iter().enumerate() {
            for (right_index, &right) in LEAVES.iter().enumerate() {
                let (l, r) = (values[left_index], values[right_index]);
                let forms: [(String, bool); 8] = [
                    (format!("{left} && {right}"), l && r),
                    (format!("{left} || {right}"), l || r),
                    (format!("!{left} && {right}"), !l && r),
                    (format!("{left} && !{right}"), l && !r),
                    (format!("!{left} || {right}"), !l || r),
                    (format!("{left} || !{right}"), l || !r),
                    (format!("!({left} && {right})"), !(l && r)),
                    (format!("!({left} || {right})"), !(l || r)),
                ];
                for (source, expected) in forms {
                    assert_eq!(
                        compiled(&source).matches(context),
                        Ok(expected),
                        "{source} on {name}"
                    );
                }
            }
        }
    }
}

#[test]
fn three_leaf_combinations_match_per_leaf_semantics() {
    let tunnelled = tunnelled();
    let context = context(&tunnelled);
    // A bounded leaf subset keeps the triple enumeration useful and finite.
    let subset = &LEAVES[..10];
    let values: Vec<bool> = subset
        .iter()
        .map(|leaf| leaf_value(leaf, &context).expect("leaf evaluates"))
        .collect();
    for (a_index, &a) in subset.iter().enumerate() {
        for (b_index, &b) in subset.iter().enumerate() {
            for (c_index, &c) in subset.iter().enumerate() {
                let (av, bv, cv) = (values[a_index], values[b_index], values[c_index]);
                let forms: [(String, bool); 10] = [
                    (format!("{a} && {b} || {c}"), av && bv || cv),
                    (format!("{a} || {b} && {c}"), av || (bv && cv)),
                    (format!("{a} && {b} && {c}"), av && bv && cv),
                    (format!("{a} || {b} || {c}"), av || bv || cv),
                    (format!("{a} && ({b} || {c})"), av && (bv || cv)),
                    (format!("({a} || {b}) && {c}"), (av || bv) && cv),
                    (format!("{a} || ({b} && {c})"), av || (bv && cv)),
                    (format!("!({a} && {b}) || {c}"), !(av && bv) || cv),
                    (format!("{a} && !({b} || {c})"), av && !(bv || cv)),
                    (format!("!({a} || {b} && {c})"), !(av || (bv && cv))),
                ];
                for (source, expected) in forms {
                    assert_eq!(
                        compiled(&source).matches(&context),
                        Ok(expected),
                        "{source}"
                    );
                }
            }
        }
    }
}

/// A deterministic xorshift, so generated filters are reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

/// Generates a fully parenthesized expression and its expected value, so the
/// generated structure is exactly the parsed structure.
fn generated(rng: &mut Rng, leaves: &[(&str, bool)], depth: usize) -> (String, bool) {
    let leafish = depth == 0 || rng.below(3) == 0;
    if leafish {
        let (source, value) = leaves[rng.below(leaves.len())];
        return (source.to_owned(), value);
    }
    match rng.below(3) {
        0 => {
            let (inner, value) = generated(rng, leaves, depth - 1);
            (format!("!({inner})"), !value)
        }
        1 => {
            let (left, lv) = generated(rng, leaves, depth - 1);
            let (right, rv) = generated(rng, leaves, depth - 1);
            (format!("({left} && {right})"), lv && rv)
        }
        _ => {
            let (left, lv) = generated(rng, leaves, depth - 1);
            let (right, rv) = generated(rng, leaves, depth - 1);
            (format!("({left} || {right})"), lv || rv)
        }
    }
}

#[test]
fn seeded_deep_expressions_match_per_leaf_semantics() {
    let tunnelled = tunnelled();
    let ipv6_tcp = ipv6_tcp();
    let contexts: Vec<(&str, Context<'_>)> = vec![
        ("tunnelled", context(&tunnelled)),
        ("ipv6_tcp", context(&ipv6_tcp)),
    ];
    for (name, context) in &contexts {
        let leaves: Vec<(&str, bool)> = LEAVES
            .iter()
            .map(|leaf| {
                (
                    *leaf,
                    leaf_value(leaf, context)
                        .unwrap_or_else(|error| panic!("{leaf} on {name}: {error}")),
                )
            })
            .collect();
        let mut rng = Rng(0x9e3779b97f4a7c15);
        for case in 0..400 {
            let (source, expected) = generated(&mut rng, &leaves, 4);
            assert_eq!(
                compiled(&source).matches(context),
                Ok(expected),
                "generated case {case} on {name}: {source}"
            );
        }
    }
}

#[test]
fn parser_limits_long_chains_and_nested_not_hold() {
    // Term and nesting ceilings accept exactly at the limit and reject above.
    let at_terms = vec!["ipv4"; MAX_FILTER_TERMS].join(" && ");
    assert!(Filter::compile(&at_terms, &registry(), Options::default()).is_ok());
    let over_terms = vec!["ipv4"; MAX_FILTER_TERMS + 1].join(" && ");
    assert!(matches!(
        Filter::compile(&over_terms, &registry(), Options::default()),
        Err(Error::TermLimit { .. })
    ));
    let at_nesting = format!("{}ipv4{}", "(".repeat(64), ")".repeat(64));
    assert!(Filter::compile(&at_nesting, &registry(), Options::default()).is_ok());
    let over_nesting = format!("{}ipv4{}", "(".repeat(65), ")".repeat(65));
    assert!(matches!(
        Filter::compile(&over_nesting, &registry(), Options::default()),
        Err(Error::NestingLimit { .. })
    ));

    // Nested `!` chains: even count preserves the operand, odd inverts it.
    let tunnelled = tunnelled();
    for (count, expected) in [
        (1usize, false),
        (2, true),
        (3, false),
        (64, true),
        (65, false),
    ] {
        let source = format!("{}ipv4", "!".repeat(count));
        assert_eq!(
            compiled(&source).matches(&context(&tunnelled)),
            Ok(expected),
            "{count} negations"
        );
    }

    // A long chain of the same operator stays left-associative and correct.
    let ors = vec!["ipv6"; 500].join(" || ");
    assert_eq!(compiled(&ors).matches(&context(&tunnelled)), Ok(false));
    let mixed = format!("{} || ipv4", vec!["ipv6"; 500].join(" || "));
    assert_eq!(compiled(&mixed).matches(&context(&tunnelled)), Ok(true));

    for malformed in [
        "(",
        ")",
        "()",
        "&& ipv4",
        "ipv4 &&",
        "ipv4 ||| ipv4",
        "ipv4 &&& ipv4",
    ] {
        assert!(
            Filter::compile(malformed, &registry(), Options::default()).is_err(),
            "{malformed} must not compile"
        );
    }
}

#[test]
fn repeated_layers_occurrences_inequality_and_derived_packets_hold() {
    let tunnelled = tunnelled();
    // `!=` remains existential over every value a path reads.
    assert_on_all(
        "udp.dstport != 4789",
        true,
        &[("tunnelled", context(&tunnelled))],
    );
    assert_on_all(
        "!(udp.dstport != 4789) || udp#2.dstport == 9999",
        true,
        &[("tunnelled", context(&tunnelled))],
    );
    assert_on_all(
        "ipv4#1.source == 10.0.0.1 || ipv4#2.source == 10.0.0.1",
        true,
        &[("tunnelled", context(&tunnelled))],
    );

    // A derived datagram exposes only the layers its completion added: the
    // reconstructed base header repeats the physical one and stays hidden.
    let inner = layered(vec![
        Box::new(Ipv4 {
            source: "192.0.2.1".parse().expect("replayed source"),
            destination: "192.0.2.2".parse().expect("replayed destination"),
            ..Ipv4::default()
        }),
        Box::new(Udp {
            source_port: 5,
            destination_port: 9,
            ..Udp::default()
        }),
    ]);
    let physical = layered(vec![Box::new(Ipv4 {
        fragment_offset: 1480,
        more_fragments: true,
        ..Ipv4::default()
    })]);
    let context = Context {
        decoded: &physical,
        derived: &[DerivedPacket {
            decoded: &inner,
            replayed_prefix_layers: 1,
        }],
        number: 1,
        tcp_stream: None,
        udp_stream: Some(11),
    };
    // The UDP layer exists only on the derived packet; the suppressed ipv4
    // prefix means `ipv4.source` still reads the physical header's address.
    assert_eq!(
        compiled("udp.dstport == 9 && ipv4.source == 192.0.2.1").matches(&context),
        Ok(false)
    );
    assert_eq!(compiled("udp.dstport == 9").matches(&context), Ok(true));
    assert_eq!(
        compiled("ipv4.source == 192.0.2.1 || udp.dstport == 9").matches(&context),
        Ok(true)
    );
    assert_eq!(
        compiled("udp.stream == 11 && udp.dstport == 9").matches(&context),
        Ok(true)
    );
}

#[test]
fn missing_fields_and_flag_semantics_are_unchanged() {
    let ipv6_tcp = ipv6_tcp();
    let cases: &[(&str, bool)] = &[
        // Bare paths still ask presence; flags still read the bit.
        ("tcp.flags.fin", false),
        ("!tcp.flags.fin", true),
        ("tcp.flags.syn && !tcp.flags.fin", true),
        ("tcp.options", true),
        ("udp", false),
        ("udp.dstport", false),
        // `!=` against an absent field has no value to satisfy it.
        ("udp.dstport != 9999", false),
        ("!(udp.dstport)", true),
        // Slices keep byte semantics.
        ("ethernet.destination[0:3] == 00:00:00", true),
        ("ethernet.destination[1] == 0", true),
    ];
    for (source, expected) in cases {
        assert_eq!(
            compiled(source).matches(&context(&ipv6_tcp)),
            Ok(*expected),
            "{source}"
        );
    }
}

#[test]
fn projection_preserves_values_ordering_and_missing_columns() {
    let tunnelled = tunnelled();
    let dns = dns_layered();
    let ipv6_tcp = ipv6_tcp();

    // Repeated occurrences form an ordered list; a single value stays scalar;
    // a missing column is `None`; an empty container stays present-but-empty.
    let projection = Projection::compile(
        [
            "ipv4.source",
            "ipv4#2.source",
            "udp.dstport",
            "tcp.options",
            "ethernet.source[0:2]",
        ],
        &registry(),
    )
    .expect("projection compiles");
    let row = projection
        .values(&context(&tunnelled), usize::MAX)
        .expect("row within budget");
    assert_eq!(
        row,
        vec![
            Some(FieldValue::List(vec![
                FieldValue::Ipv4("192.0.2.1".parse().unwrap()),
                FieldValue::Ipv4("10.0.0.1".parse().unwrap()),
            ])),
            Some(FieldValue::Ipv4("10.0.0.1".parse().unwrap())),
            Some(FieldValue::List(vec![
                FieldValue::Unsigned(4_789),
                FieldValue::Unsigned(9_999),
            ])),
            None,
            // Both ethernet layers contribute, in packet order.
            Some(FieldValue::List(vec![
                FieldValue::Bytes(Bytes::from_static(&[0x06, 0x07])),
                FieldValue::Bytes(Bytes::from_static(&[0xaa, 0xbb])),
            ])),
        ]
    );

    // Nested paths select inside reflected containers without extra copies.
    let nested = Projection::compile(
        [
            "dns.questions[0].name",
            "dns.questions[1].name",
            "dns.answers[0].value.address",
            "dns.questions",
            "dns.answers[0].value.kind",
        ],
        &registry(),
    )
    .expect("nested projection compiles");
    let row = nested
        .values(&context(&dns), usize::MAX)
        .expect("nested row within budget");
    assert_eq!(row[0], Some(FieldValue::Text("example.test.".to_owned())));
    assert_eq!(
        row[1],
        Some(FieldValue::Text("sub.domain.example.".to_owned()))
    );
    assert_eq!(row[2], Some(FieldValue::Ipv4("192.0.2.8".parse().unwrap())));
    assert!(matches!(&row[3], Some(FieldValue::List(values)) if values.len() == 2));
    assert_eq!(row[4], Some(FieldValue::Text("a".to_owned())));

    // Missing columns interleave with present ones without disturbing order.
    let mixed = Projection::compile(["udp.dstport", "tcp.dstport", "frame.number"], &registry())
        .expect("mixed projection compiles");
    let row = mixed
        .values(&context(&ipv6_tcp), usize::MAX)
        .expect("mixed row within budget");
    assert_eq!(
        row,
        vec![
            None,
            Some(FieldValue::Unsigned(443)),
            Some(FieldValue::Unsigned(7))
        ]
    );
}

#[test]
fn projection_columns_name_each_path_with_its_typed_slice() {
    let columns = [
        "raw.bytes",
        "raw.bytes[0:1]",
        "ethernet.source[1]",
        "ipv4#2.source[2:]",
    ];
    let projection = Projection::compile(columns, &registry()).expect("projection compiles");
    assert_eq!(projection.columns(), columns);
}

#[test]
fn retained_projection_cells_release_large_source_allocations() {
    let backing = Bytes::from(vec![0x11; 65_536]);
    let mut dns = Dns::default();
    dns.edit(|dns| {
        dns.answers.push(Record {
            owner: "example.test.".parse().unwrap(),
            class: 1,
            ttl: 60,
            value: RecordValue::Txt(vec![backing.slice(4..8)]),
        });
    });
    let packet = layered(vec![Box::new(Raw::new(backing.slice(..4))), Box::new(dns)]);
    let projection = Projection::compile(["raw.bytes", "dns.answers"], &registry()).unwrap();
    let row = projection.values(&context(&packet), 4096).unwrap();
    drop(packet);
    assert_eq!(
        row[0],
        Some(FieldValue::Bytes(Bytes::from_static(&[0x11; 4])))
    );
    assert!(matches!(&row[1], Some(FieldValue::List(values)) if values.len() == 1));
    assert!(
        backing.is_unique(),
        "retained scalar and nested cells must release their backing frame"
    );
}

#[test]
fn projection_budget_is_enforced_at_exact_cell_boundaries() {
    let tunnelled = tunnelled();
    // `frame.number` = 7 renders as `7`: one byte. `ip.src` renders as two
    // quoted addresses joined into a list cell.
    let single = Projection::compile(["frame.number"], &registry()).expect("compiles");
    let tunnelled_context = context(&tunnelled);
    assert!(single.values(&tunnelled_context, 1).is_ok());
    assert!(matches!(
        single.values(&tunnelled_context, 0),
        Err(Error::ProjectionLimit { .. })
    ));

    // Two repeated IPv4 addresses: `"192.0.2.1"` is 11, `"10.0.0.1"` is 10,
    // and the list cell adds `len + 1` = 3 for brackets and the comma.
    let list = Projection::compile(["ipv4.source"], &registry()).expect("compiles");
    assert!(list.values(&tunnelled_context, 24).is_ok());
    assert!(matches!(
        list.values(&tunnelled_context, 23),
        Err(Error::ProjectionLimit { .. })
    ));

    // A missing column accounts for a `null` cell: exactly four bytes.
    let missing = Projection::compile(["tcp.dstport"], &registry()).expect("compiles");
    assert!(missing.values(&tunnelled_context, 4).is_ok());
    assert!(matches!(
        missing.values(&tunnelled_context, 3),
        Err(Error::ProjectionLimit { .. })
    ));

    // Escaped text counts escape bytes, not runes: `a"b\n` encodes as the
    // eight bytes `"a\"b\n"`.
    let text = layered(vec![Box::new(Malformed::new(
        None,
        Bytes::new(),
        "a\"b\n".to_owned(),
    ))]);
    let escaped = Projection::compile(["malformed.reason"], &registry()).expect("compiles");
    let row = escaped
        .values(&context(&text), 8)
        .expect("escaped text fits its exact size");
    assert_eq!(row, vec![Some(FieldValue::Text("a\"b\n".to_owned()))]);
    assert!(matches!(
        escaped.values(&context(&text), 7),
        Err(Error::ProjectionLimit { .. })
    ));

    // Raw bytes cost two hex digits each plus quotes.
    let bytes = layered(vec![Box::new(Raw::new(vec![0xab, 0xcd, 0xef]))]);
    let raw = Projection::compile(["raw.bytes"], &registry()).expect("compiles");
    assert!(raw.values(&context(&bytes), 8).is_ok());
    assert!(matches!(
        raw.values(&context(&bytes), 7),
        Err(Error::ProjectionLimit { .. })
    ));
}

#[test]
fn projection_values_match_rendered_cells_at_numeric_and_address_edges() {
    // frame.number can carry u64::MAX; frame.time_epoch on a pre-epoch frame
    // is a signed value; addresses render in canonical text form.
    let mut extreme = tunnelled();
    extreme.frame.timestamp = Some(UNIX_EPOCH - Duration::from_secs(1));
    let columns = [
        "frame.number",
        "frame.time_epoch",
        "ipv4.source",
        "ipv6.source",
        "ethernet.source",
        "raw.bytes[0:1]",
    ];
    let projection = Projection::compile(columns, &registry()).expect("compiles");
    let extreme_context = Context {
        number: u64::MAX,
        ..context(&extreme)
    };
    let row = projection
        .values(&extreme_context, usize::MAX)
        .expect("edge row within budget");
    assert_eq!(row[0], Some(FieldValue::Unsigned(u64::MAX)));
    assert_eq!(row[1], Some(FieldValue::Signed(-1)));
    assert_eq!(
        row[2],
        Some(FieldValue::List(vec![
            FieldValue::Ipv4("192.0.2.1".parse().unwrap()),
            FieldValue::Ipv4("10.0.0.1".parse().unwrap()),
        ]))
    );
    // No IPv6 layer on the tunnelled packet: a present-but-missing column.
    assert_eq!(row[3], None);
    assert_eq!(
        row[4],
        Some(FieldValue::List(vec![
            FieldValue::Mac([0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b]),
            FieldValue::Mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        ]))
    );
    assert_eq!(row[5], Some(FieldValue::Bytes(Bytes::from_static(b"G"))));

    // IPv6 addresses — including `::` elision — measure by the same display
    // form the cell writer emits.
    let v6 = ipv6_tcp();
    let v6_projection = Projection::compile(["ipv6.source", "ipv6.destination"], &registry())
        .expect("ipv6 projection compiles");
    let row = v6_projection
        .values(&context(&v6), usize::MAX)
        .expect("ipv6 row within budget");
    assert_eq!(
        row,
        vec![
            Some(FieldValue::Ipv6("2001:db8::1".parse().unwrap())),
            Some(FieldValue::Ipv6("2001:db8:1::2".parse().unwrap())),
        ]
    );
    // `"2001:db8::1"` is 13 bytes, `"2001:db8:1::2"` is 15: 28 total.
    assert!(v6_projection.values(&context(&v6), 28).is_ok());
    assert!(matches!(
        v6_projection.values(&context(&v6), 27),
        Err(Error::ProjectionLimit { .. })
    ));
}

/// Number of timed iterations per fixture: enough to drown out timer noise
/// without making the release-mode measurement slow.
const MEASURE_ITERS: u32 = 20_000;

fn measure<F>(label: &str, iterations: u32, mut run: F)
where
    F: FnMut() -> bool,
{
    for _ in 0..iterations / 10 {
        black_box(run());
    }
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(run());
    }
    let elapsed = start.elapsed();
    eprintln!(
        "{label}: {elapsed:?} over {iterations} iterations ({:?} each)",
        elapsed / iterations
    );
}

/// A packet whose payload scan is expensive enough to make a skipped
/// `contains` obvious: 64 KiB of payload without the needle. The layers are
/// assembled directly, since only the evaluator reads them and a UDP payload
/// this size could never sit on the wire.
fn measured_packet() -> DecodedPacket {
    layered(vec![
        Box::new(Ipv4::default()),
        Box::new(Udp::default()),
        Box::new(Raw::new(vec![0x41; 64 * 1024])),
    ])
}

#[test]
#[ignore = "measurement fixture; run with `cargo test --release -- --ignored`"]
fn perf_evaluation_short_circuit_and_full() {
    let decoded = measured_packet();
    let context = context(&decoded);
    for (label, source) in [
        // A decisively false guard: the 64 KiB needle scan is skipped.
        (
            "guard_false_short_circuits",
            "ipv6 && raw.bytes contains \"zzz\"",
        ),
        // A decisively true guard: same scan skipped through `||`.
        (
            "guard_true_short_circuits",
            "ipv4 || raw.bytes contains \"zzz\"",
        ),
        // An undecided guard: the scan still runs every packet.
        (
            "full_scan_when_undecided",
            "ipv4 && raw.bytes contains \"zzz\"",
        ),
        // Fully evaluated chain of three cheap predicates.
        (
            "fully_evaluated_chain",
            "ipv4 && udp.dstport == 53 && frame.number == 7",
        ),
        // Common case: a single predicate.
        ("single_predicate", "udp.dstport == 53"),
    ] {
        let filter = compiled(source);
        measure(label, MEASURE_ITERS, || {
            filter.matches(&context).expect("measurement evaluates")
        });
    }
}

#[test]
#[ignore = "measurement fixture; run with `cargo test --release -- --ignored`"]
fn perf_evaluation_max_size_program() {
    let decoded = measured_packet();
    let context = context(&decoded);
    // The largest legal program: 1024 terms, all evaluated on a match.
    let source = vec!["ipv4"; MAX_FILTER_TERMS].join(" || ");
    assert!(source.len() <= packetcraftr_core::filter::DEFAULT_MAX_FILTER_BYTES);
    let filter = compiled(&source);
    measure("max_terms_all_or", MEASURE_ITERS / 10, || {
        filter.matches(&context).expect("measurement evaluates")
    });
    // A mixed chain that ends decisively on the last term.
    let mixed = format!("{} && ipv4", vec!["ipv6"; 512].join(" || "));
    let filter = compiled(&mixed);
    measure("mixed_chain_decisive_end", MEASURE_ITERS / 10, || {
        filter.matches(&context).expect("measurement evaluates")
    });
}

#[test]
#[ignore = "measurement fixture; run with `cargo test --release -- --ignored`"]
fn perf_compile_cost() {
    let registry = registry();
    let max = vec!["ipv4"; MAX_FILTER_TERMS].join(" || ");
    let nested = format!("{}ipv4{}", "(".repeat(64), ")".repeat(64));
    let typical = "ipv4.source in 192.0.2.0/24 && tcp.dstport == 80 || udp.port in {53, 5353}";
    let start = Instant::now();
    for _ in 0..200 {
        black_box(Filter::compile(&max, &registry, Options::default()).expect("compiles"));
    }
    eprintln!(
        "compile_max_terms: {:?} over 200 compilations",
        start.elapsed()
    );
    let start = Instant::now();
    for _ in 0..2_000 {
        black_box(
            Filter::compile(nested.as_str(), &registry, Options::default()).expect("compiles"),
        );
        black_box(Filter::compile(typical, &registry, Options::default()).expect("compiles"));
    }
    eprintln!(
        "compile_typical_and_nested: {:?} over 4000 compilations",
        start.elapsed()
    );
}

#[test]
#[ignore = "measurement fixture; run with `cargo test --release -- --ignored`"]
fn perf_projection_nested_and_scalar() {
    let dns = dns_layered();
    let tunnelled = tunnelled();
    let nested = Projection::compile(
        [
            "dns.questions",
            "dns.answers",
            "dns.questions[0].name",
            "dns.answers[1].value.strings",
        ],
        &registry(),
    )
    .expect("nested projection compiles");
    let dns_context = context(&dns);
    measure("projection_nested", MEASURE_ITERS, || {
        nested.values(&dns_context, usize::MAX).is_ok()
    });

    let scalar = Projection::compile(
        [
            "frame.number",
            "frame.time_epoch",
            "ip.src",
            "ip.dst",
            "udp.srcport",
            "udp.dstport",
            "frame.len",
            "frame.interface_id",
        ],
        &registry(),
    )
    .expect("scalar projection compiles");
    let tunnelled_context = context(&tunnelled);
    measure("projection_scalar", MEASURE_ITERS, || {
        scalar.values(&tunnelled_context, usize::MAX).is_ok()
    });
}
