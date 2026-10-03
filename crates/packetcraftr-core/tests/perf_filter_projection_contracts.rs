// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

mod common;

use common::decoded::{context, tunnelled};
use common::registry;
use std::hint::black_box;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};

use bytes::Bytes;
use packetcraftr_core::decode::DecodedPacket;
use packetcraftr_core::field::{self, FieldValue};
use packetcraftr_core::filter::{Context, Error, Filter, Limits, MAX_FILTER_TERMS, Projection};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::{Layer, Malformed, Raw, Schema};
use packetcraftr_core::layout::PacketLayout;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::application::dns::{Dns, Question, Record, RecordValue};
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::{Tcp, Udp};

fn layered(layers: Vec<Box<dyn Layer>>) -> DecodedPacket {
    let mut packet = Packet::new();
    for layer in layers {
        packet.push_boxed(layer);
    }
    DecodedPacket {
        packet,
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

fn compiled(source: &str) -> Filter {
    Filter::compile(source, &registry(), Limits::default())
        .unwrap_or_else(|error| panic!("{source} must compile: {error}"))
}

fn leaf_value(source: &str, context: &Context<'_>) -> Result<bool, Error> {
    compiled(source).matches(context)
}

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
fn missing_timestamp_fails_the_whole_filter_before_any_short_circuit() {
    let mut undated = tunnelled();
    undated.frame.timestamp = None;
    for source in [
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
    for (source, expected) in [
        ("frame.number == 999 && frame.time_epoch == 0", false),
        ("udp.dstport == 9999 || frame.time_epoch == 0", true),
        ("frame.time_epoch == 123", true),
        ("frame.number == 7 || (frame.time_epoch == 0 && udp)", true),
    ] {
        assert_eq!(
            compiled(source).matches(&context(&tunnelled())).ok(),
            Some(expected),
            "{source}"
        );
    }
}

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

fn assert_on_all(source: &str, expected: bool, contexts: &[(&str, Context<'_>)]) {
    let filter = compiled(source);
    for (name, context) in contexts {
        assert_eq!(
            filter.matches(context).ok(),
            Some(expected),
            "{source} on {name}"
        );
    }
}

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
fn parser_limits_long_chains_and_nested_not_hold() {
    let at_terms = vec!["ipv4"; MAX_FILTER_TERMS].join(" && ");
    assert!(Filter::compile(&at_terms, &registry(), Limits::default()).is_ok());
    let over_terms = vec!["ipv4"; MAX_FILTER_TERMS + 1].join(" && ");
    assert!(matches!(
        Filter::compile(&over_terms, &registry(), Limits::default()),
        Err(Error::TermLimit { .. })
    ));
    let at_nesting = format!("{}ipv4{}", "(".repeat(64), ")".repeat(64));
    assert!(Filter::compile(&at_nesting, &registry(), Limits::default()).is_ok());
    let over_nesting = format!("{}ipv4{}", "(".repeat(65), ")".repeat(65));
    assert!(matches!(
        Filter::compile(&over_nesting, &registry(), Limits::default()),
        Err(Error::NestingLimit { .. })
    ));

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
            compiled(&source).matches(&context(&tunnelled)).ok(),
            Some(expected),
            "{count} negations"
        );
    }

    let ors = vec!["ipv6"; 500].join(" || ");
    assert_eq!(
        compiled(&ors).matches(&context(&tunnelled)).ok(),
        Some(false)
    );
    let mixed = format!("{} || ipv4", vec!["ipv6"; 500].join(" || "));
    assert_eq!(
        compiled(&mixed).matches(&context(&tunnelled)).ok(),
        Some(true)
    );

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
            Filter::compile(malformed, &registry(), Limits::default()).is_err(),
            "{malformed} must not compile"
        );
    }
}

#[test]
fn projection_budget_is_enforced_at_exact_cell_boundaries() {
    let tunnelled = tunnelled();
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

fn measured_packet() -> DecodedPacket {
    layered(vec![
        Box::new(Ipv4::default()),
        Box::new(Udp::default()),
        Box::new(Raw::new(vec![0x41; 64 * 1024])),
    ])
}
