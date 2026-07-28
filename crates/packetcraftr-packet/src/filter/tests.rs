// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use packetcraftr_capture::{Frame, LinkType};

use super::super::Packet;
use super::super::codec::{
    CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext,
};
use super::super::decode::DecodedPacket;
use super::super::field::FieldValue;
use super::super::layer::{Id as ProtocolId, Layer, Padding, Raw};
use super::super::layout::PacketLayout;
use super::super::registry::{FilterFieldBinding, Registry};
use super::*;

/// The packet crate registers no protocol codecs of its own, so these fixtures
/// register the two layers it does define. `raw` supplies a byte field and
/// `padding` supplies both a number and an optional field, which between them
/// exercise every projection the evaluator performs. Protocol-specific
/// coverage lives beside the built-in catalog in `packetcraftr-protocol`.
macro_rules! fixture_codec {
    ($codec:ident, $layer:ty, $protocol:literal) => {
        #[derive(Debug)]
        struct $codec;

        impl LayerCodec for $codec {
            fn protocol_id(&self) -> ProtocolId {
                ProtocolId::new($protocol)
            }

            fn encode(
                &self,
                _layer: &dyn Layer,
                _payload: &[u8],
                _context: &LayerEncodeContext<'_>,
            ) -> Result<EncodedLayer, CodecError> {
                Err(CodecError::Unsupported {
                    protocol: self.protocol_id(),
                    message: "filter fixtures never build wire bytes".to_owned(),
                })
            }

            fn decode(
                &self,
                _input: &[u8],
                _context: &LayerDecodeContext<'_>,
            ) -> Result<DecodedLayerValue, CodecError> {
                Err(CodecError::Unsupported {
                    protocol: self.protocol_id(),
                    message: "filter fixtures never decode wire bytes".to_owned(),
                })
            }

            fn make_layer(
                &self,
                fields: &BTreeMap<String, FieldValue>,
            ) -> Result<Box<dyn Layer>, CodecError> {
                let mut layer = <$layer>::default();
                for (name, value) in fields {
                    layer.set_field(name, value.clone())?;
                }
                Ok(Box::new(layer))
            }
        }
    };
}

fixture_codec!(RawCodec, Raw, "raw");
fixture_codec!(PaddingCodec, Padding, "padding");
fixture_codec!(EndpointCodec, Endpoint, "endpoint");

/// A fixture layer carrying the address and text kinds the two real in-crate
/// layers do not, so prefix membership and text comparison are covered here
/// rather than only against the built-in catalog.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Endpoint {
    source: std::net::Ipv4Addr,
    target: std::net::Ipv6Addr,
    label: String,
}

impl Default for Endpoint {
    fn default() -> Self {
        Self {
            source: std::net::Ipv4Addr::UNSPECIFIED,
            target: std::net::Ipv6Addr::UNSPECIFIED,
            label: String::new(),
        }
    }
}

fn endpoint_schema() -> &'static crate::layer::Schema {
    static SCHEMA: std::sync::OnceLock<crate::layer::Schema> = std::sync::OnceLock::new();
    static FIELDS: &[crate::field::Schema] = &[
        crate::field::Schema {
            name: "source",
            kind: crate::field::Kind::Ipv4,
            derived: false,
            required: true,
            description: "Fixture IPv4 endpoint",
        },
        crate::field::Schema {
            name: "target",
            kind: crate::field::Kind::Ipv6,
            derived: false,
            required: true,
            description: "Fixture IPv6 endpoint",
        },
        crate::field::Schema {
            name: "label",
            kind: crate::field::Kind::Text,
            derived: false,
            required: false,
            description: "Fixture text label",
        },
    ];
    SCHEMA.get_or_init(|| crate::layer::Schema {
        protocol: ProtocolId::new("endpoint"),
        name: "Endpoint",
        fields: FIELDS,
    })
}

impl Layer for Endpoint {
    fn schema(&self) -> &'static crate::layer::Schema {
        endpoint_schema()
    }

    fn clone_box(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn field(&self, name: &str) -> Option<FieldValue> {
        match name {
            "source" => Some(FieldValue::Ipv4(self.source)),
            "target" => Some(FieldValue::Ipv6(self.target)),
            "label" => Some(FieldValue::Text(self.label.clone())),
            _ => None,
        }
    }

    fn set_field(&mut self, name: &str, value: FieldValue) -> Result<(), crate::field::Error> {
        match (name, value) {
            ("source", FieldValue::Ipv4(value)) => self.source = value,
            ("target", FieldValue::Ipv6(value)) => self.target = value,
            ("label", FieldValue::Text(value)) => self.label = value,
            (_, _) => {
                return Err(crate::field::Error::UnknownField {
                    protocol: endpoint_schema().protocol.clone(),
                    field: name.to_owned(),
                });
            }
        }
        Ok(())
    }
}

fn empty_registry() -> Registry {
    Registry::builder()
        .build()
        .expect("an empty registry always builds")
}

/// A registry carrying the two fixture layers plus filter spellings that
/// exercise each binding shape.
fn fixture_registry() -> Registry {
    let mut builder = Registry::builder();
    builder.register_codec(RawCodec).unwrap();
    builder.register_codec(PaddingCodec).unwrap();
    builder.register_codec(EndpointCodec).unwrap();
    builder
        .bind_filter_field(
            "pad.tail",
            FilterFieldBinding::Direct {
                protocol: ProtocolId::new("padding"),
                field: "bytes",
            },
        )
        .unwrap();
    builder
        .bind_filter_field(
            "pad.layer.low",
            FilterFieldBinding::Bits {
                protocol: ProtocolId::new("padding"),
                field: "outside_layer",
                mask: 0x0f,
                shift: 0,
            },
        )
        .unwrap();
    builder
        .bind_filter_field(
            "any.bytes",
            FilterFieldBinding::Either {
                protocol: ProtocolId::new("padding"),
                fields: &["bytes", "outside_layer"],
            },
        )
        .unwrap();
    builder.build().expect("fixture registry builds")
}

fn compile(source: &str) -> Result<Filter, Error> {
    Filter::compile(source, &empty_registry(), Options::default())
}

fn compile_fixture(source: &str) -> Filter {
    Filter::compile(source, &fixture_registry(), Options::default())
        .unwrap_or_else(|error| panic!("{source} should compile, got {error:?}"))
}

/// Wraps a packet in the minimum decoded context the evaluator reads.
fn decoded(packet: Packet, bytes: &[u8]) -> DecodedPacket {
    let payload = Bytes::copy_from_slice(bytes);
    let mut frame = Frame::new(
        UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        LinkType::ETHERNET,
        payload.clone(),
    )
    .expect("fixture frame is consistent");
    frame.interface = Some(3);
    DecodedPacket {
        packet,
        original: payload,
        frame,
        layout: PacketLayout { layers: Vec::new() },
        diagnostics: Vec::new(),
    }
}

fn matches(source: &str, decoded: &DecodedPacket) -> bool {
    compile_fixture(source).matches(&Context {
        decoded,
        number: 7,
        tcp_stream: None,
        udp_stream: None,
    })
}

#[test]
fn an_empty_filter_is_rejected() {
    assert!(matches!(compile(""), Err(Error::Empty)));
    assert!(matches!(compile("   \t "), Err(Error::Empty)));
}

#[test]
fn source_longer_than_the_byte_limit_is_rejected_before_parsing() {
    let options = Options {
        max_bytes: 8,
        ..Options::default()
    };
    let error =
        Filter::compile("aaaaaaaaaaaaaaaa", &empty_registry(), options.clone()).unwrap_err();
    assert!(matches!(
        error,
        Error::SizeLimit {
            actual: 16,
            limit: 8
        }
    ));

    // The bound is checked before anything scans the source, so oversized
    // whitespace is refused on length rather than examined and called empty.
    let error = Filter::compile("                ", &empty_registry(), options).unwrap_err();
    assert!(matches!(error, Error::SizeLimit { .. }));
}

#[test]
fn nesting_beyond_the_limit_is_rejected() {
    let options = Options {
        max_nesting: 4,
        ..Options::default()
    };
    let source = "(((((frame.len)))))";
    let error = Filter::compile(source, &empty_registry(), options).unwrap_err();
    assert!(matches!(error, Error::NestingLimit { limit: 4 }));
}

#[test]
fn a_nesting_limit_above_the_stable_maximum_is_rejected() {
    let options = Options {
        max_nesting: MAX_FILTER_NESTING + 1,
        ..Options::default()
    };
    let error = Filter::compile("frame.len", &empty_registry(), options).unwrap_err();
    assert!(matches!(error, Error::InvalidNestingLimit { .. }));
}

#[test]
fn more_terms_than_the_limit_are_rejected() {
    let options = Options {
        max_terms: 2,
        ..Options::default()
    };
    let source = "frame.len && frame.cap_len && frame.number";
    let error = Filter::compile(source, &empty_registry(), options).unwrap_err();
    assert!(matches!(error, Error::TermLimit { limit: 2 }));
}

#[test]
fn a_set_larger_than_the_limit_is_rejected() {
    let options = Options {
        max_set_members: 2,
        ..Options::default()
    };
    let source = "frame.len in {1, 2, 3}";
    let error = Filter::compile(source, &empty_registry(), options).unwrap_err();
    assert!(matches!(error, Error::SetMemberLimit { limit: 2 }));
}

#[test]
fn limits_above_the_stable_maxima_are_rejected_as_invalid_options() {
    let terms = Options {
        max_terms: MAX_FILTER_TERMS + 1,
        ..Options::default()
    };
    assert!(matches!(
        Filter::compile("frame.len", &empty_registry(), terms),
        Err(Error::InvalidTermLimit { .. })
    ));

    let members = Options {
        max_set_members: MAX_FILTER_SET_MEMBERS + 1,
        ..Options::default()
    };
    assert!(matches!(
        Filter::compile("frame.len", &empty_registry(), members),
        Err(Error::InvalidSetMemberLimit { .. })
    ));
}

#[test]
fn unbalanced_parentheses_are_reported_with_an_offset() {
    assert!(matches!(compile("(frame.len"), Err(Error::Syntax { .. })));
    assert!(matches!(compile("frame.len)"), Err(Error::Syntax { .. })));
}

#[test]
fn a_dangling_operator_is_a_syntax_error() {
    assert!(matches!(compile("frame.len &&"), Err(Error::Syntax { .. })));
    assert!(matches!(compile("&& frame.len"), Err(Error::Syntax { .. })));
    assert!(matches!(compile("frame.len =="), Err(Error::Syntax { .. })));
}

#[test]
fn a_single_ampersand_or_equals_is_rejected_rather_than_guessed() {
    assert!(matches!(
        compile("frame.len & 1"),
        Err(Error::Syntax { .. })
    ));
    assert!(matches!(
        compile("frame.len = 1"),
        Err(Error::Syntax { .. })
    ));
}

#[test]
fn an_unknown_field_names_the_path_that_failed() {
    let error = compile("frame.nonexistent").unwrap_err();
    match error {
        Error::UnknownField { path, .. } => assert_eq!(path, "frame.nonexistent"),
        other => panic!("expected an unknown field, got {other:?}"),
    }
}

#[test]
fn an_unregistered_protocol_is_an_unknown_field() {
    assert!(matches!(compile("tcp"), Err(Error::UnknownField { .. })));
    assert!(matches!(
        compile("tcp.destination_port == 443"),
        Err(Error::UnknownField { .. })
    ));
}

#[test]
fn synthetic_frame_fields_resolve_without_any_registered_protocol() {
    for path in [
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "frame.cap_len",
        "frame.interface_id",
        "frame.link_type",
    ] {
        compile(path).unwrap_or_else(|error| panic!("{path} should compile, got {error:?}"));
    }
}

#[test]
fn stream_paths_are_reserved_and_declare_their_requirement() {
    for path in ["tcp.stream", "udp.stream"] {
        let filter = compile(path).expect("stream paths resolve without a registry");
        assert!(
            filter.requirements().stream_index,
            "{path} must declare that it needs a stream index"
        );
    }
    let plain = compile("frame.len").unwrap();
    assert!(!plain.requirements().stream_index);
}

#[test]
fn a_layer_occurrence_must_be_a_positive_number_on_the_protocol() {
    assert!(matches!(compile("frame#0.len"), Err(Error::Syntax { .. })));
    assert!(matches!(compile("frame#x.len"), Err(Error::Syntax { .. })));
    // The selector belongs to the protocol segment, never a later one.
    assert!(matches!(compile("frame.len#2"), Err(Error::Syntax { .. })));
}

#[test]
fn synthetic_fields_have_no_occurrences_to_select() {
    // These are per-frame and per-conversation facts, not layers, so an
    // occurrence on them is a typo rather than a narrower selection.
    assert!(matches!(compile("frame#2.len"), Err(Error::Syntax { .. })));
    assert!(matches!(compile("tcp#2.stream"), Err(Error::Syntax { .. })));
    assert!(matches!(compile("udp#1.stream"), Err(Error::Syntax { .. })));
    // The unqualified spellings still resolve.
    compile("frame.len").expect("frame.len resolves");
    compile("tcp.stream").expect("tcp.stream resolves");
}

#[test]
fn a_literal_that_could_never_match_the_field_is_rejected() {
    let error = compile("frame.len == 10.0.0.1").unwrap_err();
    match error {
        Error::IncompatibleLiteral { path, .. } => assert_eq!(path, "frame.len"),
        other => panic!("expected an incompatible literal, got {other:?}"),
    }
}

#[test]
fn synthetic_fields_cannot_be_sliced() {
    assert!(matches!(
        compile("frame.len[0:2] == 00:01"),
        Err(Error::UnsliceableField { .. })
    ));
}

#[test]
fn contains_is_rejected_where_it_could_never_search() {
    let compile_fixture_result =
        |source: &str| Filter::compile(source, &fixture_registry(), Options::default());

    // A number is not a byte haystack.
    assert!(matches!(
        compile_fixture_result("padding.outside_layer contains 01"),
        Err(Error::IncompatibleLiteral { .. })
    ));
    // A prefix is not a byte needle.
    assert!(matches!(
        compile_fixture_result("raw.bytes contains 10.0.0.0/8"),
        Err(Error::IncompatibleLiteral { .. })
    ));
    // A bare number is an ambiguous needle — decimal or a single byte? — so it
    // is refused rather than guessed at.
    assert!(matches!(
        compile_fixture_result("raw.bytes contains 47"),
        Err(Error::IncompatibleLiteral { .. })
    ));
    // Slicing narrows a field to bytes, so it stays searchable.
    compile_fixture_result("raw.bytes[0:2] contains 47:45").expect("sliced bytes are searchable");
    compile_fixture_result("raw.bytes[0:2] contains \"GE\"")
        .expect("quoted text is an unambiguous needle");
}

#[test]
fn unquoted_text_is_rejected_against_a_field_that_is_never_text() {
    // `frame.len` is a plain number, so a bareword can only be a typo.
    assert!(matches!(
        compile("frame.len == nope"),
        Err(Error::IncompatibleLiteral { .. })
    ));
    assert!(matches!(
        compile("frame.len == auto"),
        Err(Error::IncompatibleLiteral { .. })
    ));
    // A non-derived numeric layer field behaves the same way.
    assert!(matches!(
        Filter::compile(
            "padding.outside_layer == auto",
            &fixture_registry(),
            Options::default()
        ),
        Err(Error::IncompatibleLiteral { .. })
    ));
}

#[test]
fn a_single_byte_slice_compares_against_a_plain_number() {
    let packet = sample();
    // A bare `47` would read as ambiguously decimal or hexadecimal, so a
    // one-byte slice is written as a number instead.
    assert!(matches("raw.bytes[0:1] == 0x47", &packet));
    assert!(matches("raw.bytes[0:1] == 71", &packet));
    assert!(!matches("raw.bytes[0:1] == 0x45", &packet));
    // A multi-byte value has no numeric reading, so it simply does not match.
    assert!(!matches("raw.bytes[0:2] == 71", &packet));
}

#[test]
fn a_set_member_limit_above_the_stable_maximum_is_rejected() {
    let options = Options {
        max_set_members: MAX_FILTER_SET_MEMBERS + 1,
        ..Options::default()
    };
    let error = Filter::compile("frame.len in {1}", &empty_registry(), options).unwrap_err();
    assert!(matches!(
        error,
        Error::InvalidSetMemberLimit {
            value,
            maximum: MAX_FILTER_SET_MEMBERS
        } if value == MAX_FILTER_SET_MEMBERS + 1
    ));
}

#[test]
fn a_term_limit_above_the_stable_maximum_is_rejected() {
    let options = Options {
        max_terms: MAX_FILTER_TERMS + 1,
        ..Options::default()
    };
    let error = Filter::compile("frame.len", &empty_registry(), options).unwrap_err();
    assert!(matches!(
        error,
        Error::InvalidTermLimit {
            value,
            maximum: MAX_FILTER_TERMS
        } if value == MAX_FILTER_TERMS + 1
    ));
}

#[test]
fn a_prefix_can_only_be_tested_for_membership() {
    // A prefix names a set, so ordering one would evaluate false for every
    // packet. That must be reported rather than silently filtering everything.
    for source in [
        "endpoint.source > 10.0.0.0/8",
        "endpoint.source <= 10.0.0.0/8",
        "endpoint.target >= 2001:db8::/32",
    ] {
        let error =
            Filter::compile(source, &fixture_registry(), Options::default()).expect_err(source);
        assert!(
            matches!(error, Error::OrderedPrefixComparison { .. }),
            "{source} should report an ordered prefix, got {error:?}"
        );
    }
    // Membership spellings stay available.
    Filter::compile(
        "endpoint.source == 10.0.0.0/8",
        &fixture_registry(),
        Options::default(),
    )
    .expect("equality against a prefix is containment");
    Filter::compile(
        "endpoint.source in 10.0.0.0/8",
        &fixture_registry(),
        Options::default(),
    )
    .expect("`in` against a prefix is containment");
}

#[test]
fn addresses_match_by_value_and_by_prefix() {
    let mut packet = Packet::new();
    packet.push(Endpoint {
        source: std::net::Ipv4Addr::new(10, 1, 2, 3),
        target: "2001:db8::5".parse().expect("fixture address"),
        label: "edge-router".to_owned(),
    });
    let record = decoded(packet, &[]);

    assert!(matches("endpoint.source == 10.1.2.3", &record));
    assert!(matches("endpoint.source == 10.0.0.0/8", &record));
    assert!(matches("endpoint.source in 10.0.0.0/8", &record));
    assert!(!matches("endpoint.source == 192.168.0.0/16", &record));
    assert!(matches("endpoint.source != 192.168.0.0/16", &record));
    // A /0 prefix contains everything, and a /32 is an exact address.
    assert!(matches("endpoint.source == 0.0.0.0/0", &record));
    assert!(matches("endpoint.source == 10.1.2.3/32", &record));
    assert!(!matches("endpoint.source == 10.1.2.4/32", &record));

    assert!(matches("endpoint.target == 2001:db8::5", &record));
    assert!(matches("endpoint.target in 2001:db8::/32", &record));
    assert!(!matches("endpoint.target in 2001:db9::/32", &record));

    // Addresses order, so a range test works too.
    assert!(matches("endpoint.source > 10.1.2.2", &record));
    assert!(matches("endpoint.source < 10.1.2.4", &record));

    // Text compares and searches.
    assert!(matches("endpoint.label == \"edge-router\"", &record));
    assert!(matches("endpoint.label contains \"router\"", &record));
    assert!(!matches("endpoint.label contains \"switch\"", &record));

    // An address slices to its octets.
    assert!(matches("endpoint.source[0:2] == 0a:01", &record));
}

#[test]
fn a_numeric_field_cannot_be_sliced() {
    // `outside_layer` is unsigned, and a number has no byte projection. The
    // slice must be refused rather than compiling into a filter that silently
    // matches nothing.
    let error = Filter::compile(
        "padding.outside_layer[0:1] == 00",
        &fixture_registry(),
        Options::default(),
    )
    .unwrap_err();
    assert!(matches!(error, Error::UnsliceableField { .. }));

    // The same holds for a bit binding, whose value is also a number.
    let error = Filter::compile(
        "pad.layer.low[0:1] == 00",
        &fixture_registry(),
        Options::default(),
    )
    .unwrap_err();
    assert!(matches!(error, Error::UnsliceableField { .. }));

    // A byte field slices normally.
    Filter::compile(
        "padding.bytes[0:1] == aa",
        &fixture_registry(),
        Options::default(),
    )
    .expect("byte fields are sliceable");
}

#[test]
fn a_reversed_byte_slice_is_rejected() {
    let error = Filter::compile(
        "padding.bytes[4:2] == aa",
        &fixture_registry(),
        Options::default(),
    )
    .expect_err("a reversed slice has no meaning");
    assert!(matches!(error, Error::Syntax { .. }), "{error:?}");
}

#[test]
fn unterminated_quotes_and_slices_are_syntax_errors() {
    assert!(matches!(
        compile("frame.len == \"open"),
        Err(Error::Syntax { .. })
    ));
    assert!(matches!(
        compile("frame.len[0:2"),
        Err(Error::Syntax { .. })
    ));
}

#[test]
fn deeply_nested_source_does_not_exhaust_the_parser_stack() {
    // Well within the configured bound, but deep enough that a recursive
    // descent parser would be visible in a stack profile.
    let depth = MAX_FILTER_NESTING;
    let source = format!("{}frame.len{}", "(".repeat(depth), ")".repeat(depth));
    compile(&source).expect("nesting at the limit compiles");

    let too_deep = format!(
        "{}frame.len{}",
        "(".repeat(depth + 1),
        ")".repeat(depth + 1)
    );
    assert!(matches!(
        compile(&too_deep),
        Err(Error::NestingLimit { .. })
    ));
}

// --- evaluation ------------------------------------------------------------

fn sample() -> DecodedPacket {
    let mut packet = Packet::new();
    packet
        .push(Raw::new(vec![0x47, 0x45, 0x54, 0x20]))
        .push(Padding::after_layer(vec![0xaa, 0xbb], 5))
        .push(Raw::new(vec![0x01, 0x02]));
    decoded(packet, &[0x47, 0x45, 0x54, 0x20, 0xaa, 0xbb, 0x01, 0x02])
}

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
