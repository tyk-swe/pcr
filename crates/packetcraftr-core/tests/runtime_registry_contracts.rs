// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Contracts for registry queries, build/decode bounds, and binding conflicts.

mod common;

use bytes::Bytes;
use common::probe::{
    Child, ChildCodec, PROBE_LINK_TYPE, Probe, ProbeCodec, probe_registry, structure,
};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::{Layer, Malformed, Padding, Raw, raw_layout};
use packetcraftr_core::layout::ByteRange;
use packetcraftr_core::protocol::{
    builtin,
    link::{Ethernet, Vlan},
    network::Ipv4,
    transport::Udp,
};
use packetcraftr_core::registry::{Discriminator, FilterFieldBinding};
use packetcraftr_core::{build, codec, decode, packet::Packet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

fn decode_probe(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    bytes: impl Into<Bytes>,
    options: decode::Options,
) -> Result<decode::DecodedPacket, decode::Error> {
    let frame = Frame::new(SystemTime::UNIX_EPOCH, PROBE_LINK_TYPE, bytes)?;
    decode::Dissector::new(Arc::clone(registry)).decode(frame, options)
}

fn assert_registry_queries(registry: &packetcraftr_core::registry::Registry) {
    assert_eq!(
        registry
            .protocol_named(" P ")
            .map(packetcraftr_core::layer::Id::as_str),
        Some("probe")
    );
    assert!(registry.codec_named("P").is_some());
    assert_eq!(
        registry
            .root_for_link_type(LinkType(777))
            .map(packetcraftr_core::layer::Id::as_str),
        Some("probe")
    );
    assert_eq!(
        registry
            .child_for("probe", Discriminator(7))
            .map(packetcraftr_core::layer::Id::as_str),
        Some("child")
    );
    assert_eq!(
        registry.discriminator_for("probe", "child"),
        Some(Discriminator(7))
    );
    assert_eq!(registry.protocols().len(), 2);
}

fn build_and_decode_probe(
    registry: &Arc<packetcraftr_core::registry::Registry>,
) -> (build::Builder, decode::DecodedPacket) {
    let mut packet = Packet::new();
    packet.push(Probe {
        value: 9,
        ..Probe::default()
    });
    packet.push(Child { value: 4 });
    let builder = build::Builder::new(Arc::clone(registry));
    let built = builder
        .build(packet, codec::Context::default(), build::Options::default())
        .expect("bound packet builds");
    assert_eq!(built.bytes.as_ref(), &[9, 4]);
    assert_eq!(built.layout.layers.len(), 2);
    assert_eq!(
        built.layout.layer(1).expect("child layout").range,
        ByteRange::new(1, 2)
    );
    assert_eq!(built.packet.encoded_payload_length(0), Some(1));
    assert_eq!(built.packet.encoded_payload_length(1), Some(0));
    assert_eq!(built.diagnostics[0].layer, Some(0));

    let decoded = decode_probe(registry, built.bytes.clone(), decode::Options::default())
        .expect("bound packet decodes");
    assert_eq!(decoded.packet.len(), 2);
    assert_eq!(decoded.original.as_ref(), &[9, 4]);
    assert_eq!(decoded.layout.layers.len(), 2);
    assert_eq!(decoded.packet.encoded_payload_length(0), Some(1));
    assert_eq!(decoded.packet.encoded_payload_length(1), Some(0));
    assert_eq!(decoded.diagnostics.len(), 1);
    (builder, decoded)
}

fn assert_failed_packet_lookups(decoded: decode::DecodedPacket) {
    let before_failed_lookups = decoded.packet.clone();
    let mut failed_lookups = decoded.packet;
    assert!(failed_lookups.get_mut::<Raw>().is_none());
    assert!(failed_lookups.layer_mut(99).is_none());
    assert!(matches!(
        failed_lookups.insert(99, Probe::default()),
        Err(packetcraftr_core::packet::Error::IndexOutOfBounds { index: 99, len: 2 })
    ));
    assert!(matches!(
        failed_lookups.replace(99, Probe::default()),
        Err(packetcraftr_core::packet::Error::IndexOutOfBounds { index: 99, len: 2 })
    ));
    assert!(matches!(
        failed_lookups.remove(99),
        Err(packetcraftr_core::packet::Error::IndexOutOfBounds { index: 99, len: 2 })
    ));
    assert_eq!(
        structure(&failed_lookups),
        structure(&before_failed_lookups)
    );
    assert_eq!(
        failed_lookups.encoded_payload_length(0),
        before_failed_lookups.encoded_payload_length(0)
    );
    assert_eq!(
        failed_lookups.encoded_payload_length(1),
        before_failed_lookups.encoded_payload_length(1)
    );
}

fn assert_root_decode_behavior(registry: &Arc<packetcraftr_core::registry::Registry>) {
    let frame = Frame::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(5),
        LinkType(777),
        vec![7, 3],
    )
    .expect("frame");
    assert_eq!(
        decode::Dissector::new(Arc::clone(registry))
            .decode(frame, decode::Options::default())
            .expect("root lookup")
            .packet
            .len(),
        2
    );
    let unsupported = Frame::new(SystemTime::UNIX_EPOCH, LinkType(778), vec![1, 2]).expect("frame");
    let raw = decode::Dissector::new(Arc::clone(registry))
        .decode(unsupported, decode::Options::default())
        .expect("unsupported roots become raw packets");
    assert_eq!(
        raw.packet.get::<Raw>().map(|raw| raw.bytes.as_ref()),
        Some(&[1, 2][..])
    );
    assert_eq!(raw.packet.encoded_payload_length(0), Some(0));
    assert_eq!(raw.layout.layers.len(), 1);
    assert_eq!(raw.layout.layers[0].range, ByteRange::new(0, 2));
    assert_eq!(raw.layout.layers[0].fields, raw_layout(2));
    assert_eq!(raw.diagnostics[0].code, "decode.unsupported_link_type");
}

fn assert_build_decode_limits(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    builder: &build::Builder,
) {
    assert!(matches!(
        builder.build(
            Packet::new(),
            codec::Context::default(),
            build::Options::default()
        ),
        Err(build::Error::EmptyPacket)
    ));
    let mut one = Packet::new();
    one.push(Probe::default());
    assert!(matches!(
        builder.build(
            one.clone(),
            codec::Context::default(),
            build::Options {
                max_layers: 0,
                ..build::Options::default()
            },
        ),
        Err(build::Error::LayerLimit {
            actual: 1,
            limit: 0
        })
    ));
    assert!(matches!(
        builder.build(
            one,
            codec::Context::default(),
            build::Options {
                max_packet_size: 0,
                ..build::Options::default()
            },
        ),
        Err(build::Error::PacketSizeLimit { .. })
    ));
    assert!(matches!(
        decode_probe(
            registry,
            vec![1],
            decode::Options {
                max_layers: 0,
                ..decode::Options::default()
            },
        ),
        Err(decode::Error::LayerLimit { limit: 0 })
    ));
    assert!(matches!(
        decode_probe(
            registry,
            vec![1, 2],
            decode::Options {
                max_packet_size: 1,
                ..decode::Options::default()
            },
        ),
        Err(decode::Error::PacketSizeLimit { .. })
    ));
    let malformed = decode_probe(registry, Vec::<u8>::new(), decode::Options::default())
        .expect("codec errors are preserved as malformed layers");
    assert!(malformed.packet.get::<Malformed>().is_some());
    assert_eq!(malformed.diagnostics[0].code, "decode.malformed_layer");
}

#[test]
fn registry_build_decode_and_error_paths_are_bounded() {
    let registry = Arc::new(probe_registry());
    assert_registry_queries(&registry);
    let (builder, decoded) = build_and_decode_probe(&registry);

    assert_failed_packet_lookups(decoded);
    assert_root_decode_behavior(&registry);
    assert_build_decode_limits(&registry, &builder);
}

#[test]
fn an_unbound_child_discriminator_is_attributed_to_its_parent_layer() {
    let mut builder = packetcraftr_core::registry::Builder::new();
    builder.register_codec(ProbeCodec, &["p"]).expect("probe");
    builder
        .bind_link_type(PROBE_LINK_TYPE, "probe")
        .expect("bind root");
    let registry = Arc::new(builder.build().expect("registry without a child binding"));

    let decoded = decode_probe(&registry, vec![7, 3], decode::Options::default())
        .expect("an unbound child is preserved");
    assert_eq!(
        decoded.packet.get::<Raw>().map(|raw| raw.bytes.as_ref()),
        Some(&[3][..])
    );
    let unknown = decoded
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "decode.unknown_binding")
        .expect("unknown binding diagnostic");
    assert_eq!(unknown.layer, Some(0));
}

fn assert_registry_binding_conflicts() {
    let mut duplicate = packetcraftr_core::registry::Builder::new();
    duplicate
        .register_codec(ProbeCodec, &["p"])
        .expect("first codec");
    assert!(matches!(
        duplicate.register_codec(ProbeCodec, &["p"]),
        Err(packetcraftr_core::registry::Error::DuplicateProtocol { .. })
    ));

    let mut roots = packetcraftr_core::registry::Builder::new();
    roots
        .bind_link_type(LinkType(1), "probe")
        .expect("first root");
    assert!(matches!(
        roots.bind_link_type(LinkType(1), "child"),
        Err(packetcraftr_core::registry::Error::DuplicateLinkType {
            link_type: LinkType(1)
        })
    ));
    assert!(matches!(
        roots.build(),
        Err(packetcraftr_core::registry::Error::UnknownProtocol { .. })
    ));

    let mut bindings = packetcraftr_core::registry::Builder::new();
    bindings.register_codec(ProbeCodec, &["p"]).expect("probe");
    bindings.register_codec(ChildCodec, &[]).expect("child");
    bindings.bind("probe", 7, "child", 1).expect("binding");
    assert!(matches!(
        bindings.bind("probe", 7, "probe", 1),
        Err(packetcraftr_core::registry::Error::BindingConflict {
            discriminator: 7,
            priority: 1,
            ..
        })
    ));
    assert!(matches!(
        bindings.bind("probe", 7, "child", 2),
        Err(packetcraftr_core::registry::Error::BindingConflict { .. })
    ));
}

fn assert_filter_field_binding_conflicts() {
    let mut invalid = packetcraftr_core::registry::Builder::new();
    assert!(matches!(
        invalid.bind_filter_field(
            "empty",
            FilterFieldBinding::Either {
                protocol: "probe".into(),
                fields: &[]
            },
        ),
        Err(packetcraftr_core::registry::Error::InvalidFilterField { .. })
    ));
    assert!(matches!(
        invalid.bind_filter_field(
            "zero",
            FilterFieldBinding::Bits {
                protocol: "probe".into(),
                field: "value",
                mask: 0,
                shift: 0
            },
        ),
        Err(packetcraftr_core::registry::Error::InvalidFilterField { .. })
    ));
    assert!(matches!(
        invalid.bind_filter_field(
            "shift",
            FilterFieldBinding::Bits {
                protocol: "probe".into(),
                field: "value",
                mask: 1,
                shift: 64
            },
        ),
        Err(packetcraftr_core::registry::Error::InvalidFilterField { .. })
    ));

    let mut canonical = packetcraftr_core::registry::Builder::new();
    canonical.register_codec(ProbeCodec, &["p"]).expect("probe");
    canonical
        .bind_filter_field(
            "probe.value",
            FilterFieldBinding::Direct {
                protocol: "probe".into(),
                field: "value",
            },
        )
        .expect("staged binding");
    assert!(matches!(
        canonical.build(),
        Err(packetcraftr_core::registry::Error::DuplicateFilterField { .. })
    ));

    let mut unknown = packetcraftr_core::registry::Builder::new();
    unknown.register_codec(ProbeCodec, &["p"]).expect("probe");
    unknown
        .bind_filter_field(
            "probe.nope",
            FilterFieldBinding::Direct {
                protocol: "probe".into(),
                field: "nope",
            },
        )
        .expect("staged binding");
    assert!(matches!(
        unknown.build(),
        Err(packetcraftr_core::registry::Error::UnknownFilterField { .. })
    ));

    let mut wrong_kind = packetcraftr_core::registry::Builder::new();
    wrong_kind
        .register_codec(ProbeCodec, &["p"])
        .expect("probe");
    wrong_kind
        .bind_filter_field(
            "probe.label.flag",
            FilterFieldBinding::Bits {
                protocol: "probe".into(),
                field: "label",
                mask: 1,
                shift: 0,
            },
        )
        .expect("staged binding");
    assert!(matches!(
        wrong_kind.build(),
        Err(packetcraftr_core::registry::Error::InvalidFilterField { .. })
    ));
}

#[test]
fn registry_rejects_alias_binding_and_filter_contract_conflicts() {
    assert_registry_binding_conflicts();
    assert_filter_field_binding_conflicts();
}

#[test]
fn registered_filter_spellings_are_sorted_and_resolve_to_their_enumerated_bindings() {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let paths: Vec<_> = registry
        .filter_fields()
        .map(|(path, binding)| {
            assert_eq!(registry.filter_field(path), Some(binding));
            let schema = registry
                .schema(binding.protocol().as_str())
                .expect("bound protocol schema");
            for field in binding.fields() {
                assert!(schema.fields.iter().any(|entry| entry.name == *field));
            }
            path
        })
        .collect();
    assert!(paths.windows(2).all(|pair| pair[0] < pair[1]));
    for path in [
        "eth.src",
        "ip.src",
        "tcp.srcport",
        "tcp.flags.syn",
        "tcp.port",
        "udp.port",
    ] {
        assert!(paths.contains(&path), "{path} is discoverable");
    }
    assert!(
        !paths.contains(&"ip.ttl"),
        "schema aliases need no stored binding"
    );
}

#[test]
fn filter_enumeration_uses_custom_registrations_in_normalized_path_order() {
    let mut builder = packetcraftr_core::registry::Builder::new();
    builder.register_codec(ProbeCodec, &["p"]).expect("probe");
    for path in ["P.Z", "p.a"] {
        builder
            .bind_filter_field(
                path,
                FilterFieldBinding::Direct {
                    protocol: "probe".into(),
                    field: "value",
                },
            )
            .expect("custom spelling");
    }
    let registry = builder.build().expect("valid custom registry");
    assert_eq!(
        registry
            .filter_fields()
            .map(|(path, _)| path)
            .collect::<Vec<_>>(),
        ["p.a", "p.z"]
    );
}

/// A two-byte link header naming its payload by EtherType, registered like a
/// custom link protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Tag {
    ether_type: u16,
}

impl Default for Tag {
    fn default() -> Self {
        Self { ether_type: 0x0800 }
    }
}

packetcraftr_core::reflective_layer! {
    fn tag_schema() => { protocol: packetcraftr_core::layer::Id::new("tag"), name: "Tag" }
    impl Tag {
        "ether_type" => {
            kind: Unsigned, derived: false, required: true,
            description: "Payload EtherType",
            get |layer| Some(packetcraftr_core::layer::reflect_get(&layer.ether_type)),
            set |layer, value, name| packetcraftr_core::layer::reflect_set(
                &mut layer.ether_type, tag_schema(), name, value
            ),
            layout: (0, 2)
        }
    }
    layout fn tag_layout();
}

#[derive(Clone, Copy, Debug)]
struct TagCodec;

impl codec::LayerCodec for TagCodec {
    fn protocol_id(&self) -> &'static packetcraftr_core::layer::Id {
        &tag_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        _context: &codec::LayerEncodeContext<'_>,
    ) -> Result<codec::EncodedLayer, codec::Error> {
        let tag = layer
            .downcast_ref::<Tag>()
            .ok_or_else(|| codec::Error::WrongLayer {
                expected: "tag".into(),
                actual: *layer.protocol_id(),
            })?;
        let mut encoded = codec::EncodedLayer::header(
            tag.ether_type.to_be_bytes().to_vec(),
            Box::new(tag.clone()),
        );
        encoded.fields = tag_layout();
        Ok(encoded)
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &codec::LayerDecodeContext<'_>,
    ) -> Result<codec::DecodedLayer, codec::Error> {
        let Some(&[high, low]) = input.first_chunk::<2>() else {
            return Err(codec::Error::Truncated {
                protocol: "tag".into(),
                needed: 2,
                available: input.len(),
            });
        };
        let ether_type = u16::from_be_bytes([high, low]);
        let mut decoded = codec::DecodedLayer::terminal(Box::new(Tag { ether_type }), 2);
        decoded.payload_len = input.len() - 2;
        decoded.next = vec![Discriminator(ether_type.into())];
        decoded.stop = false;
        decoded.fields = tag_layout();
        Ok(decoded)
    }

    fn make_layer(
        &self,
        fields: &std::collections::BTreeMap<String, packetcraftr_core::field::FieldValue>,
    ) -> Result<Box<dyn Layer>, codec::Error> {
        let mut layer = Tag::default();
        for (name, value) in fields {
            layer.set_field(name, value.clone())?;
        }
        Ok(Box::new(layer))
    }
}

const TAG_LINK_TYPE: LinkType = LinkType(778);

/// The built-in registry plus the `tag` link protocol, with or without the
/// trailing-padding property.
fn tag_registry(padding: bool) -> Arc<packetcraftr_core::registry::Registry> {
    let registry = builtin::registry_with(|builder| {
        builder.register_codec(TagCodec, &[])?;
        if padding {
            builder.allow_trailing_padding("tag");
        }
        builder.bind_link_type(TAG_LINK_TYPE, "tag")?;
        builder.bind("tag", 0x0800, "ipv4", 100)?;
        Ok(())
    })
    .expect("tag registry");
    Arc::new(registry)
}

fn udp_datagram() -> Vec<Box<dyn Layer>> {
    vec![
        Box::new(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        }),
        Box::new(Udp {
            source_port: 40_000,
            destination_port: 40_001,
            ..Udp::default()
        }),
        Box::new(Raw::new(&b"hi"[..])),
    ]
}

fn packet_of(link: Box<dyn Layer>, trailer: Option<&'static [u8]>) -> Packet {
    let mut packet = Packet::new();
    packet.push_boxed(link);
    for layer in udp_datagram() {
        packet.push_boxed(layer);
    }
    if let Some(trailer) = trailer {
        packet.push(Padding::new(trailer));
    }
    packet
}

/// The layers after the link header, with padding bytes and ownership, plus
/// the codes of the diagnostics reporting bytes outside a declared length.
fn decoded_tail(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    link_type: LinkType,
    bytes: Bytes,
) -> (Vec<String>, Vec<&'static str>) {
    let frame = Frame::new(SystemTime::UNIX_EPOCH, link_type, bytes).expect("frame");
    let decoded = decode::Dissector::new(Arc::clone(registry))
        .decode(frame, decode::Options::default())
        .expect("frame decodes");
    let layers = decoded
        .packet
        .iter()
        .skip(1)
        .map(|layer| match layer.downcast_ref::<Padding>() {
            Some(padding) => format!("padding {:?} {:?}", padding.bytes, padding.outside_layer),
            None => layer.protocol_id().to_string(),
        })
        .collect();
    let trailing = decoded
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code)
        .filter(|code| code.starts_with("decode.trailing"))
        .collect();
    (layers, trailing)
}

#[test]
fn a_custom_link_protocol_registered_with_trailing_padding_behaves_like_ethernet() {
    const TRAILER: &[u8] = &[0, 0, 0, 0];
    let padded = tag_registry(true);
    let unpadded = tag_registry(false);
    assert!(padded.allows_trailing_padding("tag"));
    assert!(!unpadded.allows_trailing_padding("tag"));
    for builtin_link in ["ethernet", "vlan", "linux_sll", "bsd_null"] {
        assert!(
            padded.allows_trailing_padding(builtin_link),
            "{builtin_link}"
        );
    }
    assert!(!padded.allows_trailing_padding("ipv4"));

    let build_with = |registry: &Arc<packetcraftr_core::registry::Registry>, packet| {
        build::Builder::new(Arc::clone(registry)).build(
            packet,
            codec::Context::default(),
            build::Options::default(),
        )
    };
    let tagged = build_with(&padded, packet_of(Box::new(Tag::default()), Some(TRAILER)))
        .expect("link padding builds inside a padding link");
    assert!(tagged.bytes.ends_with(TRAILER));
    let ethernet = build_with(
        &padded,
        packet_of(Box::new(Ethernet::default()), Some(TRAILER)),
    )
    .expect("link padding builds inside ethernet");
    build_with(&padded, packet_of(Box::new(Vlan::default()), Some(TRAILER)))
        .expect("link padding builds inside a VLAN-rooted frame, as it decodes");
    assert!(matches!(
        build_with(
            &unpadded,
            packet_of(Box::new(Tag::default()), Some(TRAILER))
        ),
        Err(build::Error::PaddingWithoutLinkLayer { index: 4 })
    ));

    let tag_tail = decoded_tail(&padded, TAG_LINK_TYPE, tagged.bytes.clone());
    assert_eq!(
        tag_tail,
        decoded_tail(&padded, LinkType::ETHERNET, ethernet.bytes.clone())
    );
    assert_eq!(
        tag_tail,
        (
            vec![
                "ipv4".to_owned(),
                "udp".to_owned(),
                "raw".to_owned(),
                "padding b\"\\0\\0\\0\\0\" Some(1)".to_owned(),
            ],
            vec!["decode.trailing_padding"],
        )
    );
    let (_, unpadded_trailing) = decoded_tail(&unpadded, TAG_LINK_TYPE, tagged.bytes);
    assert_eq!(unpadded_trailing, ["decode.trailing_malformed"]);
    let mut unknown = packetcraftr_core::registry::Builder::new();
    unknown.allow_trailing_padding("missing");
    assert!(matches!(
        unknown.build(),
        Err(packetcraftr_core::registry::Error::UnknownProtocol { protocol })
            if protocol.as_str() == "missing"
    ));
}
