// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use packetcraftr_core::frame::{Frame, LinkType};

use super::super::Packet;
use super::super::codec::{
    CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext,
};
use super::super::decode::DecodedPacket;
use super::super::field::FieldValue;
use super::super::layer::{Id as ProtocolId, Layer, Padding, Raw};
use super::super::layout::PacketLayout;
use super::super::registry::{FilterFieldBinding, Registry};
use super::{
    Context, Error, Filter, MAX_FILTER_NESTING, MAX_FILTER_SET_MEMBERS, MAX_FILTER_TERMS, Options,
};

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

fn sample() -> DecodedPacket {
    let mut packet = Packet::new();
    packet
        .push(Raw::new(vec![0x47, 0x45, 0x54, 0x20]))
        .push(Padding::after_layer(vec![0xaa, 0xbb], 5))
        .push(Raw::new(vec![0x01, 0x02]));
    decoded(packet, &[0x47, 0x45, 0x54, 0x20, 0xaa, 0xbb, 0x01, 0x02])
}

mod evaluation;
mod syntax;
mod validation;
