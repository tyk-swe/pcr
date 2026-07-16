// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::any::Any;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use packetcraftr::{
    packet::{
        Packet,
        build::{Builder, Context as BuildContext, Error as BuildError, Options as BuildOptions},
        codec::{
            Codec as LayerCodec, DecodeContext as LayerDecodeContext, Decoded as DecodedLayerValue,
            EncodeContext as LayerEncodeContext, Encoded as EncodedLayer, Error as CodecError,
        },
        decode::{Decoder as Dissector, Error as DecodeError},
        expression::{
            Error as ExpressionError, Options as ExpressionOptions,
            parse as parse_packet_expression,
        },
        field::{
            Error as FieldError, Kind as FieldKind, Schema as FieldSchema, Value as FieldValue,
            Wire as WireValue,
        },
        layer::{Id as ProtocolId, Layer, Raw, Schema as LayerSchema},
        registry::{
            Builder as RegistryBuilder, Discriminator, Error as RegistryError,
            Module as ProtocolModule, Registry as ProtocolRegistry,
        },
    },
    protocol::{
        builtin::Module as BuiltinProtocols, link::Ethernet, network::Ipv4, transport::Tcp,
    },
    workflow::fuzz::{
        Request as FuzzRequest, Strategy as FuzzStrategy, Target as FuzzTarget, run as fuzz,
    },
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Foo {
    value: u16,
}

fn schema() -> &'static LayerSchema {
    static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
    static FIELDS: &[FieldSchema] = &[FieldSchema {
        name: "value",
        kind: FieldKind::Unsigned,
        derived: false,
        required: true,
        description: "External fixture value",
    }];
    SCHEMA.get_or_init(|| LayerSchema {
        protocol: ProtocolId::new("example.foo"),
        name: "Foo",
        fields: FIELDS,
    })
}

impl Layer for Foo {
    fn schema(&self) -> &'static LayerSchema {
        schema()
    }

    fn clone_box(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn field(&self, name: &str) -> Option<FieldValue> {
        (name == "value").then_some(FieldValue::Unsigned(u64::from(self.value)))
    }

    fn set_field(&mut self, name: &str, value: FieldValue) -> Result<(), FieldError> {
        match (name, value) {
            ("value", FieldValue::Unsigned(value)) => {
                self.value = u16::try_from(value).map_err(|_| FieldError::OutOfRange {
                    protocol: schema().protocol.clone(),
                    field: name.to_owned(),
                })?;
                Ok(())
            }
            ("value", _) => Err(FieldError::WrongType {
                protocol: schema().protocol.clone(),
                field: name.to_owned(),
                expected: "unsigned",
            }),
            _ => Err(FieldError::UnknownField {
                protocol: schema().protocol.clone(),
                field: name.to_owned(),
            }),
        }
    }
}

#[derive(Debug)]
struct FooCodec;

impl LayerCodec for FooCodec {
    fn protocol_id(&self) -> ProtocolId {
        ProtocolId::new("example.foo")
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["foo"]
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        _context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<Foo>()
            .ok_or_else(|| CodecError::WrongLayer {
                expected: ProtocolId::new("example.foo"),
                actual: layer.protocol_id(),
            })?;
        Ok(EncodedLayer::header(
            layer.value.to_be_bytes().to_vec(),
            Box::new(layer.clone()),
        ))
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < 2 {
            return Err(CodecError::Truncated {
                protocol: ProtocolId::new("example.foo"),
                needed: 2,
                available: input.len(),
            });
        }
        Ok(DecodedLayerValue {
            layer: Box::new(Foo {
                value: u16::from_be_bytes([input[0], input[1]]),
            }),
            consumed: 2,
            payload_offset: 2,
            payload_len: input.len() - 2,
            next: vec![Discriminator(0)],
            fields: Vec::new(),
            diagnostics: Vec::new(),
            stop: input.len() == 2,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        let mut layer = Foo { value: 0 };
        for (name, value) in fields {
            layer.set_field(name, value.clone())?;
        }
        Ok(Box::new(layer))
    }
}

struct FooModule;

impl ProtocolModule for FooModule {
    fn register(&self, builder: &mut RegistryBuilder) -> Result<(), RegistryError> {
        builder.register_codec(FooCodec)?;
        builder.bind("ethernet", 0x88b5, "example.foo", 200)?;
        builder.bind("tcp", 0, "example.foo", 100)?;
        builder.bind("example.foo", 0, "raw", 0)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct MissingRequired;

fn missing_required_schema() -> &'static LayerSchema {
    static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
    static FIELDS: &[FieldSchema] = &[FieldSchema {
        name: "value",
        kind: FieldKind::Unsigned,
        derived: false,
        required: true,
        description: "Required external fixture value",
    }];
    SCHEMA.get_or_init(|| LayerSchema {
        protocol: ProtocolId::new("example.missing_required"),
        name: "Missing required fixture",
        fields: FIELDS,
    })
}

impl Layer for MissingRequired {
    fn schema(&self) -> &'static LayerSchema {
        missing_required_schema()
    }

    fn clone_box(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn field(&self, _name: &str) -> Option<FieldValue> {
        None
    }

    fn set_field(&mut self, name: &str, _value: FieldValue) -> Result<(), FieldError> {
        Err(FieldError::ReadOnly {
            protocol: self.protocol_id(),
            field: name.to_owned(),
        })
    }
}

#[derive(Debug)]
struct MissingRequiredCodec;

impl LayerCodec for MissingRequiredCodec {
    fn protocol_id(&self) -> ProtocolId {
        ProtocolId::new("example.missing_required")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        _context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        Ok(EncodedLayer::header(Vec::new(), layer.clone_box()))
    }

    fn decode(
        &self,
        _input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        Ok(DecodedLayerValue::terminal(Box::new(MissingRequired), 0))
    }

    fn make_layer(
        &self,
        _fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        Ok(Box::new(MissingRequired))
    }
}

#[test]
fn external_module_builds_and_decodes_ethernet_foo_raw() {
    let mut builder = ProtocolRegistry::builder();
    builder.module(&BuiltinProtocols).unwrap();
    builder.module(&FooModule).unwrap();
    let registry = Arc::new(builder.build().unwrap());

    let mut packet = Packet::new();
    packet
        .push(Ethernet {
            destination: [0, 1, 2, 3, 4, 5],
            source: [6, 7, 8, 9, 10, 11],
            ether_type: WireValue::Auto,
        })
        .push(Foo { value: 0x1234 })
        .push(Raw::new(vec![0xaa, 0xbb]));

    let built = Builder::new(Arc::clone(&registry))
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert_eq!(&built.bytes[12..16], &[0x88, 0xb5, 0x12, 0x34]);

    let decoded = Dissector::new(registry)
        .decode_with_root(built.bytes, ProtocolId::new("ethernet"), Default::default())
        .unwrap();
    assert_eq!(decoded.packet.get::<Foo>().unwrap().value, 0x1234);
    assert_eq!(
        decoded.packet.get::<Raw>().unwrap().bytes.as_ref(),
        &[0xaa, 0xbb]
    );
}

#[test]
fn shadowed_binding_cannot_encode_a_winning_external_discriminator() {
    let mut builder = ProtocolRegistry::builder();
    builder.module(&BuiltinProtocols).unwrap();
    builder.module(&FooModule).unwrap();
    builder.bind("ethernet", 0x88b5, "ipv4", 150).unwrap();
    let registry = Arc::new(builder.build().unwrap());

    assert_eq!(
        registry.child_for(&ProtocolId::new("ethernet"), Discriminator(0x88b5)),
        Some(&ProtocolId::new("example.foo"))
    );
    assert_eq!(
        registry.discriminator_for(&ProtocolId::new("ethernet"), &ProtocolId::new("ipv4")),
        Some(Discriminator(0x0800))
    );

    let mut packet = Packet::new();
    packet
        .push(Ethernet {
            destination: [0, 1, 2, 3, 4, 5],
            source: [6, 7, 8, 9, 10, 11],
            ether_type: WireValue::Auto,
        })
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        })
        .push(Tcp {
            source_port: 40_000,
            destination_port: 443,
            ..Tcp::default()
        });

    let built = Builder::new(Arc::clone(&registry))
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert_eq!(&built.bytes[12..14], &[0x08, 0x00]);

    let decoded = Dissector::new(registry)
        .decode_with_root(built.bytes, ProtocolId::new("ethernet"), Default::default())
        .unwrap();
    assert!(decoded.packet.get::<Ipv4>().is_some());
    assert!(decoded.packet.get::<Foo>().is_none());
}

#[test]
fn tcp_matcher_counts_an_external_protocol_payload() {
    let mut registry_builder = ProtocolRegistry::builder();
    registry_builder.module(&BuiltinProtocols).unwrap();
    registry_builder.module(&FooModule).unwrap();
    let registry = Arc::new(registry_builder.build().unwrap());
    let client = Ipv4Addr::new(10, 0, 0, 1);
    let server = Ipv4Addr::new(10, 0, 0, 2);

    let mut request = Packet::new();
    request
        .push(Ipv4 {
            source: client,
            destination: server,
            ..Ipv4::default()
        })
        .push(Tcp {
            source_port: 40_000,
            destination_port: 443,
            sequence: 100,
            flags: Tcp::SYN,
            ..Tcp::default()
        })
        .push(Foo { value: 0x1234 });
    let request = Builder::new(Arc::clone(&registry))
        .build(request, BuildContext::default(), BuildOptions::default())
        .unwrap()
        .packet;

    let response = |acknowledgment| {
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                source: server,
                destination: client,
                ..Ipv4::default()
            })
            .push(Tcp {
                source_port: 443,
                destination_port: 40_000,
                sequence: 500,
                acknowledgment,
                flags: Tcp::SYN | Tcp::ACK,
                ..Tcp::default()
            });
        packet
    };
    let matcher = registry.matcher(&ProtocolId::new("tcp")).unwrap();

    // The two encoded Foo bytes and SYN consume three sequence numbers.
    assert!(matcher.matches(&request, &response(103)).matched);
    assert!(!matcher.matches(&request, &response(101)).matched);
}

#[test]
fn external_reflective_fields_participate_in_bounded_fuzzing() {
    let mut builder = ProtocolRegistry::builder();
    builder.module(&BuiltinProtocols).unwrap();
    builder.module(&FooModule).unwrap();
    let registry = Arc::new(builder.build().unwrap());
    let mut packet = Packet::new();
    packet
        .push(Ethernet {
            destination: [0, 1, 2, 3, 4, 5],
            source: [6, 7, 8, 9, 10, 11],
            ether_type: WireValue::Auto,
        })
        .push(Foo { value: 0x1234 })
        .push(Raw::new(vec![0xaa]));

    let result = fuzz(
        &FuzzRequest {
            seed: 99,
            cases: 16,
            strategies: vec![FuzzStrategy::Boundary, FuzzStrategy::Random],
            targets: vec![FuzzTarget {
                layer: 1,
                field: "value".to_owned(),
            }],
            ..FuzzRequest::default()
        },
        packet,
        registry,
    )
    .unwrap();
    assert_eq!(result.cases.len(), 16);
    assert!(
        result
            .cases
            .iter()
            .all(|case| case.mutation.protocol == "example.foo")
    );
    assert!(result.cases.iter().any(|case| case.built.is_some()));
    assert!(result.cases.iter().any(|case| case.error.is_some()));
}

#[test]
fn external_codec_factories_must_materialize_required_fields() {
    let mut builder = ProtocolRegistry::builder();
    builder.register_codec(MissingRequiredCodec).unwrap();
    let registry = builder.build().unwrap();

    let error = parse_packet_expression(
        "example.missing_required()",
        &registry,
        ExpressionOptions::default(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ExpressionError::Layer {
            source: CodecError::Field(FieldError::MissingRequired { .. }),
            ..
        }
    ));

    let registry = Arc::new(registry);
    let mut packet = Packet::new();
    packet.push(MissingRequired);
    assert!(matches!(
        Builder::new(Arc::clone(&registry)).build(
            packet,
            BuildContext::default(),
            BuildOptions::default()
        ),
        Err(BuildError::InvalidLayer {
            source: FieldError::MissingRequired { .. },
            ..
        })
    ));

    assert!(matches!(
        Dissector::new(registry).decode_with_root(
            Bytes::new(),
            ProtocolId::new("example.missing_required"),
            Default::default()
        ),
        Err(DecodeError::InvalidLayer {
            source: FieldError::MissingRequired { .. },
            ..
        })
    ));
}

#[test]
fn registry_rejects_duplicate_conflicting_and_dangling_extensions() {
    let mut builder = ProtocolRegistry::builder();
    builder.module(&BuiltinProtocols).unwrap();
    builder.module(&FooModule).unwrap();

    assert!(matches!(
        builder.register_codec(FooCodec),
        Err(RegistryError::DuplicateProtocol { protocol })
            if protocol == ProtocolId::new("example.foo")
    ));
    assert!(matches!(
        builder.bind_link_type(1, "example.foo"),
        Err(RegistryError::DuplicateLinkType { link_type: 1 })
    ));

    builder.bind("ipv4", 253, "raw", 10).unwrap();
    assert!(matches!(
        builder.bind("ipv4", 253, "udp", 10),
        Err(RegistryError::BindingConflict {
            parent,
            discriminator: 253,
            priority: 10,
        }) if parent == ProtocolId::new("ipv4")
    ));

    let mut dangling = ProtocolRegistry::builder();
    dangling.register_codec(FooCodec).unwrap();
    dangling.bind_link_type(147, "example.missing").unwrap();
    assert!(matches!(
        dangling.build(),
        Err(RegistryError::UnknownProtocol { protocol })
            if protocol == ProtocolId::new("example.missing")
    ));
}
