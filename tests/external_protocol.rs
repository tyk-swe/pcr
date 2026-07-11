// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::any::Any;
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use packetcraftr::core::{
    BuildContext, BuildOptions, CodecError, DecodedLayerValue, Discriminator, EncodedLayer,
    FieldError, FieldKind, FieldSchema, FieldValue, Layer, LayerCodec, LayerDecodeContext,
    LayerEncodeContext, LayerSchema, ProtocolId,
};
use packetcraftr::{
    fuzz, Builder, BuiltinProtocols, Dissector, Ethernet, FuzzRequest, FuzzStrategy, FuzzTarget,
    Packet, ProtocolModule, ProtocolRegistry, Raw, RegistryBuilder, RegistryError, WireValue,
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
        builder.bind("example.foo", 0, "raw", 0)?;
        Ok(())
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
    assert!(result
        .cases
        .iter()
        .all(|case| case.mutation.protocol == "example.foo"));
    assert!(result.cases.iter().any(|case| case.built.is_some()));
    assert!(result.cases.iter().any(|case| case.error.is_some()));
}
