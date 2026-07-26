// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::any::Any;
use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use packetcraftr::{
    output::build::Result as BuildOutput,
    packet::{
        Packet,
        build::{Builder, Context as BuildContext, Options as BuildOptions},
        catalog::{
            CatalogError, NativeProtocolModule, ProtocolBindingRegistration,
            ProtocolCatalogSnapshot, ProtocolRegistration, ProtocolRegistrationSet,
        },
        codec::{
            CodecError, DecodedLayerValue, Discriminator, EncodedLayer, NativeLayerCodec,
            NativeLayerDecodeContext, NativeLayerEncodeContext,
        },
        decode::Decoder as Dissector,
        document::PacketDocument,
        expression::{Options as ExpressionOptions, parse as parse_packet_expression},
        field::{FieldKind, FieldValue, WireValue},
        layer::{
            DynamicLayer, FieldConstraints, FieldError, FieldId, FieldSchema, Layer, LayerSchema,
            ProtocolId, Raw, ValidatedFieldSet,
        },
        provider::{NativeProtocolImplementation, NativeProtocolProvider, ProviderProtocolKey},
        template::{PacketTemplate, TemplateValues},
    },
    protocol::{builtin::Module as BuiltinProtocols, link::Ethernet},
    workflow::fuzz::{
        Request as FuzzRequest, Strategy as FuzzStrategy, Target as FuzzTarget, run as fuzz,
    },
};
use packetcraftr_model::{ProviderId, RegistrationOrigin};

const FOO_PROTOCOL: &str = "example.foo";
const DYNAMIC_PROTOCOL: &str = "example.dynamic";
const PROVIDER: &str = "example.native.protocols";

fn foo_schema_cell() -> &'static Arc<LayerSchema> {
    static SCHEMA: OnceLock<Arc<LayerSchema>> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        Arc::new(
            LayerSchema::new(
                ProtocolId::from_static(FOO_PROTOCOL),
                "Example Foo",
                ["foo"],
                1,
                [FieldSchema::new(
                    FieldId::from_static("value"),
                    "value",
                    ["v"],
                    FieldKind::Unsigned,
                    true,
                    false,
                    "External fixture value",
                    FieldConstraints::unsigned(0, u64::from(u16::MAX)),
                )
                .unwrap()],
            )
            .unwrap(),
        )
    })
}

fn foo_schema() -> Arc<LayerSchema> {
    Arc::clone(foo_schema_cell())
}

fn dynamic_schema_cell() -> &'static Arc<LayerSchema> {
    static SCHEMA: OnceLock<Arc<LayerSchema>> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        Arc::new(
            LayerSchema::new(
                ProtocolId::from_static(DYNAMIC_PROTOCOL),
                "Example Dynamic",
                ["dyn"],
                1,
                [FieldSchema::new(
                    FieldId::from_static("quantity"),
                    "quantity",
                    ["amount"],
                    FieldKind::Unsigned,
                    true,
                    false,
                    "Dynamically represented example quantity",
                    FieldConstraints::unsigned(0, u64::from(u16::MAX)),
                )
                .unwrap()],
            )
            .unwrap(),
        )
    })
}

fn dynamic_schema() -> Arc<LayerSchema> {
    Arc::clone(dynamic_schema_cell())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Foo {
    value: u16,
}

impl Layer for Foo {
    fn schema(&self) -> &LayerSchema {
        foo_schema_cell()
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

    fn field_by_id(&self, id: &FieldId) -> Option<FieldValue> {
        (id.as_str() == "value").then_some(FieldValue::Unsigned(u64::from(self.value)))
    }

    fn set_field_by_id(&mut self, id: &FieldId, value: FieldValue) -> Result<(), FieldError> {
        if id.as_str() != "value" {
            return Err(FieldError::UnknownFieldId {
                protocol: self.protocol_id().clone(),
                field: id.clone(),
            });
        }
        let FieldValue::Unsigned(value) = value else {
            return Err(FieldError::WrongKind {
                protocol: self.protocol_id().clone(),
                field: id.clone(),
                expected: FieldKind::Unsigned,
                actual: value.kind(),
            });
        };
        self.value = u16::try_from(value).map_err(|_| FieldError::Constraint {
            protocol: self.protocol_id().clone(),
            field: id.clone(),
        })?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct FooCodec;

impl NativeLayerCodec for FooCodec {
    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &NativeLayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<Foo>()
            .ok_or_else(|| CodecError::WrongLayer {
                expected: ProtocolId::from_static(FOO_PROTOCOL),
                actual: layer.protocol_id().clone(),
            })?;
        let mut prefix = layer.value.to_be_bytes().to_vec();
        if context.child_protocol.is_some() {
            let discriminator =
                context
                    .canonical_child_discriminator
                    .ok_or_else(|| CodecError::Invalid {
                        protocol: ProtocolId::from_static(FOO_PROTOCOL),
                        message: "child has no canonical discriminator".to_owned(),
                    })?;
            prefix.push(
                u8::try_from(discriminator.0).map_err(|_| CodecError::Invalid {
                    protocol: ProtocolId::from_static(FOO_PROTOCOL),
                    message: "child discriminator exceeds one byte".to_owned(),
                })?,
            );
        }
        Ok(EncodedLayer::header(prefix, Box::new(layer.clone())))
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &NativeLayerDecodeContext,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < 2 {
            return Err(CodecError::Truncated {
                protocol: ProtocolId::from_static(FOO_PROTOCOL),
                needed: 2,
                available: input.len(),
            });
        }
        let has_child = input.len() > 2;
        Ok(DecodedLayerValue {
            layer: Box::new(Foo {
                value: u16::from_be_bytes([input[0], input[1]]),
            }),
            consumed: 2 + usize::from(has_child),
            payload_offset: 2 + usize::from(has_child),
            payload_len: input.len().saturating_sub(2 + usize::from(has_child)),
            next: has_child
                .then(|| Discriminator(u64::from(input[2])))
                .into_iter()
                .collect(),
            fields: Vec::new(),
            diagnostics: Vec::new(),
            stop: !has_child,
            network: None,
        })
    }

    fn make_layer(&self, fields: &ValidatedFieldSet) -> Result<Box<dyn Layer>, CodecError> {
        let id = FieldId::from_static("value");
        let value = fields.get(&id).ok_or_else(|| {
            CodecError::Field(FieldError::MissingRequired {
                protocol: ProtocolId::from_static(FOO_PROTOCOL),
                field: id.clone(),
            })
        })?;
        let FieldValue::Unsigned(value) = value else {
            unreachable!("validated field sets enforce schema kinds")
        };
        Ok(Box::new(Foo {
            value: u16::try_from(*value).map_err(|_| {
                CodecError::Field(FieldError::Constraint {
                    protocol: ProtocolId::from_static(FOO_PROTOCOL),
                    field: id,
                })
            })?,
        }))
    }
}

#[derive(Clone, Copy, Debug)]
struct DynamicCodec;

impl NativeLayerCodec for DynamicCodec {
    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        _context: &NativeLayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        if layer.protocol_id().as_str() != DYNAMIC_PROTOCOL {
            return Err(CodecError::WrongLayer {
                expected: ProtocolId::from_static(DYNAMIC_PROTOCOL),
                actual: layer.protocol_id().clone(),
            });
        }
        let id = FieldId::from_static("quantity");
        let Some(FieldValue::Unsigned(value)) = layer.field_by_id(&id) else {
            return Err(CodecError::Field(FieldError::MissingRequired {
                protocol: ProtocolId::from_static(DYNAMIC_PROTOCOL),
                field: id,
            }));
        };
        let value = u16::try_from(value).map_err(|_| CodecError::Invalid {
            protocol: ProtocolId::from_static(DYNAMIC_PROTOCOL),
            message: "quantity exceeds the schema limit".to_owned(),
        })?;
        Ok(EncodedLayer::header(
            value.to_be_bytes().to_vec(),
            layer.clone_box(),
        ))
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &NativeLayerDecodeContext,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < 2 {
            return Err(CodecError::Truncated {
                protocol: ProtocolId::from_static(DYNAMIC_PROTOCOL),
                needed: 2,
                available: input.len(),
            });
        }
        let layer = DynamicLayer::new(
            dynamic_schema(),
            [(
                FieldId::from_static("quantity"),
                FieldValue::Unsigned(u64::from(u16::from_be_bytes([input[0], input[1]]))),
            )],
        )?;
        let has_child = input.len() > 2;
        Ok(DecodedLayerValue {
            layer: Box::new(layer),
            consumed: 2,
            payload_offset: 2,
            payload_len: input.len() - 2,
            next: has_child.then_some(Discriminator(0)).into_iter().collect(),
            fields: Vec::new(),
            diagnostics: Vec::new(),
            stop: !has_child,
            network: None,
        })
    }

    fn make_layer(&self, fields: &ValidatedFieldSet) -> Result<Box<dyn Layer>, CodecError> {
        Ok(Box::new(DynamicLayer::from_validated(fields.clone())?))
    }
}

#[derive(Clone, Copy, Debug)]
struct ExampleProtocols;

impl NativeProtocolModule for ExampleProtocols {
    fn registrations(&self) -> Result<ProtocolRegistrationSet, CatalogError> {
        let provider_id = ProviderId::from_static(PROVIDER);
        let origin = RegistrationOrigin::Native {
            provider: provider_id.clone(),
        };
        let foo_key = ProviderProtocolKey::from_static("foo");
        let dynamic_key = ProviderProtocolKey::from_static("dynamic");
        let provider = NativeProtocolProvider::new(
            provider_id.clone(),
            origin.clone(),
            [
                NativeProtocolImplementation::new(foo_key.clone(), FooCodec),
                NativeProtocolImplementation::new(dynamic_key.clone(), DynamicCodec),
            ],
        )?;

        let mut set = ProtocolRegistrationSet::new();
        set.register_provider(Arc::new(provider))
            .register_protocol(ProtocolRegistration::new(
                foo_schema(),
                provider_id.clone(),
                foo_key,
                origin.clone(),
            ))
            .register_protocol(ProtocolRegistration::new(
                dynamic_schema(),
                provider_id,
                dynamic_key,
                origin.clone(),
            ))
            .binding(ProtocolBindingRegistration::canonical(
                ProtocolId::from_static("ethernet"),
                0x88b5,
                ProtocolId::from_static(FOO_PROTOCOL),
                origin.clone(),
            ))
            .binding(ProtocolBindingRegistration::canonical(
                ProtocolId::from_static(FOO_PROTOCOL),
                1,
                ProtocolId::from_static(DYNAMIC_PROTOCOL),
                origin.clone(),
            ))
            .binding(ProtocolBindingRegistration::canonical(
                ProtocolId::from_static(DYNAMIC_PROTOCOL),
                0,
                ProtocolId::from_static("raw"),
                origin,
            ));
        Ok(set)
    }
}

fn example_catalog() -> Arc<ProtocolCatalogSnapshot> {
    let mut builder = ProtocolCatalogSnapshot::builder();
    builder.native_module(&BuiltinProtocols).unwrap();
    builder.native_module(&ExampleProtocols).unwrap();
    Arc::new(builder.build().unwrap())
}

fn example_packet() -> Packet {
    let dynamic =
        DynamicLayer::from_named(dynamic_schema(), [("amount", FieldValue::Unsigned(7))]).unwrap();
    let mut packet = Packet::new();
    packet
        .push(Ethernet {
            destination: [0, 1, 2, 3, 4, 5],
            source: [6, 7, 8, 9, 10, 11],
            ether_type: WireValue::Auto,
        })
        .push(Foo { value: 0x1234 })
        .push(dynamic)
        .push(Raw::new(vec![0xaa, 0xbb]));
    packet
}

#[test]
fn native_typed_access_and_dynamic_layers_round_trip_exactly() {
    let catalog = example_catalog();
    let built = Builder::new(Arc::clone(&catalog))
        .build(
            example_packet(),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert_eq!(
        &built.bytes[12..21],
        &[0x88, 0xb5, 0x12, 0x34, 1, 0, 7, 0xaa, 0xbb]
    );
    assert_eq!(built.packet.get::<Foo>().unwrap().value, 0x1234);
    assert_eq!(
        built
            .packet
            .get::<DynamicLayer>()
            .unwrap()
            .field("quantity"),
        Some(FieldValue::Unsigned(7))
    );

    let decoded = Dissector::new(catalog)
        .decode_with_root(
            built.bytes.clone(),
            ProtocolId::from_static("ethernet"),
            Default::default(),
        )
        .unwrap();
    assert_eq!(
        decoded
            .packet
            .iter()
            .map(|layer| layer.protocol_id().as_str())
            .collect::<Vec<_>>(),
        ["ethernet", FOO_PROTOCOL, DYNAMIC_PROTOCOL, "raw"]
    );
    assert_eq!(decoded.packet.get::<Foo>().unwrap().value, 0x1234);
    assert_eq!(
        decoded
            .packet
            .get::<DynamicLayer>()
            .unwrap()
            .field_by_id(&FieldId::from_static("quantity")),
        Some(FieldValue::Unsigned(7))
    );
}

#[test]
fn dynamic_layers_work_in_documents_expressions_and_output() {
    let catalog = example_catalog();
    let built = Builder::new(Arc::clone(&catalog))
        .build(
            example_packet(),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();

    let document = PacketDocument::from_packet(&built.packet);
    assert_eq!(document.layers[2].protocol, DYNAMIC_PROTOCOL);
    assert_eq!(
        document.layers[2].fields.get("quantity"),
        Some(&FieldValue::Unsigned(7))
    );
    let restored = document.to_packet(&catalog, 16).unwrap();
    assert_eq!(
        restored.get::<DynamicLayer>().unwrap().field("amount"),
        Some(FieldValue::Unsigned(7))
    );

    let expression = parse_packet_expression(
        "ethernet()/foo(v=4660)/dyn(amount=7)/raw(hex=aabb)",
        &catalog,
        ExpressionOptions::default(),
    )
    .unwrap();
    let expression_built = Builder::new(Arc::clone(&catalog))
        .build(expression, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert_eq!(&expression_built.bytes[12..], &built.bytes[12..]);

    let (output, diagnostics) = BuildOutput::from_built(built);
    assert!(diagnostics.is_empty());
    assert_eq!(output.packet.layers[2].protocol, DYNAMIC_PROTOCOL);
    assert_eq!(
        output.packet.layers[2].fields.get("quantity"),
        Some(&FieldValue::Unsigned(7))
    );
}

#[test]
fn dynamic_layers_work_in_template_expansion() {
    let catalog = example_catalog();
    let template = PacketTemplate::new(example_packet()).axis(
        2,
        "amount",
        TemplateValues::Values(vec![FieldValue::Unsigned(8), FieldValue::Unsigned(9)]),
    );

    let expanded = template
        .expand(2)
        .unwrap()
        .map(|packet| packet.unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        expanded
            .iter()
            .map(|packet| packet
                .get::<DynamicLayer>()
                .unwrap()
                .field_by_id(&FieldId::from_static("quantity")))
            .collect::<Vec<_>>(),
        [Some(FieldValue::Unsigned(8)), Some(FieldValue::Unsigned(9))]
    );

    let encoded = expanded
        .into_iter()
        .map(|packet| {
            Builder::new(Arc::clone(&catalog))
                .build(packet, BuildContext::default(), BuildOptions::default())
                .unwrap()
                .bytes
        })
        .collect::<Vec<_>>();
    assert_eq!(&encoded[0][17..19], &[0, 8]);
    assert_eq!(&encoded[1][17..19], &[0, 9]);
}

#[test]
fn dynamic_fields_participate_in_bounded_fuzzing() {
    let result = fuzz(
        &FuzzRequest {
            seed: 99,
            cases: 16,
            strategies: vec![FuzzStrategy::Boundary, FuzzStrategy::Random],
            targets: vec![FuzzTarget {
                layer: 2,
                field: "amount".to_owned(),
            }],
            ..FuzzRequest::default()
        },
        example_packet(),
        example_catalog(),
    )
    .unwrap();

    assert_eq!(result.cases.len(), 16);
    assert!(
        result
            .cases
            .iter()
            .all(|case| case.mutation.protocol == DYNAMIC_PROTOCOL)
    );
    assert!(result.cases.iter().any(|case| case.built.is_some()));
    assert!(result.cases.iter().any(|case| case.error.is_some()));
}

#[test]
fn schema_aliases_resolve_to_stable_field_ids() {
    let schema = dynamic_schema();
    assert_eq!(
        schema.canonical_field_id(" AMOUNT "),
        Some(&FieldId::from_static("quantity"))
    );
    assert_eq!(
        schema.field_named("quantity").unwrap().id,
        FieldId::from_static("quantity")
    );
    assert_eq!(schema.schema_hash, dynamic_schema().schema_hash);

    let mut layer =
        DynamicLayer::from_named(Arc::clone(&schema), [("quantity", FieldValue::Unsigned(3))])
            .unwrap();
    layer.set_field("amount", FieldValue::Unsigned(4)).unwrap();
    assert_eq!(
        layer.field_by_id(&FieldId::from_static("quantity")),
        Some(FieldValue::Unsigned(4))
    );
}

#[test]
fn catalog_operation_invokes_builtin_matchers_without_exposing_them() {
    use packetcraftr::protocol::{network::Ipv4, transport::Tcp};
    use std::net::Ipv4Addr;

    let catalog = example_catalog();
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
        });
    let request = Builder::new(Arc::clone(&catalog))
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

    let mut operation = catalog.operation();
    let matched = operation
        .match_response(&ProtocolId::from_static("tcp"), &request, &response(101))
        .unwrap()
        .unwrap();
    assert!(matched.result.matched);
}

#[test]
fn construction_rejects_missing_required_dynamic_fields() {
    let catalog = example_catalog();
    let error = catalog
        .operation()
        .construct_named(DYNAMIC_PROTOCOL, std::iter::empty::<(&str, FieldValue)>())
        .unwrap_err();
    assert!(error.to_string().contains("required field quantity"));

    let error = DynamicLayer::new(
        dynamic_schema(),
        std::iter::empty::<(FieldId, FieldValue)>(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        FieldError::MissingRequired { field, .. }
            if field == FieldId::from_static("quantity")
    ));
}

#[test]
fn decode_preserves_truncated_external_layers_as_malformed_evidence() {
    let catalog = example_catalog();
    let decoded = Dissector::new(catalog)
        .decode_with_root(
            Bytes::from_static(&[0x12]),
            ProtocolId::from_static(FOO_PROTOCOL),
            Default::default(),
        )
        .unwrap();
    assert_eq!(
        decoded.packet.layer(0).unwrap().protocol_id().as_str(),
        "malformed"
    );
    assert!(
        decoded.diagnostics[0]
            .message
            .contains("need at least 2 bytes")
    );
}
