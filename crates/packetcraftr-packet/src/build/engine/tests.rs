// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::any::Any;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use bytes::Bytes;

use super::Builder;
use super::buffer::PacketBuffer;
use super::error::BuildError;
use super::options::{BuildContext, BuildMode, BuildOptions, DEFAULT_MAX_LAYERS};
use crate::codec::{
    DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext,
};
use crate::field::{FieldKind, FieldValue};
use crate::layer::{FieldError, FieldSchema, Layer, LayerSchema, Padding, ProtocolId, Raw};
use crate::layout::ByteRange;
use crate::model::Packet;
use crate::registry::{CodecError, ProtocolRegistry, RegistryBuilder};

#[derive(Clone, Debug)]
struct ExternalMetadata(Bytes);

impl Layer for ExternalMetadata {
    fn schema(&self) -> &'static LayerSchema {
        static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
        static FIELDS: &[FieldSchema] = &[FieldSchema {
            name: "metadata",
            kind: FieldKind::Bytes,
            derived: false,
            required: false,
            description: "Reflective metadata that is not emitted on the wire",
        }];
        SCHEMA.get_or_init(|| LayerSchema {
            protocol: ProtocolId::new("external.metadata"),
            name: "External metadata",
            fields: FIELDS,
        })
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
        (name == "metadata").then(|| FieldValue::Bytes(self.0.clone()))
    }

    fn set_field(&mut self, name: &str, value: FieldValue) -> Result<(), FieldError> {
        match (name, value) {
            ("metadata", FieldValue::Bytes(value)) => {
                self.0 = value;
                Ok(())
            }
            ("metadata", _) => Err(FieldError::WrongType {
                protocol: self.protocol_id().clone(),
                field: name.to_owned(),
                expected: "bytes",
            }),
            _ => Err(FieldError::UnknownField {
                protocol: self.protocol_id().clone(),
                field: name.to_owned(),
            }),
        }
    }
}

#[derive(Debug)]
struct ExternalMetadataCodec;

impl LayerCodec for ExternalMetadataCodec {
    fn protocol_id(&self) -> ProtocolId {
        ProtocolId::new("external.metadata")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        _context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        Ok(EncodedLayer {
            prefix: vec![0],
            suffix: vec![255],
            materialized: layer.clone_box(),
            fields: Vec::new(),
            diagnostics: Vec::new(),
        })
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        Ok(DecodedLayerValue::terminal(
            Box::new(ExternalMetadata(Bytes::new())),
            input.len(),
        ))
    }

    fn make_layer(
        &self,
        _fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        Ok(Box::new(ExternalMetadata(Bytes::new())))
    }
}

#[derive(Debug)]
struct CloneCountingLayer {
    id: u8,
    clone_count: Arc<AtomicUsize>,
}

impl Clone for CloneCountingLayer {
    fn clone(&self) -> Self {
        self.clone_count.fetch_add(1, Ordering::Relaxed);
        Self {
            id: self.id,
            clone_count: Arc::clone(&self.clone_count),
        }
    }
}

impl Layer for CloneCountingLayer {
    fn schema(&self) -> &'static LayerSchema {
        static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
        SCHEMA.get_or_init(|| LayerSchema {
            protocol: ProtocolId::new("clone.counting"),
            name: "Clone counting",
            fields: &[],
        })
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
        Err(FieldError::UnknownField {
            protocol: self.protocol_id().clone(),
            field: name.to_owned(),
        })
    }
}

#[derive(Debug)]
struct CloneCountingCodec;

impl LayerCodec for CloneCountingCodec {
    fn protocol_id(&self) -> ProtocolId {
        ProtocolId::new("clone.counting")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        _context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<CloneCountingLayer>()
            .ok_or_else(|| CodecError::WrongLayer {
                expected: self.protocol_id(),
                actual: layer.protocol_id().clone(),
            })?;
        Ok(EncodedLayer::header(vec![layer.id], layer.clone_box()))
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        Ok(DecodedLayerValue::terminal(
            Box::new(CloneCountingLayer {
                id: input.first().copied().unwrap_or_default(),
                clone_count: Arc::new(AtomicUsize::new(0)),
            }),
            input.len(),
        ))
    }

    fn make_layer(
        &self,
        _fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        Ok(Box::new(CloneCountingLayer {
            id: 0,
            clone_count: Arc::new(AtomicUsize::new(0)),
        }))
    }
}

fn empty_registry() -> Arc<ProtocolRegistry> {
    Arc::new(ProtocolRegistry::builder().build().unwrap())
}

#[test]
fn byte_layer_limit_is_rejected_before_encoding() {
    let mut packet = Packet::new();
    packet.push(Raw::new(vec![0_u8; 1024]));
    assert!(matches!(
        Builder::new(empty_registry()).build(
            packet,
            BuildContext::default(),
            BuildOptions {
                max_packet_size: 16,
                ..BuildOptions::default()
            },
        ),
        Err(BuildError::PacketSizeLimit {
            actual: 1024,
            limit: 16
        })
    ));
}

#[test]
fn external_byte_fields_are_not_assumed_to_be_wire_bytes() {
    let mut packet = Packet::new();
    packet.push(ExternalMetadata(Bytes::from(vec![0_u8; 1024])));
    let mut registry = RegistryBuilder::new();
    registry.register_codec(ExternalMetadataCodec).unwrap();
    let registry = Arc::new(registry.build().unwrap());

    let built = Builder::new(registry)
        .build(
            packet,
            BuildContext::default(),
            BuildOptions {
                max_packet_size: 2,
                ..BuildOptions::default()
            },
        )
        .unwrap();
    assert_eq!(built.bytes.as_ref(), &[0, 255]);
}

#[test]
fn nested_prefixes_and_suffixes_keep_layouts_and_payload_lengths() {
    let mut packet = Packet::new();
    packet
        .push(ExternalMetadata(Bytes::new()))
        .push(ExternalMetadata(Bytes::new()));
    let mut registry = RegistryBuilder::new();
    registry.register_codec(ExternalMetadataCodec).unwrap();
    let built = Builder::new(Arc::new(registry.build().unwrap()))
        .build(
            packet,
            BuildContext::default(),
            BuildOptions {
                mode: BuildMode::Permissive,
                ..BuildOptions::default()
            },
        )
        .unwrap();

    assert_eq!(built.bytes.as_ref(), &[0, 0, 255, 255]);
    assert_eq!(built.layout.layers[0].range, ByteRange::new(0, 1));
    assert_eq!(built.layout.layers[1].range, ByteRange::new(1, 2));
    assert_eq!(built.packet.encoded_payload_length(0), Some(2));
    assert_eq!(built.packet.encoded_payload_length(1), Some(0));
}

#[test]
fn builder_only_clones_layers_when_the_codec_materializes_them() {
    let clone_count = Arc::new(AtomicUsize::new(0));
    let mut packet = Packet::new();
    for id in [1, 2, 3] {
        packet.push(CloneCountingLayer {
            id,
            clone_count: Arc::clone(&clone_count),
        });
    }
    let mut registry = RegistryBuilder::new();
    registry.register_codec(CloneCountingCodec).unwrap();

    let built = Builder::new(Arc::new(registry.build().unwrap()))
        .build(
            packet,
            BuildContext::default(),
            BuildOptions {
                mode: BuildMode::Permissive,
                ..BuildOptions::default()
            },
        )
        .unwrap();

    assert_eq!(clone_count.load(Ordering::Relaxed), 3);
    let materialized_ids: Vec<_> = built
        .packet
        .iter()
        .map(|layer| {
            layer
                .as_any()
                .downcast_ref::<CloneCountingLayer>()
                .expect("the codec preserves its concrete layer type")
                .id
        })
        .collect();
    assert_eq!(materialized_ids, [1, 2, 3]);
    let payload_lengths: Vec<_> = (0..built.packet.len())
        .map(|index| built.packet.encoded_payload_length(index))
        .collect();
    assert_eq!(payload_lengths, [Some(2), Some(1), Some(0)]);
}

#[test]
fn deep_prefix_and_suffix_stack_preserves_bytes() {
    let mut packet = Packet::new();
    for _ in 0..DEFAULT_MAX_LAYERS {
        packet.push(ExternalMetadata(Bytes::new()));
    }
    let mut registry = RegistryBuilder::new();
    registry.register_codec(ExternalMetadataCodec).unwrap();
    let built = Builder::new(Arc::new(registry.build().unwrap()))
        .build(
            packet,
            BuildContext::default(),
            BuildOptions {
                mode: BuildMode::Permissive,
                ..BuildOptions::default()
            },
        )
        .unwrap();

    assert_eq!(built.bytes.len(), DEFAULT_MAX_LAYERS * 2);
    assert!(
        built.bytes[..DEFAULT_MAX_LAYERS]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert!(
        built.bytes[DEFAULT_MAX_LAYERS..]
            .iter()
            .all(|byte| *byte == 255)
    );
    let storage = built
        .bytes
        .try_into_mut()
        .expect("built bytes are uniquely owned");
    assert!(storage.capacity() <= DEFAULT_MAX_LAYERS * 2);
}

#[test]
fn alternating_one_sided_extensions_recenter_before_growing() {
    let mut buffer = PacketBuffer::default();
    for index in 0..64 {
        let byte = [u8::try_from(index).unwrap()];
        if index % 2 == 0 {
            buffer.wrap(&byte, &[], 1_024).unwrap();
        } else {
            buffer.wrap(&[], &byte, 1_024).unwrap();
        }
    }

    assert_eq!(buffer.len(), 64);
    assert!(buffer.storage.len() <= 128);
}

#[test]
fn padding_without_a_link_envelope_is_not_a_strict_ip_packet() {
    let mut packet = Packet::new();
    packet
        .push(Raw::default())
        .push(Padding::new(vec![0_u8; 4]));
    assert!(matches!(
        Builder::new(empty_registry()).build(
            packet,
            BuildContext::default(),
            BuildOptions::default(),
        ),
        Err(BuildError::PaddingWithoutLinkLayer { index: 1 })
    ));
}

#[test]
fn padding_coverage_boundary_must_reference_an_enclosing_layer() {
    let mut packet = Packet::new();
    packet
        .push(Raw::default())
        .push(Padding::after_layer(vec![0_u8; 4], 1));
    assert!(matches!(
        Builder::new(empty_registry()).build(
            packet,
            BuildContext::default(),
            BuildOptions::default(),
        ),
        Err(BuildError::InvalidPaddingBoundary {
            index: 1,
            outside_layer: 1
        })
    ));
}
