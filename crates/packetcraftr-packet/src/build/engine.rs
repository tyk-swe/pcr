// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::super::Packet;
use super::super::diagnostic::Diagnostic;
use super::super::layer::{FieldError, MalformedLayer, Padding, ProtocolId};
use super::super::layout::{ByteRange, LayerLayout, PacketLayout};
use super::super::registry::{CodecError, LayerEncodeContext, ProtocolRegistry};
use super::super::semantics::BuiltinProtocol;

use buffer::PacketBuffer;

mod buffer;
mod validation;

pub const DEFAULT_MAX_PACKET_SIZE: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_LAYERS: usize = 64;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildMode {
    #[default]
    Strict,
    Permissive,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuildContext {
    pub source: Option<IpAddr>,
    pub destination: Option<IpAddr>,
    pub mtu: Option<u32>,
    pub link_type: Option<u32>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildOptions {
    pub mode: BuildMode,
    pub max_layers: usize,
    pub max_packet_size: usize,
}

impl Default for BuildOptions {
    fn default() -> Self {
        Self {
            mode: BuildMode::Strict,
            max_layers: DEFAULT_MAX_LAYERS,
            max_packet_size: DEFAULT_MAX_PACKET_SIZE,
        }
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BuildError {
    #[error("cannot build an empty packet")]
    EmptyPacket,
    #[error("packet has {actual} layers, exceeding configured limit {limit}")]
    LayerLimit { actual: usize, limit: usize },
    #[error("packet size {actual} exceeds configured limit {limit}")]
    PacketSizeLimit { actual: usize, limit: usize },
    #[error("no codec is registered for layer {protocol} at index {index}")]
    MissingCodec { index: usize, protocol: ProtocolId },
    #[error("layer {protocol} at index {index} violates its reflective schema: {source}")]
    InvalidLayer {
        index: usize,
        protocol: ProtocolId,
        #[source]
        source: FieldError,
    },
    #[error("layer {parent} cannot contain adjacent layer {child}")]
    UnboundLayers {
        parent: ProtocolId,
        child: ProtocolId,
    },
    #[error("failed to encode layer {protocol} at index {index}: {source}")]
    Codec {
        index: usize,
        protocol: ProtocolId,
        #[source]
        source: CodecError,
    },
    #[error("packet length arithmetic overflow")]
    LengthOverflow,
    #[error("could not allocate {requested} bytes for the packet buffer")]
    AllocationFailure { requested: usize },
    #[error("codec for layer {protocol} returned a different materialized layer {actual}")]
    MaterializedProtocolMismatch {
        protocol: ProtocolId,
        actual: ProtocolId,
    },
    #[error("codec for layer {protocol} returned an invalid byte layout")]
    InvalidCodecLayout { protocol: ProtocolId },
    #[error("padding layer at index {index} has invalid outside-layer boundary {outside_layer}")]
    InvalidPaddingBoundary { index: usize, outside_layer: usize },
    #[error("padding layer at index {index} has no enclosing link-layer frame")]
    PaddingWithoutLinkLayer { index: usize },
}

/// Exact encoded bytes plus the resolved packet, byte layout, and diagnostics.
#[derive(Clone, Debug)]
pub struct BuiltPacket {
    pub bytes: Bytes,
    pub packet: Packet,
    pub layout: PacketLayout,
    pub diagnostics: Vec<Diagnostic>,
    /// Live transmission must explicitly opt in when this is true.
    pub requires_live_opt_in: bool,
}

impl BuiltPacket {
    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }
}

#[derive(Clone, Debug)]
pub struct Builder {
    registry: Arc<ProtocolRegistry>,
}

impl Builder {
    pub fn new(registry: Arc<ProtocolRegistry>) -> Self {
        Self { registry }
    }

    pub fn registry(&self) -> &Arc<ProtocolRegistry> {
        &self.registry
    }

    /// Encodes a packet into exact wire bytes.
    ///
    /// # Panics
    ///
    /// Panics if a layer index validated earlier in the same call is no longer
    /// present, which would mean this builder had corrupted its own state.
    /// Malformed input is reported through [`BuildError`] instead.
    pub fn build(
        &self,
        packet: Packet,
        context: BuildContext,
        options: BuildOptions,
    ) -> Result<BuiltPacket, BuildError> {
        if packet.is_empty() {
            return Err(BuildError::EmptyPacket);
        }
        if packet.len() > options.max_layers {
            return Err(BuildError::LayerLimit {
                actual: packet.len(),
                limit: options.max_layers,
            });
        }
        // Reject definitely oversized pass-through layers before their codecs
        // duplicate the buffers. An arbitrary external byte-valued reflective
        // field is not necessarily emitted on the wire, so it cannot safely be
        // included in this lower bound.
        let pass_through_bytes = validation::pass_through_byte_length(&packet)?;
        if pass_through_bytes > options.max_packet_size {
            return Err(BuildError::PacketSizeLimit {
                actual: pass_through_bytes,
                limit: options.max_packet_size,
            });
        }

        let mut diagnostics = Vec::new();
        for (index, layer) in packet.iter().enumerate() {
            layer
                .validate_required_fields()
                .map_err(|source| BuildError::InvalidLayer {
                    index,
                    protocol: layer.protocol_id().clone(),
                    source,
                })?;
        }
        let protocols: Vec<_> = packet
            .iter()
            .map(|layer| layer.protocol_id().clone())
            .collect();
        validation::validate_bindings(
            &self.registry,
            &packet,
            &protocols,
            options.mode,
            &mut diagnostics,
        )?;

        // The reverse walk keeps the source packet intact for every codec and
        // accumulates each materialized result once before restoring source order.
        let mut bytes = PacketBuffer::default();
        let mut layouts = Vec::with_capacity(packet.len());
        let mut materialized_layers = Vec::with_capacity(packet.len());
        let mut encoded_payload_lengths = Vec::with_capacity(packet.len());

        for (index, protocol) in protocols.into_iter().enumerate().rev() {
            let layer = packet
                .layer(index)
                .expect("validated layer index must remain present");
            let codec =
                self.registry
                    .codec(protocol.as_str())
                    .ok_or_else(|| BuildError::MissingCodec {
                        index,
                        protocol: protocol.clone(),
                    })?;
            let child = packet.layer(index + 1);
            encoded_payload_lengths.push(Some(bytes.len()));
            let remaining_packet_bytes = options.max_packet_size.checked_sub(bytes.len()).ok_or(
                BuildError::PacketSizeLimit {
                    actual: bytes.len(),
                    limit: options.max_packet_size,
                },
            )?;
            let encoded = codec
                .encode(
                    layer,
                    bytes.as_slice(),
                    &LayerEncodeContext {
                        packet: &packet,
                        index,
                        build_context: &context,
                        mode: options.mode,
                        registry: &self.registry,
                        child,
                        remaining_packet_bytes,
                    },
                )
                .map_err(|source| BuildError::Codec {
                    index,
                    protocol: protocol.clone(),
                    source,
                })?;

            let actual = encoded.materialized.protocol_id();
            if actual != &protocol {
                return Err(BuildError::MaterializedProtocolMismatch {
                    protocol,
                    actual: actual.clone(),
                });
            }
            encoded
                .materialized
                .validate_required_fields()
                .map_err(|source| BuildError::InvalidLayer {
                    index,
                    protocol: encoded.materialized.protocol_id().clone(),
                    source,
                })?;

            if encoded.fields.iter().any(|field| {
                field.range.start > field.range.end || field.range.end > encoded.prefix.len()
            }) {
                return Err(BuildError::InvalidCodecLayout { protocol });
            }
            let fields = encoded.fields;
            layouts.push(LayerLayout {
                index,
                protocol,
                range: ByteRange::new(0, encoded.prefix.len()),
                fields,
            });

            bytes.wrap(&encoded.prefix, &encoded.suffix, options.max_packet_size)?;
            materialized_layers.push(encoded.materialized);
            diagnostics.extend(encoded.diagnostics.into_iter().map(|mut diagnostic| {
                if diagnostic.layer.is_none() {
                    diagnostic.layer = Some(index);
                }
                diagnostic
            }));
        }

        layouts.reverse();
        let mut layout_offset = 0usize;
        for layout in &mut layouts {
            if !layout.checked_shift(layout_offset) {
                return Err(BuildError::LengthOverflow);
            }
            layout_offset = layout_offset
                .checked_add(layout.range.len())
                .ok_or(BuildError::LengthOverflow)?;
        }
        let layout = PacketLayout { layers: layouts };
        materialized_layers.reverse();
        encoded_payload_lengths.reverse();
        let materialized =
            Packet::from_encoded_layers(materialized_layers, encoded_payload_lengths);
        let contains_malformed = materialized
            .iter()
            .any(|layer| layer.as_any().is::<MalformedLayer>());
        let contains_network_trailer = materialized.iter().any(|layer| {
            layer
                .as_any()
                .downcast_ref::<Padding>()
                .and_then(|padding| padding.outside_layer)
                .and_then(|outside_layer| materialized.layer(outside_layer))
                .is_some_and(|outside| {
                    matches!(
                        BuiltinProtocol::of(outside),
                        Some(
                            BuiltinProtocol::Ipv4
                                | BuiltinProtocol::Ipv6
                                | BuiltinProtocol::Udp
                                | BuiltinProtocol::Pppoe
                        )
                    )
                })
        });
        Ok(BuiltPacket {
            bytes: bytes.into_bytes(),
            packet: materialized,
            layout,
            diagnostics,
            requires_live_opt_in: options.mode == BuildMode::Permissive
                || contains_malformed
                || contains_network_trailer,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::any::Any;
    use std::collections::BTreeMap;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::layer::Raw;
    use crate::{
        codec::{DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext},
        field::{FieldKind, FieldValue},
        layer::{FieldSchema, Layer, LayerSchema},
        registry::RegistryBuilder,
    };

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
            .into_bytes()
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
}
