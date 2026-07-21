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
use super::super::layer::{FieldError, MalformedLayer, Padding, ProtocolId, Raw};
use super::super::layout::{ByteRange, LayerLayout, PacketLayout};
use super::super::registry::{CodecError, LayerEncodeContext, ProtocolRegistry};

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

/// A contiguous payload accumulator for the reverse encoder walk.
///
/// Codecs still receive one contiguous child slice, but outer headers grow
/// into front slack instead of rebuilding that child slice for every layer.
#[derive(Debug, Default)]
struct PacketBuffer {
    storage: Vec<u8>,
    start: usize,
    end: usize,
}

impl PacketBuffer {
    const MINIMUM_CAPACITY: usize = 64;

    fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    fn as_slice(&self) -> &[u8] {
        &self.storage[self.start..self.end]
    }

    fn wrap(&mut self, prefix: &[u8], suffix: &[u8], maximum: usize) -> Result<(), BuildError> {
        let total = prefix
            .len()
            .checked_add(self.len())
            .and_then(|value| value.checked_add(suffix.len()))
            .ok_or(BuildError::LengthOverflow)?;
        if total > maximum {
            return Err(BuildError::PacketSizeLimit {
                actual: total,
                limit: maximum,
            });
        }
        if self.start < prefix.len() || self.storage.len().saturating_sub(self.end) < suffix.len() {
            let additional = prefix
                .len()
                .checked_add(suffix.len())
                .ok_or(BuildError::LengthOverflow)?;
            if self.storage.len().saturating_sub(self.len()) >= additional {
                self.recenter_and_wrap(prefix, suffix, total)?;
            } else {
                self.grow_and_wrap(prefix, suffix, total, maximum)?;
            }
            return Ok(());
        }

        let start = self.start - prefix.len();
        self.storage[start..self.start].copy_from_slice(prefix);
        self.storage[self.end..self.end + suffix.len()].copy_from_slice(suffix);
        self.start = start;
        self.end += suffix.len();
        Ok(())
    }

    fn recenter_and_wrap(
        &mut self,
        prefix: &[u8],
        suffix: &[u8],
        total: usize,
    ) -> Result<(), BuildError> {
        let spare = self
            .storage
            .len()
            .checked_sub(total)
            .ok_or(BuildError::LengthOverflow)?;
        let start = spare / 2;
        let prefix_end = start
            .checked_add(prefix.len())
            .ok_or(BuildError::LengthOverflow)?;
        let payload_end = prefix_end
            .checked_add(self.len())
            .ok_or(BuildError::LengthOverflow)?;
        let end = payload_end
            .checked_add(suffix.len())
            .ok_or(BuildError::LengthOverflow)?;
        self.storage.copy_within(self.start..self.end, prefix_end);
        self.storage[start..prefix_end].copy_from_slice(prefix);
        self.storage[payload_end..end].copy_from_slice(suffix);
        self.start = start;
        self.end = end;
        Ok(())
    }

    fn grow_and_wrap(
        &mut self,
        prefix: &[u8],
        suffix: &[u8],
        total: usize,
        maximum: usize,
    ) -> Result<(), BuildError> {
        let minimum = Self::MINIMUM_CAPACITY.min(maximum);
        let doubled = self.storage.len().checked_mul(2).unwrap_or(maximum);
        let capacity = doubled.max(minimum).max(total).min(maximum);
        if capacity < total {
            return Err(BuildError::PacketSizeLimit {
                actual: total,
                limit: maximum,
            });
        }

        let mut storage = vec![0_u8; capacity];
        let spare = capacity - total;
        // The reverse encoder walk normally adds headers, but custom codecs
        // may add suffixes. Reserve the unused space on the active side for
        // one-sided codecs and split it for codecs that add both.
        let start = match (prefix.is_empty(), suffix.is_empty()) {
            (false, true) => spare,
            (true, false) => 0,
            _ => spare / 2,
        };
        let prefix_end = start
            .checked_add(prefix.len())
            .ok_or(BuildError::LengthOverflow)?;
        let payload_end = prefix_end
            .checked_add(self.len())
            .ok_or(BuildError::LengthOverflow)?;
        let end = payload_end
            .checked_add(suffix.len())
            .ok_or(BuildError::LengthOverflow)?;
        storage[start..prefix_end].copy_from_slice(prefix);
        storage[prefix_end..payload_end].copy_from_slice(self.as_slice());
        storage[payload_end..end].copy_from_slice(suffix);
        self.storage = storage;
        self.start = start;
        self.end = end;
        Ok(())
    }

    fn into_bytes(self) -> Bytes {
        if self.start == 0 && self.end == self.storage.len() {
            return Bytes::from(self.storage);
        }
        // Do not retain a geometric-growth allocation behind a small packet.
        // This bounded final flattening also returns exact-sized bytes when
        // the active packet is offset within the assembly buffer.
        Bytes::copy_from_slice(&self.storage[self.start..self.end])
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
        let pass_through_bytes = pass_through_byte_length(&packet)?;
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
                    protocol: layer.protocol_id(),
                    source,
                })?;
        }
        let protocols: Vec<_> = packet.iter().map(|layer| layer.protocol_id()).collect();
        self.validate_bindings(&packet, &protocols, options.mode, &mut diagnostics)?;

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
            let codec = self
                .registry
                .codec(&protocol)
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
            if actual != protocol {
                return Err(BuildError::MaterializedProtocolMismatch { protocol, actual });
            }
            encoded
                .materialized
                .validate_required_fields()
                .map_err(|source| BuildError::InvalidLayer {
                    index,
                    protocol: encoded.materialized.protocol_id(),
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
                    matches!(outside.protocol_id().as_str(), "ipv4" | "ipv6" | "udp")
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

    fn validate_bindings(
        &self,
        packet: &Packet,
        protocols: &[ProtocolId],
        mode: BuildMode,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> Result<(), BuildError> {
        debug_assert_eq!(protocols.len(), packet.len());
        for (index, layer) in packet.iter().enumerate() {
            let Some(padding) = layer.as_any().downcast_ref::<Padding>() else {
                continue;
            };
            if let Some(outside_layer) = padding.outside_layer {
                let Some(outside) = packet
                    .layer(outside_layer)
                    .filter(|_| outside_layer < index)
                else {
                    return Err(BuildError::InvalidPaddingBoundary {
                        index,
                        outside_layer,
                    });
                };
                if outside.as_any().is::<Padding>() || outside.as_any().is::<MalformedLayer>() {
                    return Err(BuildError::InvalidPaddingBoundary {
                        index,
                        outside_layer,
                    });
                }
                let outside_protocol = &protocols[outside_layer];
                let has_declared_boundary =
                    matches!(outside_protocol.as_str(), "ipv4" | "ipv6" | "udp" | "arp");
                if !has_declared_boundary {
                    if mode == BuildMode::Strict {
                        return Err(BuildError::InvalidPaddingBoundary {
                            index,
                            outside_layer,
                        });
                    }
                    diagnostics.push(
                        Diagnostic::warning(
                            "build.unsupported_padding_boundary",
                            format!(
                                "layer {outside_protocol} has no independent wire-length boundary"
                            ),
                        )
                        .at_layer(index),
                    );
                }
                if matches!(outside_protocol.as_str(), "ipv4" | "ipv6" | "udp") {
                    diagnostics.push(
                        Diagnostic::warning(
                            "build.padding_outside_network_length",
                            "preserving bytes outside a declared network or datagram length",
                        )
                        .at_layer(index),
                    );
                }
                continue;
            }
            let enclosed_by_link = protocols.iter().take(index).any(|protocol| {
                matches!(
                    protocol.as_str(),
                    "ethernet" | "bsd_null" | "bsd_loop" | "linux_sll" | "linux_sll2"
                )
            });
            if enclosed_by_link {
                continue;
            }
            if mode == BuildMode::Strict {
                return Err(BuildError::PaddingWithoutLinkLayer { index });
            }
            diagnostics.push(
                Diagnostic::warning(
                    "build.padding_without_link_layer",
                    "bytes outside all declared protocol lengths require a link-layer envelope",
                )
                .at_layer(index),
            );
        }

        let mut previous_binding = None;
        for index in 0..packet.len().saturating_sub(1) {
            let parent = &protocols[index];
            let child = &protocols[index + 1];
            let discriminator = match previous_binding {
                Some((previous_parent, previous_child, discriminator))
                    if previous_parent == parent && previous_child == child =>
                {
                    discriminator
                }
                _ => {
                    let discriminator = self.registry.discriminator_for(parent, child);
                    previous_binding = Some((parent, child, discriminator));
                    discriminator
                }
            };
            if discriminator.is_some()
                || parent.as_str() == "raw"
                || matches!(child.as_str(), "padding" | "malformed")
            {
                continue;
            }
            if mode == BuildMode::Strict {
                return Err(BuildError::UnboundLayers {
                    parent: parent.clone(),
                    child: child.clone(),
                });
            }
            diagnostics.push(
                Diagnostic::warning(
                    "build.unbound_layers",
                    format!("no registered binding from {parent} to {child}"),
                )
                .at_layer(index),
            );
        }
        Ok(())
    }
}

fn pass_through_byte_length(packet: &Packet) -> Result<usize, BuildError> {
    packet.iter().try_fold(0_usize, |total, layer| {
        let length = layer
            .as_any()
            .downcast_ref::<Raw>()
            .map(|layer| layer.bytes.len())
            .or_else(|| {
                layer
                    .as_any()
                    .downcast_ref::<Padding>()
                    .map(|layer| layer.bytes.len())
            })
            .or_else(|| {
                layer
                    .as_any()
                    .downcast_ref::<MalformedLayer>()
                    .map(|layer| layer.bytes.len())
            })
            .unwrap_or(0);
        total.checked_add(length).ok_or(BuildError::LengthOverflow)
    })
}

#[cfg(test)]
mod tests {
    use std::any::Any;
    use std::collections::BTreeMap;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::packet::layer::Raw;
    use crate::packet::{
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
                    protocol: self.protocol_id(),
                    field: name.to_owned(),
                    expected: "bytes",
                }),
                _ => Err(FieldError::UnknownField {
                    protocol: self.protocol_id(),
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
                protocol: self.protocol_id(),
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
                    actual: layer.protocol_id(),
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
            let byte = [index as u8];
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
