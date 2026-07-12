// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::diagnostic::Diagnostic;
use super::field::FieldValue;
use super::layer::{FieldError, MalformedLayer, Padding, ProtocolId};
use super::layout::{ByteRange, LayerLayout, PacketLayout};
use super::registry::{CodecError, LayerEncodeContext, ProtocolRegistry};
use super::Packet;

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
        // Reject definitely oversized byte-bearing layers before any codec
        // duplicates their buffers. Fixed headers only increase this lower
        // bound, so exceeding it can never produce a valid packet.
        let reflected_bytes = reflected_byte_length(&packet)?;
        if reflected_bytes > options.max_packet_size {
            return Err(BuildError::PacketSizeLimit {
                actual: reflected_bytes,
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
        self.validate_bindings(&packet, options.mode, &mut diagnostics)?;

        let mut materialized = packet.clone();
        let mut bytes = Vec::new();
        let mut layouts: Vec<Option<LayerLayout>> = vec![None; packet.len()];
        let mut encoded_payload_lengths = vec![None; packet.len()];

        for index in (0..packet.len()).rev() {
            let layer = packet
                .layer(index)
                .expect("validated layer index must remain present");
            let protocol = layer.protocol_id();
            let codec = self
                .registry
                .codec(&protocol)
                .ok_or_else(|| BuildError::MissingCodec {
                    index,
                    protocol: protocol.clone(),
                })?;
            let child = packet.layer(index + 1);
            encoded_payload_lengths[index] = Some(bytes.len());
            let remaining_packet_bytes = options.max_packet_size.checked_sub(bytes.len()).ok_or(
                BuildError::PacketSizeLimit {
                    actual: bytes.len(),
                    limit: options.max_packet_size,
                },
            )?;
            let encoded = codec
                .encode(
                    layer,
                    &bytes,
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

            let total = encoded
                .prefix
                .len()
                .checked_add(bytes.len())
                .and_then(|value| value.checked_add(encoded.suffix.len()))
                .ok_or(BuildError::LengthOverflow)?;
            if total > options.max_packet_size {
                return Err(BuildError::PacketSizeLimit {
                    actual: total,
                    limit: options.max_packet_size,
                });
            }

            if encoded.fields.iter().any(|field| {
                field.range.start > field.range.end || field.range.end > encoded.prefix.len()
            }) {
                return Err(BuildError::InvalidCodecLayout { protocol });
            }
            for layout in layouts.iter_mut().flatten() {
                if !layout.checked_shift(encoded.prefix.len()) {
                    return Err(BuildError::LengthOverflow);
                }
            }
            let fields = encoded.fields;
            layouts[index] = Some(LayerLayout {
                index,
                protocol: layer.protocol_id(),
                range: ByteRange::new(0, encoded.prefix.len()),
                fields,
            });

            let mut combined = Vec::with_capacity(total);
            combined.extend_from_slice(&encoded.prefix);
            combined.extend_from_slice(&bytes);
            combined.extend_from_slice(&encoded.suffix);
            bytes = combined;
            materialized
                .replace_boxed(index, encoded.materialized)
                .expect("materialized packet keeps source packet shape");
            diagnostics.extend(encoded.diagnostics.into_iter().map(|mut diagnostic| {
                if diagnostic.layer.is_none() {
                    diagnostic.layer = Some(index);
                }
                diagnostic
            }));
        }

        let layout = PacketLayout {
            layers: layouts.into_iter().flatten().collect(),
        };
        materialized.set_encoded_payload_lengths(encoded_payload_lengths);
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
            bytes: Bytes::from(bytes),
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
        mode: BuildMode,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> Result<(), BuildError> {
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
                let outside_protocol = outside.protocol_id();
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
            let enclosed_by_link = packet.iter().take(index).any(|layer| {
                matches!(
                    layer.protocol_id().as_str(),
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

        for index in 0..packet.len().saturating_sub(1) {
            let parent = packet.layer(index).expect("index in packet").protocol_id();
            let child = packet
                .layer(index + 1)
                .expect("child index in packet")
                .protocol_id();
            if self.registry.discriminator_for(&parent, &child).is_some()
                || parent.as_str() == "raw"
                || matches!(child.as_str(), "padding" | "malformed")
            {
                continue;
            }
            if mode == BuildMode::Strict {
                return Err(BuildError::UnboundLayers { parent, child });
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

fn reflected_byte_length(packet: &Packet) -> Result<usize, BuildError> {
    packet.iter().try_fold(0_usize, |total, layer| {
        layer
            .schema()
            .fields
            .iter()
            .try_fold(total, |total, field| {
                let length = match layer.field(field.name) {
                    Some(FieldValue::Bytes(bytes)) => bytes.len(),
                    _ => 0,
                };
                total.checked_add(length).ok_or(BuildError::LengthOverflow)
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::layer::Raw;

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
