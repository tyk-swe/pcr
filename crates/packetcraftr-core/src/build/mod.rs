// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact packet construction.

use std::sync::Arc;

use crate::Packet;
use crate::codec::LayerEncodeContext;
use crate::layer::{MalformedLayer, Padding};
use crate::layout::{ByteRange, LayerLayout, PacketLayout};
use crate::registry::ProtocolRegistry;
use crate::semantics::BuiltinProtocol;

use buffer::PacketBuffer;

mod buffer;
mod error;
mod options;
mod validation;

pub use error::BuildError;
pub use options::{
    BuildContext, BuildMode, BuildOptions, BuiltPacket, DEFAULT_MAX_LAYERS, DEFAULT_MAX_PACKET_SIZE,
};

// Compatibility aliases retained for existing callers.
pub use error::BuildError as Error;
pub use options::{
    BuildContext as Context, BuildMode as Mode, BuildOptions as Options, BuiltPacket as Result,
};

#[derive(Clone, Debug)]
pub struct Builder {
    registry: Arc<ProtocolRegistry>,
}

impl Builder {
    pub fn new(registry: Arc<ProtocolRegistry>) -> Self {
        Self { registry }
    }

    /// Encodes a packet into exact wire bytes.
    ///
    /// # Panics
    ///
    /// Panics only if the builder corrupts its validated state; malformed input returns
    /// [`BuildError`].
    pub fn build(
        &self,
        packet: Packet,
        context: BuildContext,
        options: BuildOptions,
    ) -> std::result::Result<BuiltPacket, BuildError> {
        if packet.is_empty() {
            return Err(BuildError::EmptyPacket);
        }
        if packet.len() > options.max_layers {
            return Err(BuildError::LayerLimit {
                actual: packet.len(),
                limit: options.max_layers,
            });
        }
        // Only pass-through bytes are a safe pre-encoding lower bound; other fields might not
        // reach the wire.
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

        // Encode in reverse, then restore source order.
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
