// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact packet construction.

use std::sync::Arc;

use crate::Packet;
use crate::codec::LayerEncodeContext;
use crate::layer::{Id, Malformed, Padding};
use crate::layout::{ByteRange, LayerLayout, PacketLayout};
use crate::protocol::BuiltinProtocol;
use crate::registry::Registry;

use buffer::PacketBuffer;

mod buffer;
mod error;
mod options;
mod validation;

/// Re-exported so a builder caller names the encoding mode, the address
/// context, and the default ceilings without importing the codec contract or
/// the layout module. These are the same items, not copies.
pub use crate::codec::{Context, Mode};
pub use crate::layout::{DEFAULT_MAX_LAYERS, DEFAULT_MAX_PACKET_SIZE};
pub use error::Error;
pub use options::{BuiltPacket, Options};

#[derive(Clone, Debug)]
pub struct Builder {
    registry: Arc<Registry>,
}

struct Encoding {
    bytes: PacketBuffer,
    layouts: Vec<LayerLayout>,
    layers: Vec<Box<dyn crate::layer::Layer>>,
    payload_lengths: Vec<Option<usize>>,
    diagnostics: Vec<crate::diagnostic::Diagnostic>,
}

impl Builder {
    pub fn new(registry: Arc<Registry>) -> Self {
        Self { registry }
    }

    /// Encodes a packet into exact wire bytes.
    ///
    /// # Panics
    ///
    /// Panics only if the builder corrupts its validated state; malformed input returns
    /// [`Error`].
    pub fn build(
        &self,
        packet: Packet,
        context: Context,
        options: Options,
    ) -> Result<BuiltPacket, Error> {
        let mut diagnostics = Vec::new();
        let protocols = self.validate_packet(&packet, &options, &mut diagnostics)?;
        let encoding = self.encode_layers(&packet, protocols, &context, &options, diagnostics)?;
        Self::finalize(encoding, options.mode)
    }

    fn validate_packet(
        &self,
        packet: &Packet,
        options: &Options,
        diagnostics: &mut Vec<crate::diagnostic::Diagnostic>,
    ) -> Result<Vec<Id>, Error> {
        if packet.is_empty() {
            return Err(Error::EmptyPacket);
        }
        if packet.len() > options.max_layers {
            return Err(Error::LayerLimit {
                actual: packet.len(),
                limit: options.max_layers,
            });
        }
        // Only pass-through bytes are a safe pre-encoding lower bound; other fields might not
        // reach the wire.
        let pass_through_bytes = validation::pass_through_byte_length(packet)?;
        if pass_through_bytes > options.max_packet_size {
            return Err(Error::PacketSizeLimit {
                actual: pass_through_bytes,
                limit: options.max_packet_size,
            });
        }

        for (index, layer) in packet.iter().enumerate() {
            layer
                .validate_required_fields()
                .map_err(|source| Error::InvalidLayer {
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
            packet,
            &protocols,
            options.mode,
            diagnostics,
        )?;
        Ok(protocols)
    }

    fn encode_layers(
        &self,
        packet: &Packet,
        protocols: Vec<Id>,
        context: &Context,
        options: &Options,
        mut diagnostics: Vec<crate::diagnostic::Diagnostic>,
    ) -> Result<Encoding, Error> {
        let mut bytes = PacketBuffer::default();
        let mut layouts = Vec::with_capacity(packet.len());
        let mut layers = Vec::with_capacity(packet.len());
        let mut payload_lengths = Vec::with_capacity(packet.len());

        for (index, protocol) in protocols.into_iter().enumerate().rev() {
            let layer = packet
                .layer(index)
                .expect("validated layer index must remain present");
            let codec =
                self.registry
                    .codec(protocol.as_str())
                    .ok_or_else(|| Error::MissingCodec {
                        index,
                        protocol: protocol.clone(),
                    })?;
            #[expect(
                clippy::arithmetic_side_effects,
                reason = "`index` comes from enumerating `protocols`, so it is below its length"
            )]
            let child = packet.layer(index + 1);
            payload_lengths.push(Some(bytes.len()));
            let remaining_packet_bytes = remaining_packet_bytes(&bytes, options)?;
            let encoded = codec
                .encode(
                    layer,
                    bytes.as_slice(),
                    &LayerEncodeContext {
                        packet,
                        index,
                        build_context: context,
                        mode: options.mode,
                        registry: &self.registry,
                        child,
                        remaining_packet_bytes,
                    },
                )
                .map_err(|source| Error::Codec {
                    index,
                    protocol: protocol.clone(),
                    source,
                })?;

            let actual = encoded.materialized.protocol_id();
            if actual != &protocol {
                return Err(Error::MaterializedProtocolMismatch {
                    protocol,
                    actual: actual.clone(),
                });
            }
            encoded
                .materialized
                .validate_required_fields()
                .map_err(|source| Error::InvalidLayer {
                    index,
                    protocol: encoded.materialized.protocol_id().clone(),
                    source,
                })?;

            if encoded.fields.iter().any(|field| {
                field.range.start > field.range.end || field.range.end > encoded.prefix.len()
            }) {
                return Err(Error::InvalidCodecLayout { protocol });
            }
            let fields = encoded.fields;
            layouts.push(LayerLayout {
                index,
                protocol,
                range: ByteRange::new(0, encoded.prefix.len()),
                fields,
            });

            bytes.wrap(&encoded.prefix, &encoded.suffix, options.max_packet_size)?;
            layers.push(encoded.materialized);
            diagnostics.extend(encoded.diagnostics.into_iter().map(|mut diagnostic| {
                if diagnostic.layer.is_none() {
                    diagnostic.layer = Some(index);
                }
                diagnostic
            }));
        }
        Ok(Encoding {
            bytes,
            layouts,
            layers,
            payload_lengths,
            diagnostics,
        })
    }

    fn finalize(mut encoding: Encoding, mode: Mode) -> Result<BuiltPacket, Error> {
        encoding.layouts.reverse();
        let mut layout_offset = 0usize;
        for layout in &mut encoding.layouts {
            if !layout.checked_shift(layout_offset) {
                return Err(Error::LengthOverflow);
            }
            layout_offset = layout_offset
                .checked_add(layout.range.len())
                .ok_or(Error::LengthOverflow)?;
        }
        let layout = PacketLayout::new(encoding.layouts);
        encoding.layers.reverse();
        encoding.payload_lengths.reverse();
        let materialized = Packet::from_encoded_layers(encoding.layers, encoding.payload_lengths);
        let contains_malformed = materialized
            .iter()
            .any(|layer| layer.as_any().is::<Malformed>());
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
            bytes: encoding.bytes.into_bytes(),
            packet: materialized,
            layout,
            diagnostics: encoding.diagnostics,
            requires_live_opt_in: mode == Mode::Permissive
                || contains_malformed
                || contains_network_trailer,
        })
    }
}

fn remaining_packet_bytes(bytes: &PacketBuffer, options: &Options) -> Result<usize, Error> {
    options
        .max_packet_size
        .checked_sub(bytes.len())
        .ok_or(Error::PacketSizeLimit {
            actual: bytes.len(),
            limit: options.max_packet_size,
        })
}
