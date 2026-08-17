// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Stateful decode traversal and result assembly.

use std::ops::Range;

use bytes::Bytes;

use crate::Packet;
use crate::codec::{DecodedLayerValue, Error as CodecError, LayerCodec, LayerDecodeContext};
use crate::diagnostic::Diagnostic;
use crate::frame::Frame;
use crate::layer::Id as ProtocolId;
use crate::layout::{ByteRange, LayerLayout, PacketLayout};
use crate::registry::{Discriminator, Registry as ProtocolRegistry};

use super::error::Error;
use super::fallback::{
    append_malformed, append_missing_required_layer, append_padding, append_raw, slice_original,
};
use super::options::{DecodedPacket, Options as DecodeOptions};
use super::traversal::TraversalScope;

struct DecodeCursor {
    protocol: ProtocolId,
    discriminator: Option<Discriminator>,
    bytes: Range<usize>,
}

struct ChildSelection {
    protocol: Option<ProtocolId>,
    discriminator: Option<Discriminator>,
}

struct TrailingBytes {
    offset: usize,
    bytes: Bytes,
    outside_layer: usize,
}

struct ValidatedLayer {
    decoded: DecodedLayerValue,
    protocol: ProtocolId,
    layer_end: usize,
    payload_end: usize,
}

pub(super) struct DecodeSession<'registry> {
    registry: &'registry ProtocolRegistry,
    root: ProtocolId,
    frame: Frame,
    original: Bytes,
    options: DecodeOptions,
    packet: Packet,
    layouts: Vec<LayerLayout>,
    diagnostics: Vec<Diagnostic>,
    trailing: Vec<TrailingBytes>,
    traversal: TraversalScope,
}

impl<'registry> DecodeSession<'registry> {
    pub(super) fn new(
        registry: &'registry ProtocolRegistry,
        frame: Frame,
        root: ProtocolId,
        options: DecodeOptions,
    ) -> Self {
        let original = frame.bytes().clone();
        let traversal = TraversalScope::new(&root);
        Self {
            registry,
            root,
            frame,
            original,
            options,
            packet: Packet::new(),
            layouts: Vec::new(),
            diagnostics: Vec::new(),
            trailing: Vec::new(),
            traversal,
        }
    }

    pub(super) fn run(mut self) -> Result<DecodedPacket, Error> {
        let mut cursor = DecodeCursor {
            protocol: self.root.clone(),
            discriminator: None,
            bytes: 0..self.original.len(),
        };
        loop {
            self.ensure_layer_capacity()?;
            let Some(codec) = self.registry.codec(cursor.protocol.as_str()) else {
                self.preserve_missing_codec(&cursor)?;
                break;
            };
            let allow_link_padding = self.traversal.allows_current_link_padding();
            let decoded = match self.decode_layer(codec.as_ref(), &cursor, allow_link_padding) {
                Ok(decoded) => decoded,
                Err(source) => {
                    self.preserve_malformed_layer(&cursor, source.to_string());
                    break;
                }
            };
            let layer = self.validate_layer(codec.as_ref(), &cursor, decoded)?;
            self.preserve_trailing_bytes(&cursor, &layer, allow_link_padding);
            let child = self.select_child(&layer);
            let next = self.commit_layer(cursor, layer, child)?;
            let Some(next) = next else {
                break;
            };
            cursor = next;
        }
        self.finish()
    }

    fn ensure_layer_capacity(&self) -> Result<(), Error> {
        if self.packet.len() >= self.options.max_layers {
            return Err(Error::LayerLimit {
                limit: self.options.max_layers,
            });
        }
        Ok(())
    }

    fn decode_layer(
        &self,
        codec: &dyn LayerCodec,
        cursor: &DecodeCursor,
        allow_link_padding: bool,
    ) -> Result<DecodedLayerValue, CodecError> {
        codec.decode(
            &self.original[cursor.bytes.clone()],
            &LayerDecodeContext {
                registry: self.registry,
                layer_index: self.packet.len(),
                absolute_offset: cursor.bytes.start,
                verify_checksums: self.options.verify_checksums,
                allow_trailing_padding: allow_link_padding,
                network: self.traversal.network(),
                discriminator: cursor.discriminator,
            },
        )
    }

    fn preserve_missing_codec(&mut self, cursor: &DecodeCursor) -> Result<(), Error> {
        if self.packet.is_empty() {
            return Err(Error::MissingRootCodec {
                protocol: cursor.protocol.clone(),
            });
        }
        append_raw(
            &mut self.packet,
            &mut self.layouts,
            slice_original(&self.original, cursor.bytes.start, cursor.bytes.len()),
            cursor.bytes.start,
        );
        self.diagnostics.push(Diagnostic::warning(
            "decode.missing_codec",
            format!("no codec registered for {}", cursor.protocol),
        ));
        Ok(())
    }

    fn preserve_malformed_layer(&mut self, cursor: &DecodeCursor, message: String) {
        let index = self.packet.len();
        append_malformed(
            &mut self.packet,
            &mut self.layouts,
            Some(cursor.protocol.clone()),
            slice_original(&self.original, cursor.bytes.start, cursor.bytes.len()),
            message.clone(),
            cursor.bytes.start,
        );
        self.diagnostics
            .push(Diagnostic::error("decode.malformed_layer", message).at_layer(index));
    }

    fn validate_layer(
        &self,
        codec: &dyn LayerCodec,
        cursor: &DecodeCursor,
        mut decoded: DecodedLayerValue,
    ) -> Result<ValidatedLayer, Error> {
        let actual_protocol = decoded.layer.protocol_id().clone();
        if !codec.accepts_decoded_protocol(&actual_protocol) {
            return Err(Error::CodecLayerMismatch {
                protocol: cursor.protocol.clone(),
                actual: actual_protocol,
            });
        }
        decoded
            .layer
            .validate_required_fields()
            .map_err(|source| Error::InvalidLayer {
                protocol: actual_protocol.clone(),
                source,
            })?;

        let input_len = cursor.bytes.len();
        if decoded.consumed > input_len || (!decoded.stop && decoded.consumed == 0) {
            return Err(Error::InvalidCodecCursor {
                protocol: cursor.protocol.clone(),
            });
        }
        let payload_end = decoded
            .consumed
            .checked_add(decoded.payload_len)
            .filter(|end| *end <= input_len)
            .and_then(|end| cursor.bytes.start.checked_add(end))
            .ok_or_else(|| Error::InvalidCodecCursor {
                protocol: cursor.protocol.clone(),
            })?;
        let layer_end = cursor
            .bytes
            .start
            .checked_add(decoded.consumed)
            .ok_or_else(|| Error::InvalidCodecCursor {
                protocol: cursor.protocol.clone(),
            })?;

        if decoded
            .fields
            .iter()
            .any(|field| field.range.start > field.range.end || field.range.end > decoded.consumed)
        {
            return Err(Error::InvalidCodecLayout {
                protocol: cursor.protocol.clone(),
            });
        }
        for field in &mut decoded.fields {
            if !field.range.checked_shift(cursor.bytes.start) {
                return Err(Error::InvalidCodecLayout {
                    protocol: cursor.protocol.clone(),
                });
            }
        }
        Ok(ValidatedLayer {
            decoded,
            protocol: actual_protocol,
            layer_end,
            payload_end,
        })
    }

    fn preserve_trailing_bytes(
        &mut self,
        cursor: &DecodeCursor,
        layer: &ValidatedLayer,
        allow_link_padding: bool,
    ) {
        if layer.payload_end == cursor.bytes.end {
            return;
        }
        let byte_count = cursor.bytes.end - layer.payload_end;
        self.trailing.push(TrailingBytes {
            offset: layer.payload_end,
            bytes: slice_original(&self.original, layer.payload_end, byte_count),
            outside_layer: self.packet.len(),
        });
        let message = format!(
            "preserved {byte_count} byte(s) outside the declared length of {}",
            cursor.protocol
        );
        let diagnostic = if allow_link_padding {
            Diagnostic::info("decode.trailing_padding", message)
        } else {
            Diagnostic::warning("decode.trailing_malformed", message)
        };
        self.diagnostics
            .push(diagnostic.at_layer(self.packet.len()));
    }

    fn select_child(&self, layer: &ValidatedLayer) -> ChildSelection {
        let selected = layer.decoded.next.iter().find_map(|value| {
            self.registry
                .child_for(layer.protocol.as_str(), *value)
                .map(|protocol| (*value, protocol.clone()))
        });
        ChildSelection {
            discriminator: selected.as_ref().map(|(value, _)| *value),
            protocol: selected.map(|(_, protocol)| protocol),
        }
    }

    fn commit_layer(
        &mut self,
        cursor: DecodeCursor,
        layer: ValidatedLayer,
        child: ChildSelection,
    ) -> Result<Option<DecodeCursor>, Error> {
        let index = self.packet.len();
        let ValidatedLayer {
            decoded,
            protocol: decoded_protocol,
            layer_end,
            payload_end,
        } = layer;
        self.layouts.push(LayerLayout {
            index,
            protocol: decoded_protocol.clone(),
            range: ByteRange::new(cursor.bytes.start, layer_end),
            fields: decoded.fields,
        });
        self.traversal.accept_network(decoded.network);
        self.traversal
            .enter_child(&decoded_protocol, child.protocol.as_ref());
        self.packet.push_boxed(decoded.layer);
        self.diagnostics
            .extend(decoded.diagnostics.into_iter().map(|mut diagnostic| {
                if diagnostic.layer.is_none() {
                    diagnostic.layer = Some(index);
                }
                diagnostic
            }));

        if decoded.payload_len == 0 {
            self.preserve_missing_required_child(
                index,
                &decoded_protocol,
                child.protocol,
                layer_end,
            )?;
            return Ok(None);
        }
        if decoded.stop {
            self.preserve_terminal_payload(
                index,
                &cursor.protocol,
                layer_end,
                decoded.payload_len,
            )?;
            return Ok(None);
        }
        let Some(next_protocol) = child.protocol else {
            self.preserve_unknown_child(&decoded_protocol, layer_end, decoded.payload_len)?;
            return Ok(None);
        };
        Ok(Some(DecodeCursor {
            protocol: next_protocol,
            discriminator: child.discriminator,
            bytes: layer_end..payload_end,
        }))
    }

    fn preserve_missing_required_child(
        &mut self,
        parent_index: usize,
        parent: &ProtocolId,
        child: Option<ProtocolId>,
        offset: usize,
    ) -> Result<(), Error> {
        let Some(required) = child.filter(|protocol| {
            !matches!(
                crate::semantics::BuiltinProtocol::from_id(protocol),
                Some(
                    crate::semantics::BuiltinProtocol::Raw
                        | crate::semantics::BuiltinProtocol::Malformed
                        | crate::semantics::BuiltinProtocol::Padding
                )
            )
        }) else {
            return Ok(());
        };
        self.ensure_layer_capacity()?;
        let message = format!("{parent} discriminator requires {required}, but no bytes remain");
        append_missing_required_layer(&mut self.packet, &mut self.layouts, required, offset);
        self.diagnostics.push(
            Diagnostic::error("decode.missing_required_child", message).at_layer(parent_index),
        );
        Ok(())
    }

    fn preserve_terminal_payload(
        &mut self,
        parent_index: usize,
        protocol: &ProtocolId,
        offset: usize,
        payload_len: usize,
    ) -> Result<(), Error> {
        self.ensure_layer_capacity()?;
        append_raw(
            &mut self.packet,
            &mut self.layouts,
            slice_original(&self.original, offset, payload_len),
            offset,
        );
        self.diagnostics.push(
            Diagnostic::warning(
                "decode.terminal_payload",
                format!(
                    "codec for {protocol} stopped with {payload_len} unconsumed payload byte(s); preserved as Raw"
                ),
            )
            .at_layer(parent_index),
        );
        Ok(())
    }

    fn preserve_unknown_child(
        &mut self,
        parent: &ProtocolId,
        offset: usize,
        payload_len: usize,
    ) -> Result<(), Error> {
        self.ensure_layer_capacity()?;
        append_raw(
            &mut self.packet,
            &mut self.layouts,
            slice_original(&self.original, offset, payload_len),
            offset,
        );
        self.diagnostics.push(Diagnostic::warning(
            "decode.unknown_binding",
            format!("unknown child discriminator after {parent}"),
        ));
        Ok(())
    }

    fn finish(mut self) -> Result<DecodedPacket, Error> {
        self.trailing.sort_by_key(|trailing| trailing.offset);
        let trailing = std::mem::take(&mut self.trailing);
        for trailing in trailing {
            self.ensure_layer_capacity()?;
            // Keep explicit coverage ownership so a strict byte-for-byte
            // rebuild preserves the declared protocol length. The builder
            // marks padding outside a network root as requiring live
            // malformed-traffic opt-in.
            append_padding(
                &mut self.packet,
                &mut self.layouts,
                trailing.bytes,
                trailing.offset,
                trailing.outside_layer,
            );
        }
        let encoded_payload_lengths = self
            .layouts
            .iter()
            .map(|layout| self.original.len().checked_sub(layout.range.end))
            .collect();
        self.packet
            .set_encoded_payload_lengths(encoded_payload_lengths);
        Ok(DecodedPacket {
            packet: self.packet,
            original: self.original,
            frame: self.frame,
            layout: PacketLayout {
                layers: self.layouts,
            },
            diagnostics: self.diagnostics,
        })
    }
}
