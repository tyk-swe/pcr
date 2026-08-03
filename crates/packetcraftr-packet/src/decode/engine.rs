// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use bytes::Bytes;
use thiserror::Error;

use packetcraftr_core::frame::{Frame, FrameError as CaptureError, LinkType};

use super::super::Packet;
use super::super::build::{DEFAULT_MAX_LAYERS, DEFAULT_MAX_PACKET_SIZE};
use super::super::diagnostic::Diagnostic;
use super::super::layer::{FieldError, MalformedLayer, ProtocolId};
use super::super::layout::{ByteRange, LayerLayout, PacketLayout};
use super::super::registry::{LayerDecodeContext, ProtocolRegistry};
use super::super::semantics::BuiltinProtocol;

use fallback::{
    append_missing_required_layer, append_padding, append_raw, raw_decoded_frame, slice_original,
};
use traversal::TraversalScope;

mod fallback;
mod traversal;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeOptions {
    pub max_layers: usize,
    pub max_packet_size: usize,
    pub verify_checksums: bool,
}

impl Default for DecodeOptions {
    fn default() -> Self {
        Self {
            max_layers: DEFAULT_MAX_LAYERS,
            max_packet_size: DEFAULT_MAX_PACKET_SIZE,
            verify_checksums: true,
        }
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DecodeError {
    #[error("captured packet size {actual} exceeds configured limit {limit}")]
    PacketSizeLimit { actual: usize, limit: usize },
    #[error("decoded layer count reached configured limit {limit}")]
    LayerLimit { limit: usize },
    #[error("no codec is registered for root protocol {protocol}")]
    MissingRootCodec { protocol: ProtocolId },
    #[error("codec for {protocol} returned an invalid cursor range")]
    InvalidCodecCursor { protocol: ProtocolId },
    #[error("codec for {protocol} returned an invalid field layout")]
    InvalidCodecLayout { protocol: ProtocolId },
    #[error("codec for {protocol} returned layer {actual}")]
    CodecLayerMismatch {
        protocol: ProtocolId,
        actual: ProtocolId,
    },
    #[error("codec for {protocol} returned a layer that violates its reflective schema: {source}")]
    InvalidLayer {
        protocol: ProtocolId,
        #[source]
        source: FieldError,
    },
    #[error("invalid capture record: {0}")]
    InvalidCaptureRecord(#[from] CaptureError),
}

#[derive(Clone, Debug)]
pub struct DecodedPacket {
    pub packet: Packet,
    pub original: Bytes,
    pub frame: Frame,
    pub layout: PacketLayout,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Debug)]
pub struct Dissector {
    registry: Arc<ProtocolRegistry>,
}

impl Dissector {
    pub fn new(registry: Arc<ProtocolRegistry>) -> Self {
        Self { registry }
    }

    pub fn decode(
        &self,
        frame: Frame,
        options: DecodeOptions,
    ) -> Result<DecodedPacket, DecodeError> {
        if options.max_layers == 0 {
            return Err(DecodeError::LayerLimit { limit: 0 });
        }
        if frame.bytes().len() > options.max_packet_size {
            return Err(DecodeError::PacketSizeLimit {
                actual: frame.bytes().len(),
                limit: options.max_packet_size,
            });
        }
        let original = frame.bytes().clone();
        let Some(root) = self.registry.root_for_link_type(frame.link_type.0).cloned() else {
            let link_type = frame.link_type.0;
            return Ok(raw_decoded_frame(
                frame,
                Diagnostic::warning(
                    "decode.unsupported_link_type",
                    format!("no root binding for link type {link_type}"),
                ),
            ));
        };
        self.decode_from_root(frame, root, options, original)
    }

    pub fn decode_with_root(
        &self,
        bytes: impl Into<Bytes>,
        root: ProtocolId,
        options: DecodeOptions,
    ) -> Result<DecodedPacket, DecodeError> {
        let bytes = bytes.into();
        if bytes.len() > options.max_packet_size {
            return Err(DecodeError::PacketSizeLimit {
                actual: bytes.len(),
                limit: options.max_packet_size,
            });
        }
        let frame = Frame::new(
            std::time::SystemTime::UNIX_EPOCH,
            LinkType(u32::MAX),
            bytes.clone(),
        )?;
        if options.max_layers == 0 {
            return Err(DecodeError::LayerLimit { limit: 0 });
        }
        self.decode_from_root(frame, root, options, bytes)
    }

    fn decode_from_root(
        &self,
        frame: Frame,
        root: ProtocolId,
        options: DecodeOptions,
        original: Bytes,
    ) -> Result<DecodedPacket, DecodeError> {
        let mut traversal = TraversalScope::new(&root);
        let mut packet = Packet::new();
        let mut layouts = Vec::new();
        let mut diagnostics = Vec::new();
        let mut current_protocol = root;
        let mut current = original.as_ref();
        let mut absolute_offset = 0usize;
        let mut current_discriminator = None;
        let mut trailing = Vec::<(usize, Bytes, usize)>::new();

        loop {
            if packet.len() >= options.max_layers {
                return Err(DecodeError::LayerLimit {
                    limit: options.max_layers,
                });
            }
            let Some(codec) = self.registry.codec(current_protocol.as_str()) else {
                if packet.is_empty() {
                    return Err(DecodeError::MissingRootCodec {
                        protocol: current_protocol,
                    });
                }
                append_raw(
                    &mut packet,
                    &mut layouts,
                    slice_original(&original, absolute_offset, current.len()),
                    absolute_offset,
                );
                diagnostics.push(Diagnostic::warning(
                    "decode.missing_codec",
                    format!("no codec registered for {current_protocol}"),
                ));
                break;
            };
            let index = packet.len();
            // Once an enclosing IP layer has established a network envelope,
            // bytes outside a child's declared length are still covered by
            // that IP packet and cannot be link-layer padding.
            let allow_current_link_padding = traversal.allows_current_link_padding();
            let decoded = match codec.decode(
                current,
                &LayerDecodeContext {
                    registry: &self.registry,
                    layer_index: index,
                    absolute_offset,
                    verify_checksums: options.verify_checksums,
                    allow_trailing_padding: allow_current_link_padding,
                    network: traversal.network(),
                    discriminator: current_discriminator,
                },
            ) {
                Ok(decoded) => decoded,
                Err(source) => {
                    let message = source.to_string();
                    packet.push_boxed(Box::new(MalformedLayer::new(
                        Some(current_protocol.clone()),
                        slice_original(&original, absolute_offset, current.len()),
                        message.clone(),
                    )));
                    layouts.push(LayerLayout {
                        index,
                        protocol: ProtocolId::new(BuiltinProtocol::Malformed.as_str()),
                        range: ByteRange::new(
                            absolute_offset,
                            absolute_offset.saturating_add(current.len()),
                        ),
                        fields: Vec::new(),
                    });
                    diagnostics
                        .push(Diagnostic::error("decode.malformed_layer", message).at_layer(index));
                    break;
                }
            };
            let actual_protocol = decoded.layer.protocol_id();
            if !codec.accepts_decoded_protocol(actual_protocol) {
                return Err(DecodeError::CodecLayerMismatch {
                    protocol: current_protocol,
                    actual: actual_protocol.clone(),
                });
            }
            decoded.layer.validate_required_fields().map_err(|source| {
                DecodeError::InvalidLayer {
                    protocol: actual_protocol.clone(),
                    source,
                }
            })?;
            let binding_parent = actual_protocol;
            if decoded.consumed > current.len()
                || decoded.payload_offset > current.len()
                || decoded.consumed != decoded.payload_offset
                || (!decoded.stop && decoded.payload_offset == 0)
            {
                return Err(DecodeError::InvalidCodecCursor {
                    protocol: current_protocol,
                });
            }
            let payload_end = decoded
                .payload_offset
                .checked_add(decoded.payload_len)
                .filter(|end| *end <= current.len())
                .ok_or_else(|| DecodeError::InvalidCodecCursor {
                    protocol: current_protocol.clone(),
                })?;
            if payload_end < current.len() {
                let trailing_offset =
                    absolute_offset.checked_add(payload_end).ok_or_else(|| {
                        DecodeError::InvalidCodecCursor {
                            protocol: current_protocol.clone(),
                        }
                    })?;
                trailing.push((
                    trailing_offset,
                    slice_original(&original, trailing_offset, current.len() - payload_end),
                    index,
                ));
                let message = format!(
                    "preserved {} byte(s) outside the declared length of {current_protocol}",
                    current.len() - payload_end
                );
                let diagnostic = if allow_current_link_padding {
                    Diagnostic::info("decode.trailing_padding", message)
                } else {
                    Diagnostic::warning("decode.trailing_malformed", message)
                };
                diagnostics.push(diagnostic.at_layer(index));
            }

            let mut fields = decoded.fields;
            if fields.iter().any(|field| {
                field.range.start > field.range.end || field.range.end > decoded.consumed
            }) {
                return Err(DecodeError::InvalidCodecLayout {
                    protocol: current_protocol,
                });
            }
            for field in &mut fields {
                if !field.range.checked_shift(absolute_offset) {
                    return Err(DecodeError::InvalidCodecLayout {
                        protocol: current_protocol,
                    });
                }
            }
            let layer_end = absolute_offset
                .checked_add(decoded.consumed)
                .ok_or_else(|| DecodeError::InvalidCodecCursor {
                    protocol: current_protocol.clone(),
                })?;
            let next_selection = decoded.next.iter().find_map(|value| {
                self.registry
                    .child_for(binding_parent.as_str(), *value)
                    .map(|protocol| (*value, protocol.clone()))
            });
            let next_discriminator = next_selection.as_ref().map(|(value, _)| *value);
            let next_protocol = next_selection.map(|(_, protocol)| protocol);
            let missing_required_message = (decoded.payload_len == 0)
                .then(|| {
                    next_protocol.as_ref().filter(|protocol| {
                        !matches!(
                            BuiltinProtocol::from_id(protocol),
                            Some(
                                BuiltinProtocol::Raw
                                    | BuiltinProtocol::Malformed
                                    | BuiltinProtocol::Padding
                            )
                        )
                    })
                })
                .flatten()
                .map(|required| {
                    format!(
                        "{binding_parent} discriminator requires {required}, but no bytes remain"
                    )
                });
            let unknown_binding_message =
                (decoded.payload_len > 0 && !decoded.stop && next_protocol.is_none())
                    .then(|| format!("unknown child discriminator after {binding_parent}"));
            layouts.push(LayerLayout {
                index,
                protocol: decoded.layer.protocol_id().clone(),
                range: ByteRange::new(absolute_offset, layer_end),
                fields,
            });
            traversal.accept_network(decoded.network);
            traversal.enter_child(binding_parent, next_protocol.as_ref());
            packet.push_boxed(decoded.layer);
            diagnostics.extend(decoded.diagnostics.into_iter().map(|mut diagnostic| {
                if diagnostic.layer.is_none() {
                    diagnostic.layer = Some(index);
                }
                diagnostic
            }));
            if decoded.payload_len == 0 {
                if let Some(required) = next_protocol.filter(|protocol| {
                    !matches!(
                        BuiltinProtocol::from_id(protocol),
                        Some(
                            BuiltinProtocol::Raw
                                | BuiltinProtocol::Malformed
                                | BuiltinProtocol::Padding
                        )
                    )
                }) {
                    if packet.len() >= options.max_layers {
                        return Err(DecodeError::LayerLimit {
                            limit: options.max_layers,
                        });
                    }
                    append_missing_required_layer(&mut packet, &mut layouts, required, layer_end);
                    diagnostics.push(
                        Diagnostic::error(
                            "decode.missing_required_child",
                            missing_required_message
                                .expect("typed missing child has a prepared diagnostic"),
                        )
                        .at_layer(index),
                    );
                }
                break;
            }
            if decoded.stop {
                if packet.len() >= options.max_layers {
                    return Err(DecodeError::LayerLimit {
                        limit: options.max_layers,
                    });
                }
                append_raw(
                    &mut packet,
                    &mut layouts,
                    slice_original(&original, layer_end, decoded.payload_len),
                    layer_end,
                );
                diagnostics.push(
                    Diagnostic::warning(
                        "decode.terminal_payload",
                        format!(
                            "codec for {current_protocol} stopped with {} unconsumed payload byte(s); preserved as Raw",
                            decoded.payload_len
                        ),
                    )
                    .at_layer(index),
                );
                break;
            }
            let payload = &current[decoded.payload_offset..payload_end];
            absolute_offset = layer_end;
            let Some(next_protocol) = next_protocol else {
                if packet.len() >= options.max_layers {
                    return Err(DecodeError::LayerLimit {
                        limit: options.max_layers,
                    });
                }
                append_raw(
                    &mut packet,
                    &mut layouts,
                    slice_original(&original, absolute_offset, decoded.payload_len),
                    absolute_offset,
                );
                diagnostics.push(Diagnostic::warning(
                    "decode.unknown_binding",
                    unknown_binding_message
                        .expect("unknown child binding has a prepared diagnostic"),
                ));
                break;
            };
            current_protocol = next_protocol;
            current_discriminator = next_discriminator;
            current = payload;
        }

        trailing.sort_by_key(|(offset, _, _)| *offset);
        for (offset, bytes, outside_layer) in trailing {
            if packet.len() >= options.max_layers {
                return Err(DecodeError::LayerLimit {
                    limit: options.max_layers,
                });
            }
            // Keep explicit coverage ownership so a strict byte-for-byte
            // rebuild preserves the declared protocol length. The builder
            // marks padding outside a network root as requiring live
            // malformed-traffic opt-in.
            append_padding(&mut packet, &mut layouts, bytes, offset, outside_layer);
        }

        Ok(DecodedPacket {
            packet,
            original,
            frame,
            layout: PacketLayout { layers: layouts },
            diagnostics,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, OnceLock};

    use super::*;
    use crate::{
        codec::{
            CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext,
            LayerEncodeContext,
        },
        field::FieldValue,
        layer::{FieldError, Layer, LayerSchema, Padding, Raw},
        layout::FieldLayout,
        registry::RegistryBuilder,
    };
    use packetcraftr_core::frame::LinkType;

    #[derive(Clone, Debug)]
    struct Probe;

    fn probe_schema() -> &'static LayerSchema {
        static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
        SCHEMA.get_or_init(|| LayerSchema {
            protocol: ProtocolId::new("probe"),
            name: "Probe",
            fields: &[],
        })
    }

    impl Layer for Probe {
        fn schema(&self) -> &'static LayerSchema {
            probe_schema()
        }

        fn clone_box(&self) -> Box<dyn Layer> {
            Box::new(self.clone())
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
            self
        }

        fn field(&self, _name: &str) -> Option<FieldValue> {
            None
        }

        fn set_field(&mut self, name: &str, _value: FieldValue) -> Result<(), FieldError> {
            Err(FieldError::UnknownField {
                protocol: ProtocolId::new("probe"),
                field: name.to_owned(),
            })
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum ProbeMode {
        StopWithPayload,
        CursorGap,
        InvalidLayout,
        Trailing,
        Reject,
    }

    #[derive(Clone, Copy, Debug)]
    struct ProbeCodec(ProbeMode);

    impl LayerCodec for ProbeCodec {
        fn protocol_id(&self) -> ProtocolId {
            ProtocolId::new("probe")
        }

        fn encode(
            &self,
            _layer: &dyn Layer,
            _payload: &[u8],
            _context: &LayerEncodeContext<'_>,
        ) -> Result<EncodedLayer, CodecError> {
            Ok(EncodedLayer::header(vec![0], Box::new(Probe)))
        }

        fn decode(
            &self,
            input: &[u8],
            _context: &LayerDecodeContext<'_>,
        ) -> Result<DecodedLayerValue, CodecError> {
            let mut value = DecodedLayerValue {
                layer: Box::new(Probe),
                consumed: 1,
                payload_offset: 1,
                payload_len: input.len().saturating_sub(1),
                next: Vec::new(),
                fields: Vec::new(),
                diagnostics: Vec::new(),
                stop: true,
                network: None,
            };
            match self.0 {
                ProbeMode::StopWithPayload => {}
                ProbeMode::CursorGap => {
                    value.payload_offset = 2;
                    value.payload_len = input.len().saturating_sub(2);
                }
                ProbeMode::InvalidLayout => {
                    value.payload_len = 0;
                    value.fields.push(FieldLayout {
                        name: "outside".to_owned(),
                        range: ByteRange::new(0, 2),
                    });
                }
                ProbeMode::Trailing => value.payload_len = 0,
                ProbeMode::Reject => {
                    return Err(CodecError::Invalid {
                        protocol: ProtocolId::new("probe"),
                        message: "rejected test input".to_owned(),
                    });
                }
            }
            Ok(value)
        }

        fn make_layer(
            &self,
            _fields: &BTreeMap<String, FieldValue>,
        ) -> Result<Box<dyn Layer>, CodecError> {
            Ok(Box::new(Probe))
        }
    }

    fn dissector(mode: ProbeMode) -> Dissector {
        let mut builder = RegistryBuilder::new();
        builder.register_codec(ProbeCodec(mode)).unwrap();
        Dissector::new(Arc::new(builder.build().unwrap()))
    }

    #[test]
    fn terminal_codec_payload_is_preserved_as_raw_and_counted() {
        let decoded = dissector(ProbeMode::StopWithPayload)
            .decode_with_root(
                Bytes::from_static(&[1, 2, 3]),
                ProtocolId::new("probe"),
                DecodeOptions {
                    max_layers: 2,
                    ..DecodeOptions::default()
                },
            )
            .unwrap();
        assert_eq!(
            decoded.packet.get::<Raw>().unwrap().bytes,
            Bytes::from_static(&[2, 3])
        );
        assert_eq!(
            decoded.packet.get::<Raw>().unwrap().bytes.as_ptr(),
            decoded.original[1..].as_ptr()
        );

        assert!(matches!(
            dissector(ProbeMode::StopWithPayload).decode_with_root(
                Bytes::from_static(&[1, 2]),
                ProtocolId::new("probe"),
                DecodeOptions {
                    max_layers: 1,
                    ..DecodeOptions::default()
                },
            ),
            Err(DecodeError::LayerLimit { limit: 1 })
        ));
    }

    #[test]
    fn preserved_decoder_bytes_share_original_backing() {
        let malformed = dissector(ProbeMode::Reject)
            .decode_with_root(
                Bytes::from(vec![1, 2, 3]),
                ProtocolId::new("probe"),
                DecodeOptions::default(),
            )
            .unwrap();
        assert_eq!(
            malformed
                .packet
                .get::<MalformedLayer>()
                .unwrap()
                .bytes
                .as_ptr(),
            malformed.original.as_ptr()
        );

        let trailing = dissector(ProbeMode::Trailing)
            .decode_with_root(
                Bytes::from(vec![1, 2, 3]),
                ProtocolId::new("probe"),
                DecodeOptions::default(),
            )
            .unwrap();
        assert_eq!(
            trailing.packet.get::<Padding>().unwrap().bytes.as_ptr(),
            trailing.original[1..].as_ptr()
        );
    }

    #[test]
    fn codec_cursor_gaps_and_out_of_layer_fields_are_rejected() {
        assert!(matches!(
            dissector(ProbeMode::CursorGap).decode_with_root(
                Bytes::from_static(&[1, 2, 3]),
                ProtocolId::new("probe"),
                DecodeOptions::default(),
            ),
            Err(DecodeError::InvalidCodecCursor { .. })
        ));
        assert!(matches!(
            dissector(ProbeMode::InvalidLayout).decode_with_root(
                Bytes::from_static(&[1]),
                ProtocolId::new("probe"),
                DecodeOptions::default(),
            ),
            Err(DecodeError::InvalidCodecLayout { .. })
        ));
    }

    #[test]
    fn zero_layer_limit_applies_to_unknown_link_types() {
        let frame = Frame::new(std::time::SystemTime::UNIX_EPOCH, LinkType(9999), vec![1]).unwrap();
        assert!(matches!(
            dissector(ProbeMode::StopWithPayload).decode(
                frame,
                DecodeOptions {
                    max_layers: 0,
                    ..DecodeOptions::default()
                },
            ),
            Err(DecodeError::LayerLimit { limit: 0 })
        ));
    }
}
