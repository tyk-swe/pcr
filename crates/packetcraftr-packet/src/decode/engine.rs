// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use bytes::Bytes;
use thiserror::Error;

use packetcraftr_model::{Frame, FrameError, LinkType};

use super::super::Packet;
use super::super::build::{DEFAULT_MAX_LAYERS, DEFAULT_MAX_PACKET_SIZE};
use super::super::catalog::{ProtocolCatalogSnapshot, ProtocolOperationError};
use super::super::codec::NativeLayerDecodeContext;
use super::super::diagnostic::Diagnostic;
use super::super::invariant::{
    decode_payload_end, layer_count_within_limit, packet_size_within_limit,
};
use super::super::layer::{FieldError, FieldId, MalformedLayer, Padding, ProtocolId, Raw};
use super::super::layout::{ByteRange, FieldLayout, LayerLayout, PacketLayout};
use super::super::semantics::BuiltinProtocol;

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
    #[error("codec for {protocol} returned a network envelope with mixed address families")]
    InvalidNetworkEnvelope { protocol: ProtocolId },
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
    InvalidCaptureRecord(#[from] FrameError),
    #[error("protocol provider failed for {protocol}: {source}")]
    Provider {
        protocol: ProtocolId,
        #[source]
        source: ProtocolOperationError,
    },
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
    catalog: Arc<ProtocolCatalogSnapshot>,
}

impl Dissector {
    pub fn new(catalog: Arc<ProtocolCatalogSnapshot>) -> Self {
        Self { catalog }
    }

    pub fn catalog(&self) -> &Arc<ProtocolCatalogSnapshot> {
        &self.catalog
    }

    pub fn decode(
        &self,
        frame: Frame,
        options: DecodeOptions,
    ) -> Result<DecodedPacket, DecodeError> {
        if !layer_count_within_limit(1, options.max_layers) {
            return Err(DecodeError::LayerLimit { limit: 0 });
        }
        frame.validate()?;
        if !packet_size_within_limit(frame.bytes().len(), options.max_packet_size) {
            return Err(DecodeError::PacketSizeLimit {
                actual: frame.bytes().len(),
                limit: options.max_packet_size,
            });
        }
        let original = frame.bytes().clone();
        let Some(root) = self.catalog.root_for_link_type(frame.link_type.0).cloned() else {
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
        if !packet_size_within_limit(bytes.len(), options.max_packet_size) {
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
        if !layer_count_within_limit(1, options.max_layers) {
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
        let allow_trailing_padding = matches!(
            BuiltinProtocol::from_id(&root),
            Some(
                BuiltinProtocol::Ethernet
                    | BuiltinProtocol::BsdNull
                    | BuiltinProtocol::BsdLoop
                    | BuiltinProtocol::LinuxSll
                    | BuiltinProtocol::LinuxSll2
            )
        );
        let mut packet = Packet::new();
        let mut layouts = Vec::new();
        let mut diagnostics = Vec::new();
        let mut current_protocol = root;
        let mut current = original.as_ref();
        let mut absolute_offset = 0usize;
        let mut network = None;
        let mut trailing = Vec::<(usize, Bytes, usize)>::new();
        let mut operation = self.catalog.operation();

        loop {
            if !layer_count_within_limit(packet.len() + 1, options.max_layers) {
                return Err(DecodeError::LayerLimit {
                    limit: options.max_layers,
                });
            }
            let Some(registration) = self.catalog.descriptor(&current_protocol) else {
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
            let allow_current_link_padding = allow_trailing_padding && network.is_none();
            let decoded = match operation.decode(
                &current_protocol,
                current,
                &NativeLayerDecodeContext {
                    layer_index: index,
                    absolute_offset,
                    verify_checksums: options.verify_checksums,
                    allow_trailing_padding: allow_current_link_padding,
                    network,
                },
            ) {
                Ok(decoded) => decoded,
                Err(source) => {
                    if !matches!(source, ProtocolOperationError::Codec { .. }) {
                        return Err(map_operation_error(&current_protocol, source));
                    }
                    let message = source_codec_message(source);
                    packet.push_boxed(Box::new(MalformedLayer::new(
                        Some(current_protocol.clone()),
                        slice_original(&original, absolute_offset, current.len()),
                        message.clone(),
                    )));
                    layouts.push(LayerLayout {
                        index,
                        protocol: ProtocolId::from_static(BuiltinProtocol::Malformed.as_str()),
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
            debug_assert!(registration.accepts_decoded_protocol(actual_protocol));
            let binding_parent = actual_protocol;
            let payload_end = decode_payload_end(
                current.len(),
                decoded.consumed,
                decoded.payload_offset,
                decoded.payload_len,
                decoded.stop,
            )
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
            let next_protocol = decoded
                .next
                .iter()
                .find_map(|value| self.catalog.child_for(binding_parent, *value))
                .or_else(|| {
                    (!decoded.next.is_empty())
                        .then(|| self.catalog.fallback_child_for(binding_parent))
                        .flatten()
                })
                .cloned();
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
            packet.push_boxed(decoded.layer);
            if let Some(envelope) = decoded.network {
                network = Some(envelope);
            }
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
                    if !layer_count_within_limit(packet.len() + 1, options.max_layers) {
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
                if !layer_count_within_limit(packet.len() + 1, options.max_layers) {
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
                if !layer_count_within_limit(packet.len() + 1, options.max_layers) {
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
            current = payload;
        }

        trailing.sort_by_key(|(offset, _, _)| *offset);
        for (offset, bytes, outside_layer) in trailing {
            if !layer_count_within_limit(packet.len() + 1, options.max_layers) {
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

fn source_codec_message(source: ProtocolOperationError) -> String {
    match source {
        ProtocolOperationError::Codec { source, .. } => source.to_string(),
        _ => unreachable!("caller checked the operation error variant"),
    }
}

fn map_operation_error(protocol: &ProtocolId, source: ProtocolOperationError) -> DecodeError {
    match source {
        ProtocolOperationError::AcceptedDecode { actual, .. }
        | ProtocolOperationError::ProtocolOwnership { actual, .. } => {
            DecodeError::CodecLayerMismatch {
                protocol: protocol.clone(),
                actual,
            }
        }
        ProtocolOperationError::UnknownProtocol { .. }
        | ProtocolOperationError::UnknownProtocolName { .. } => DecodeError::MissingRootCodec {
            protocol: protocol.clone(),
        },
        ProtocolOperationError::InvalidLayer { source, .. } => DecodeError::InvalidLayer {
            protocol: protocol.clone(),
            source,
        },
        ProtocolOperationError::InvalidCursor { .. } => DecodeError::InvalidCodecCursor {
            protocol: protocol.clone(),
        },
        ProtocolOperationError::InvalidLayout { .. } => DecodeError::InvalidCodecLayout {
            protocol: protocol.clone(),
        },
        ProtocolOperationError::InvalidNetworkEnvelope { .. } => {
            DecodeError::InvalidNetworkEnvelope {
                protocol: protocol.clone(),
            }
        }
        source => DecodeError::Provider {
            protocol: protocol.clone(),
            source,
        },
    }
}

fn append_padding(
    packet: &mut Packet,
    layouts: &mut Vec<LayerLayout>,
    bytes: Bytes,
    absolute_offset: usize,
    outside_layer: usize,
) {
    let index = packet.len();
    let layout = bytes_layer_layout(
        index,
        BuiltinProtocol::Padding,
        absolute_offset,
        bytes.len(),
    );
    packet.push(Padding::after_layer(bytes, outside_layer));
    layouts.push(layout);
}

fn append_raw(
    packet: &mut Packet,
    layouts: &mut Vec<LayerLayout>,
    bytes: Bytes,
    absolute_offset: usize,
) {
    let index = packet.len();
    let layout = bytes_layer_layout(index, BuiltinProtocol::Raw, absolute_offset, bytes.len());
    packet.push(Raw::new(bytes));
    layouts.push(layout);
}

fn bytes_layer_layout(
    index: usize,
    protocol: BuiltinProtocol,
    absolute_offset: usize,
    byte_length: usize,
) -> LayerLayout {
    let end = absolute_offset.saturating_add(byte_length);
    LayerLayout {
        index,
        protocol: ProtocolId::from_static(protocol.as_str()),
        range: ByteRange::new(absolute_offset, end),
        fields: vec![FieldLayout {
            id: FieldId::from_static("bytes"),
            range: ByteRange::new(absolute_offset, end),
        }],
    }
}

fn slice_original(original: &Bytes, offset: usize, length: usize) -> Bytes {
    let end = offset
        .checked_add(length)
        .expect("decoder cursor ranges were validated before preserving bytes");
    original.slice(offset..end)
}

fn append_missing_required_layer(
    packet: &mut Packet,
    layouts: &mut Vec<LayerLayout>,
    intended: ProtocolId,
    absolute_offset: usize,
) {
    let index = packet.len();
    packet.push(MalformedLayer::new(
        Some(intended),
        Bytes::new(),
        "required child header is absent",
    ));
    layouts.push(LayerLayout {
        index,
        protocol: ProtocolId::from_static(BuiltinProtocol::Malformed.as_str()),
        range: ByteRange::new(absolute_offset, absolute_offset),
        fields: Vec::new(),
    });
}

fn raw_decoded_frame(frame: Frame, diagnostic: Diagnostic) -> DecodedPacket {
    let original = frame.bytes().clone();
    let mut packet = Packet::new();
    packet.push(Raw::new(original.clone()));
    DecodedPacket {
        packet,
        original: original.clone(),
        frame,
        layout: PacketLayout {
            layers: vec![LayerLayout {
                index: 0,
                protocol: ProtocolId::from_static(BuiltinProtocol::Raw.as_str()),
                range: ByteRange::new(0, original.len()),
                fields: vec![FieldLayout {
                    id: FieldId::from_static("bytes"),
                    range: ByteRange::new(0, original.len()),
                }],
            }],
        },
        diagnostics: vec![diagnostic],
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, OnceLock};

    use super::*;
    use crate::{
        codec::{
            CodecError, DecodedLayerValue, EncodedLayer, NativeLayerCodec,
            NativeLayerDecodeContext, NativeLayerEncodeContext,
        },
        field::FieldValue,
        layer::{FieldError, FieldId, Layer, LayerSchema, ValidatedFieldSet},
        test_support::native_catalog,
    };
    use packetcraftr_model::LinkType;

    #[derive(Clone, Debug)]
    struct Probe;

    fn probe_schema() -> &'static LayerSchema {
        static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
        SCHEMA.get_or_init(|| {
            LayerSchema::empty(
                ProtocolId::from_static("probe"),
                "Probe",
                std::iter::empty::<&str>(),
            )
            .unwrap()
        })
    }

    impl Layer for Probe {
        fn schema(&self) -> &LayerSchema {
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

        fn field_by_id(&self, _id: &FieldId) -> Option<FieldValue> {
            None
        }

        fn set_field_by_id(&mut self, id: &FieldId, _value: FieldValue) -> Result<(), FieldError> {
            Err(FieldError::UnknownFieldId {
                protocol: ProtocolId::from_static("probe"),
                field: id.clone(),
            })
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum ProbeMode {
        StopWithPayload,
        CursorGap,
        InvalidLayout,
        InvalidNetwork,
        Trailing,
        Reject,
    }

    #[derive(Clone, Copy, Debug)]
    struct ProbeCodec(ProbeMode);

    impl NativeLayerCodec for ProbeCodec {
        fn encode(
            &self,
            _layer: &dyn Layer,
            _payload: &[u8],
            _context: &NativeLayerEncodeContext<'_>,
        ) -> Result<EncodedLayer, CodecError> {
            Ok(EncodedLayer::header(vec![0], Box::new(Probe)))
        }

        fn decode(
            &self,
            input: &[u8],
            _context: &NativeLayerDecodeContext,
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
                        id: FieldId::from_static("outside"),
                        range: ByteRange::new(0, 2),
                    });
                }
                ProbeMode::InvalidNetwork => {
                    value.payload_len = 0;
                    value.network = Some(crate::codec::NetworkEnvelope {
                        source: std::net::Ipv4Addr::LOCALHOST.into(),
                        destination: std::net::Ipv6Addr::LOCALHOST.into(),
                    });
                }
                ProbeMode::Trailing => value.payload_len = 0,
                ProbeMode::Reject => {
                    return Err(CodecError::Invalid {
                        protocol: ProtocolId::from_static("probe"),
                        message: "rejected test input".to_owned(),
                    });
                }
            }
            Ok(value)
        }

        fn make_layer(&self, _fields: &ValidatedFieldSet) -> Result<Box<dyn Layer>, CodecError> {
            Ok(Box::new(Probe))
        }
    }

    fn dissector(mode: ProbeMode) -> Dissector {
        Dissector::new(native_catalog(
            Arc::new(probe_schema().clone()),
            ProbeCodec(mode),
        ))
    }

    #[test]
    fn terminal_codec_payload_is_preserved_as_raw_and_counted() {
        let decoded = dissector(ProbeMode::StopWithPayload)
            .decode_with_root(
                Bytes::from_static(&[1, 2, 3]),
                ProtocolId::from_static("probe"),
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
                ProtocolId::from_static("probe"),
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
                ProtocolId::from_static("probe"),
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
                ProtocolId::from_static("probe"),
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
                ProtocolId::from_static("probe"),
                DecodeOptions::default(),
            ),
            Err(DecodeError::InvalidCodecCursor { .. })
        ));
        assert!(matches!(
            dissector(ProbeMode::InvalidLayout).decode_with_root(
                Bytes::from_static(&[1]),
                ProtocolId::from_static("probe"),
                DecodeOptions::default(),
            ),
            Err(DecodeError::InvalidCodecLayout { .. })
        ));
        assert!(matches!(
            dissector(ProbeMode::InvalidNetwork).decode_with_root(
                Bytes::from_static(&[1]),
                ProtocolId::from_static("probe"),
                DecodeOptions::default(),
            ),
            Err(DecodeError::InvalidNetworkEnvelope { .. })
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
