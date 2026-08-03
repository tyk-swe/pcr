// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use packetcraftr_core::frame::LinkType;

use super::Dissector;
use super::error::DecodeError;
use super::options::DecodeOptions;
use crate::{
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext,
        LayerEncodeContext,
    },
    field::FieldValue,
    layer::{FieldError, Layer, LayerSchema, MalformedLayer, Padding, ProtocolId, Raw},
    layout::{ByteRange, FieldLayout},
    registry::RegistryBuilder,
};

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
    let frame = packetcraftr_core::frame::Frame::new(
        std::time::SystemTime::UNIX_EPOCH,
        LinkType(9999),
        vec![1],
    )
    .unwrap();
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
