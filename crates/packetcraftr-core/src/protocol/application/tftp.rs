// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::{self, FieldKind, FieldValue},
    layer::{FieldSchema, Layer, Raw, reflective_layer},
    layout::{ByteRange, FieldLayout},
    protocol::{
        application::byte_string_field,
        common::{
            ensure_encode_budget, invalid, make_layer, protocol,
            structured::{Encoder, Object, list, member, object},
            typed_layer, unsupported,
        },
    },
};

use crate::protocol::BuiltinProtocol;

const NAME: &str = BuiltinProtocol::Tftp.as_str();

/// Option pairs per RRQ, WRQ or OACK; a longer list decodes as `raw`.
pub const MAX_OPTIONS: usize = 32;

const OPCODE_LEN: usize = 2;
const RRQ: u16 = 1;
const WRQ: u16 = 2;
const DATA: u16 = 3;
const ACK: u16 = 4;
const ERROR: u16 = 5;
const OACK: u16 = 6;

const OPTION_FIELDS: &[FieldSchema] = &[
    member("name", FieldKind::Bytes, &[]),
    member("value", FieldKind::Bytes, &[]),
];

/// One option name and value of an RRQ, WRQ or OACK (RFC 2347), kept as the
/// raw bytes between the NUL terminators.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TftpOption {
    pub name: Bytes,
    pub value: Bytes,
}

/// TFTP message (RFC 1350 with RFC 2347 options). Strings stay raw bytes; only
/// the fields of the message's opcode are on the wire, and a message the typed
/// fields cannot reproduce byte for byte decodes as `raw` instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tftp {
    pub opcode: u16,
    pub filename: Bytes,
    pub mode: Bytes,
    pub options: Vec<TftpOption>,
    pub block: u16,
    pub data: Bytes,
    pub error_code: u16,
    pub error_message: Bytes,
}

impl Default for Tftp {
    fn default() -> Self {
        Self {
            opcode: RRQ,
            filename: Bytes::new(),
            mode: Bytes::new(),
            options: Vec::new(),
            block: 0,
            data: Bytes::new(),
            error_code: 0,
            error_message: Bytes::new(),
        }
    }
}

fn byte_string(value: FieldValue, name: &str) -> Result<Bytes, field::Error> {
    byte_string_field(tftp_schema(), value, name)
}

fn options_value(options: &[TftpOption]) -> FieldValue {
    FieldValue::List(
        options
            .iter()
            .map(|option| {
                object([
                    ("name", option.name.clone().into()),
                    ("value", option.value.clone().into()),
                ])
            })
            .collect(),
    )
}

fn set_options(layer: &mut Tftp, value: FieldValue, name: &str) -> Result<(), field::Error> {
    let mut options = Vec::new();
    for entry in list(value, MAX_OPTIONS, tftp_schema(), name)? {
        let mut entry = Object::new(entry, tftp_schema(), name)?;
        let option = TftpOption {
            name: byte_string(entry.required("name")?, name)?,
            value: byte_string(entry.required("value")?, name)?,
        };
        entry.finish()?;
        options.push(option);
    }
    layer.options = options;
    Ok(())
}

reflective_layer! {
    fn tftp_schema() => { protocol: protocol(NAME), name: "TFTP" }
    impl Tftp {
        "opcode" => { kind: Unsigned, derived: false, required: true, description: "Opcode: 1 RRQ, 2 WRQ, 3 DATA, 4 ACK, 5 ERROR, 6 OACK", reflect: opcode, layout: (0, 2) },
        "filename" => {
            kind: Bytes, derived: false, required: false,
            description: "RRQ/WRQ file name, raw bytes without the NUL terminator",
            get |layer| Some(FieldValue::Bytes(layer.filename.clone())),
            set |layer, value, name| { layer.filename = byte_string(value, name)?; Ok(()) }
        },
        "mode" => {
            kind: Bytes, derived: false, required: false,
            description: "RRQ/WRQ transfer mode, raw bytes without the NUL terminator",
            get |layer| Some(FieldValue::Bytes(layer.mode.clone())),
            set |layer, value, name| { layer.mode = byte_string(value, name)?; Ok(()) }
        },
        "options" => {
            kind: List, derived: false, required: false,
            description: "RFC 2347 option names and values of an RRQ, WRQ or OACK",
            children: OPTION_FIELDS,
            get |layer| Some(options_value(&layer.options)),
            set |layer, value, name| set_options(layer, value, name)
        },
        "block" => { kind: Unsigned, derived: false, required: false, description: "DATA or ACK block number", reflect: block },
        "data" => { kind: Bytes, derived: false, required: false, description: "DATA payload", reflect: data },
        "error_code" => { kind: Unsigned, derived: false, required: false, description: "ERROR code", reflect: error_code },
        "error_message" => {
            kind: Bytes, derived: false, required: false,
            description: "ERROR message, raw bytes without the NUL terminator",
            get |layer| Some(FieldValue::Bytes(layer.error_message.clone())),
            set |layer, value, name| { layer.error_message = byte_string(value, name)?; Ok(()) }
        },
    }
    layout fn tftp_static_layout();
}

fn tftp_layout(layer: &Tftp) -> Vec<FieldLayout> {
    let mut fields = tftp_static_layout();
    let field = |name: &'static str, start: usize, end: usize| FieldLayout {
        name,
        range: ByteRange::new(start, end),
    };
    let mut cursor = OPCODE_LEN;
    match layer.opcode {
        RRQ | WRQ => {
            let filename_end = cursor.saturating_add(layer.filename.len());
            fields.push(field("filename", cursor, filename_end));
            let mode_start = filename_end.saturating_add(1);
            let mode_end = mode_start.saturating_add(layer.mode.len());
            fields.push(field("mode", mode_start, mode_end));
            cursor = mode_end.saturating_add(1);
            push_options_layout(&mut fields, layer, cursor);
        }
        DATA => {
            fields.push(field("block", cursor, cursor.saturating_add(2)));
            cursor = cursor.saturating_add(2);
            fields.push(field(
                "data",
                cursor,
                cursor.saturating_add(layer.data.len()),
            ));
        }
        ACK => fields.push(field("block", cursor, cursor.saturating_add(2))),
        ERROR => {
            fields.push(field("error_code", cursor, cursor.saturating_add(2)));
            cursor = cursor.saturating_add(2);
            fields.push(field(
                "error_message",
                cursor,
                cursor.saturating_add(layer.error_message.len()),
            ));
        }
        OACK => push_options_layout(&mut fields, layer, cursor),
        _ => {}
    }
    fields
}

fn push_options_layout(fields: &mut Vec<FieldLayout>, layer: &Tftp, start: usize) {
    let end = layer.options.iter().fold(start, |cursor, option| {
        cursor
            .saturating_add(option.name.len())
            .saturating_add(option.value.len())
            .saturating_add(2)
    });
    if end != start {
        fields.push(FieldLayout {
            name: "options",
            range: ByteRange::new(start, end),
        });
    }
}

/// The bytes up to the next NUL, which is consumed.
fn next_string(input: &Bytes, cursor: &mut usize) -> Option<Bytes> {
    let rest = input.get(*cursor..)?;
    let length = rest.iter().position(|byte| *byte == 0)?;
    let string = input.slice(*cursor..cursor.checked_add(length)?);
    *cursor = cursor.checked_add(length)?.checked_add(1)?;
    Some(string)
}

fn parse_options(input: &Bytes, cursor: &mut usize) -> Option<Vec<TftpOption>> {
    let mut options = Vec::new();
    while *cursor < input.len() {
        if options.len() == MAX_OPTIONS {
            return None;
        }
        let name = next_string(input, cursor)?;
        let value = next_string(input, cursor)?;
        options.push(TftpOption { name, value });
    }
    Some(options)
}

/// `None` leaves the datagram to the `raw` fallback: unknown opcodes, missing
/// terminators, unpaired options and bytes after the message.
fn parse(input: &Bytes) -> Option<Tftp> {
    let opcode = u16::from_be_bytes(*input.first_chunk::<OPCODE_LEN>()?);
    let mut layer = Tftp {
        opcode,
        ..Tftp::default()
    };
    let mut cursor = OPCODE_LEN;
    match opcode {
        RRQ | WRQ => {
            layer.filename = next_string(input, &mut cursor)?;
            layer.mode = next_string(input, &mut cursor)?;
            layer.options = parse_options(input, &mut cursor)?;
        }
        DATA => {
            layer.block = u16::from_be_bytes(*input.get(cursor..)?.first_chunk::<2>()?);
            layer.data = input.slice(cursor.checked_add(2)?..);
            cursor = input.len();
        }
        ACK => {
            layer.block = u16::from_be_bytes(*input.get(cursor..)?.first_chunk::<2>()?);
            cursor = cursor.checked_add(2)?;
        }
        ERROR => {
            layer.error_code = u16::from_be_bytes(*input.get(cursor..)?.first_chunk::<2>()?);
            cursor = cursor.checked_add(2)?;
            layer.error_message = next_string(input, &mut cursor)?;
        }
        OACK => layer.options = parse_options(input, &mut cursor)?,
        _ => return None,
    }
    (cursor == input.len()).then_some(layer)
}

fn require_no_nul(field: &str, value: &[u8]) -> Result<(), crate::codec::Error> {
    if value.contains(&0) {
        return Err(invalid(NAME, format!("{field} contains a NUL byte")));
    }
    Ok(())
}

/// A field that only another opcode puts on the wire would be dropped
/// silently, so it is refused instead.
fn require_unused_fields_empty(layer: &Tftp) -> Result<(), crate::codec::Error> {
    let opcode = layer.opcode;
    let stray = [
        (
            "filename",
            !layer.filename.is_empty() && !matches!(opcode, RRQ | WRQ),
        ),
        (
            "mode",
            !layer.mode.is_empty() && !matches!(opcode, RRQ | WRQ),
        ),
        (
            "options",
            !layer.options.is_empty() && !matches!(opcode, RRQ | WRQ | OACK),
        ),
        ("block", layer.block != 0 && !matches!(opcode, DATA | ACK)),
        ("data", !layer.data.is_empty() && opcode != DATA),
        ("error_code", layer.error_code != 0 && opcode != ERROR),
        (
            "error_message",
            !layer.error_message.is_empty() && opcode != ERROR,
        ),
    ];
    match stray.into_iter().find(|(_, stray)| *stray) {
        Some((field, _)) => Err(invalid(
            NAME,
            format!("{field} is not part of opcode {opcode}"),
        )),
        None => Ok(()),
    }
}

fn encode_options(
    encoder: &mut Encoder,
    options: &[TftpOption],
) -> Result<(), crate::codec::Error> {
    if options.len() > MAX_OPTIONS {
        return Err(invalid(
            NAME,
            format!(
                "{} options exceed the limit of {MAX_OPTIONS}",
                options.len()
            ),
        ));
    }
    for option in options {
        require_no_nul("option name", &option.name)?;
        require_no_nul("option value", &option.value)?;
        encoder.bytes(&option.name)?;
        encoder.u8(0)?;
        encoder.bytes(&option.value)?;
        encoder.u8(0)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TftpCodec;

impl LayerCodec for TftpCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &tftp_schema().protocol
    }

    fn accepts_decoded_protocol(&self, protocol: &crate::layer::Id) -> bool {
        matches!(protocol.as_str(), "tftp" | "raw")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        if !payload.is_empty() {
            return Err(invalid(NAME, "TFTP is a complete UDP payload"));
        }
        let layer = typed_layer::<Tftp>(NAME, layer)?;
        require_unused_fields_empty(layer)?;
        let mut encoder = Encoder::new(NAME, context.remaining_packet_bytes);
        encoder.u16(layer.opcode)?;
        match layer.opcode {
            RRQ | WRQ => {
                require_no_nul("filename", &layer.filename)?;
                require_no_nul("mode", &layer.mode)?;
                encoder.bytes(&layer.filename)?;
                encoder.u8(0)?;
                encoder.bytes(&layer.mode)?;
                encoder.u8(0)?;
                encode_options(&mut encoder, &layer.options)?;
            }
            DATA => {
                encoder.u16(layer.block)?;
                encoder.bytes(&layer.data)?;
            }
            ACK => encoder.u16(layer.block)?,
            ERROR => {
                require_no_nul("error_message", &layer.error_message)?;
                encoder.u16(layer.error_code)?;
                encoder.bytes(&layer.error_message)?;
                encoder.u8(0)?;
            }
            OACK => encode_options(&mut encoder, &layer.options)?,
            opcode => {
                return Err(unsupported(
                    NAME,
                    format!(
                        "opcode {opcode} has no typed encoding; carry the bytes as a raw layer"
                    ),
                ));
            }
        }
        let message = encoder.finish();
        ensure_encode_budget(NAME, message.len(), context)?;
        Ok(EncodedLayer::header(message, Box::new(layer.clone())).with_fields(tftp_layout(layer)))
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let Some(layer) = parse(&input) else {
            return Ok(Raw::decoded(input));
        };
        Ok(DecodedLayer {
            fields: tftp_layout(&layer),
            layer: Box::new(layer),
            consumed: input.len(),
            payload_len: 0,
            next: Vec::new(),
            diagnostics: Vec::new(),
            stop: true,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Tftp::default(), fields)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_field_refuses_more_options_than_the_limit() {
        let entry = || {
            object([
                ("name", Bytes::new().into()),
                ("value", Bytes::new().into()),
            ])
        };
        let mut layer = Tftp::default();
        let refused = FieldValue::List((0..=MAX_OPTIONS).map(|_| entry()).collect());
        assert!(layer.set_field("options", refused).is_err());
        let accepted = FieldValue::List((0..MAX_OPTIONS).map(|_| entry()).collect());
        layer.set_field("options", accepted).unwrap();
        assert_eq!(layer.options.len(), MAX_OPTIONS);
    }
}
