// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use super::reflection::reflective_layer;
use super::{Id, Layer};
use crate::{
    codec::{Codec, DecodeContext, Decoded, EncodeContext, Encoded},
    diagnostic::Diagnostic,
    field,
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Raw {
    pub bytes: Bytes,
}

impl Raw {
    pub(crate) const ID: Id = Id::new("raw");

    pub fn new(bytes: impl Into<Bytes>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    pub fn layout(length: usize) -> Vec<crate::layout::FieldLayout> {
        raw_layout(length)
    }

    pub(crate) fn decoded(input: Bytes) -> Decoded {
        let length = input.len();
        let mut decoded = Decoded::terminal(Box::new(Self::new(input)), length);
        decoded.fields = raw_layout(length);
        decoded
    }
}

reflective_layer! {
    fn raw_schema() => { protocol: Raw::ID, name: "Raw" }
    impl Raw {
        "bytes" => {
            kind: Bytes, derived: false, required: false,
            description: "Verbatim bytes",
            reflect: bytes,
            layout: (0, length)
        }
    }
    layout fn raw_layout(length: usize);
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Padding {
    pub bytes: Bytes,
    /// `None` denotes link padding excluded from every dependent payload.
    pub outside_layer: Option<usize>,
}

impl Padding {
    pub(crate) const ID: Id = Id::new("padding");

    pub fn excluded_from(&self, layer_index: usize) -> bool {
        self.outside_layer
            .is_none_or(|outside_layer| layer_index >= outside_layer)
    }

    pub fn new(bytes: impl Into<Bytes>) -> Self {
        Self {
            bytes: bytes.into(),
            outside_layer: None,
        }
    }

    pub fn after_layer(bytes: impl Into<Bytes>, outside_layer: usize) -> Self {
        Self {
            bytes: bytes.into(),
            outside_layer: Some(outside_layer),
        }
    }
}

reflective_layer! {
    fn padding_schema() => { protocol: Padding::ID, name: "Padding" }
    impl Padding {
        "bytes" => {
            kind: Bytes, derived: false, required: false,
            description: "Trailing padding bytes",
            reflect: bytes,
            layout: (0, length)
        },
        "outside_layer" => {
            kind: Unsigned, derived: false, required: false,
            description: "First layer index whose declared length excludes the padding",
            get |layer| layer.outside_layer.map(field::Value::from),
            set |layer, value, name| match value {
                field::Value::Unsigned(value) => {
                    layer.outside_layer = Some(usize::try_from(value).map_err(|_| field::Error::OutOfRange {
                        protocol: Padding::ID, field: name.to_owned(),
                    })?);
                    Ok(())
                }
                _ => Err(field::Error::WrongType {
                    protocol: Padding::ID, field: name.to_owned(), expected: "unsigned",
                }),
            }
        }
    }
    layout fn padding_layout(length: usize);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Malformed {
    pub intended_protocol: Option<String>,
    pub bytes: Bytes,
    pub reason: String,
}

impl Malformed {
    pub(crate) const ID: Id = Id::new("malformed");

    pub fn new(
        intended_protocol: Option<String>,
        bytes: impl Into<Bytes>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            intended_protocol,
            bytes: bytes.into(),
            reason: reason.into(),
        }
    }
}

reflective_layer! {
    fn malformed_schema() => { protocol: Malformed::ID, name: "Malformed" }
    impl Malformed {
        "protocol" => {
            kind: Text, derived: false, required: false,
            description: "Intended protocol identifier",
            get |layer| layer.intended_protocol.clone().map(field::Value::Text),
            set |layer, value, name| match value {
                field::Value::Text(value) => { layer.intended_protocol = Some(value); Ok(()) }
                _ => Err(field::Error::WrongType { protocol: Malformed::ID, field: name.to_owned(), expected: "text" }),
            }
        },
        "bytes" => {
            kind: Bytes, derived: false, required: false,
            description: "Preserved malformed bytes",
            reflect: bytes,
            layout: (0, length)
        },
        "reason" => {
            kind: Text, derived: false, required: true,
            description: "Decode or construction finding",
            reflect: reason
        }
    }
    layout fn malformed_layout(length: usize);
}

/// Parses hexadecimal raw bytes with optional `0x`, whitespace, colon, or dash separators.
pub fn parse_hex(input: &str) -> Result<Bytes, crate::codec::Error> {
    let protocol = Raw::ID;
    let compact = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input)
        .chars()
        .filter(|character| {
            !character.is_ascii_whitespace() && *character != ':' && *character != '-'
        })
        .collect::<String>();
    if compact.len() % 2 != 0 {
        return Err(crate::codec::Error::invalid(
            protocol,
            "hex value must contain an even number of digits",
        ));
    }
    let pairs = compact.as_bytes().as_chunks::<2>().0;
    let mut bytes = Vec::with_capacity(pairs.len());
    for (index, &[high, low]) in pairs.iter().enumerate() {
        let (Some(high), Some(low)) = (hex_nibble(high), hex_nibble(low)) else {
            return Err(crate::codec::Error::invalid(
                protocol,
                format!("invalid hex at byte {index}"),
            ));
        };
        bytes.push((high << 4) | low);
    }
    Ok(Bytes::from(bytes))
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RawCodec;

impl Codec for RawCodec {
    fn protocol_id(&self) -> &'static Id {
        &raw_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &EncodeContext<'_>,
    ) -> Result<Encoded, crate::codec::Error> {
        let layer = layer
            .downcast_ref::<Raw>()
            .ok_or_else(|| crate::codec::Error::wrong_layer(Raw::ID, layer))?;
        context.ensure_room(Raw::ID, layer.bytes.len())?;
        Ok(
            Encoded::header(layer.bytes.to_vec(), Box::new(layer.clone()))
                .with_fields(raw_layout(layer.bytes.len())),
        )
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &DecodeContext<'_>,
    ) -> Result<Decoded, crate::codec::Error> {
        Ok(Raw::decoded(input))
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, field::Value>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        with_fields(Raw::default(), raw_fields(fields, Raw::ID)?)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PaddingCodec;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct MalformedCodec;

impl Codec for MalformedCodec {
    fn protocol_id(&self) -> &'static Id {
        &malformed_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &EncodeContext<'_>,
    ) -> Result<Encoded, crate::codec::Error> {
        let layer = layer
            .downcast_ref::<Malformed>()
            .ok_or_else(|| crate::codec::Error::wrong_layer(Malformed::ID, layer))?;
        context.ensure_room(Malformed::ID, layer.bytes.len())?;
        Ok(
            Encoded::header(layer.bytes.to_vec(), Box::new(layer.clone()))
                .with_fields(malformed_layout(layer.bytes.len()))
                .with_diagnostics(vec![Diagnostic::warning(
                    "build.malformed_layer",
                    format!("preserving explicitly malformed bytes: {}", layer.reason),
                )]),
        )
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &DecodeContext<'_>,
    ) -> Result<Decoded, crate::codec::Error> {
        let mut decoded = Decoded::terminal(
            Box::new(Malformed::new(
                None,
                input.clone(),
                "explicit malformed root",
            )),
            input.len(),
        );
        decoded.fields = malformed_layout(input.len());
        Ok(decoded)
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, field::Value>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        with_fields(
            Malformed::new(None, Bytes::new(), "explicit malformed bytes"),
            fields.clone(),
        )
    }
}

impl Codec for PaddingCodec {
    fn protocol_id(&self) -> &'static Id {
        &padding_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &EncodeContext<'_>,
    ) -> Result<Encoded, crate::codec::Error> {
        let layer = layer
            .downcast_ref::<Padding>()
            .ok_or_else(|| crate::codec::Error::wrong_layer(Padding::ID, layer))?;
        context.ensure_room(Padding::ID, layer.bytes.len())?;
        Ok(
            Encoded::header(layer.bytes.to_vec(), Box::new(layer.clone()))
                .with_fields(padding_layout(layer.bytes.len())),
        )
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &DecodeContext<'_>,
    ) -> Result<Decoded, crate::codec::Error> {
        let mut decoded = Decoded::terminal(Box::new(Padding::new(input.clone())), input.len());
        decoded.fields = padding_layout(input.len());
        Ok(decoded)
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, field::Value>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        with_fields(Padding::default(), raw_fields(fields, Padding::ID)?)
    }
}

fn raw_fields(
    fields: &BTreeMap<String, field::Value>,
    name: Id,
) -> Result<BTreeMap<String, field::Value>, crate::codec::Error> {
    let mut normalized = fields.clone();
    let derived = match normalized.remove("hex") {
        Some(value) => {
            let field::Value::Text(value) = value else {
                return Err(crate::codec::Error::invalid(
                    name,
                    "hex must be a quoted hexadecimal string",
                ));
            };
            Some(field::Value::Bytes(parse_hex(&value)?))
        }
        None => match normalized.remove("text") {
            Some(value) => {
                let field::Value::Text(value) = value else {
                    return Err(crate::codec::Error::invalid(
                        name,
                        "text must be a quoted string",
                    ));
                };
                Some(field::Value::Bytes(Bytes::from(value.into_bytes())))
            }
            None => None,
        },
    };
    if let Some(value) = derived
        && normalized.insert("bytes".to_string(), value).is_some()
    {
        return Err(crate::codec::Error::invalid(
            name,
            "bytes cannot be combined with hex or text",
        ));
    }
    Ok(normalized)
}

fn with_fields<L: Layer>(
    mut layer: L,
    fields: BTreeMap<String, field::Value>,
) -> Result<Box<dyn Layer>, crate::codec::Error> {
    for (name, value) in fields {
        layer.set_field(&name, value)?;
    }
    Ok(Box::new(layer))
}
