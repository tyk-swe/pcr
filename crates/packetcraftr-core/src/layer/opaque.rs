// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Opaque byte layers: `Raw` payloads, trailing `Padding`, and `Malformed`
//! bytes. They are part of the layer model, so every codec and engine can use
//! them without depending on a protocol.

use std::collections::BTreeMap;

use bytes::Bytes;

use super::reflection::reflective_layer;
use super::{Id, Layer};
use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::Diagnostic,
    field::{self, FieldValue},
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

    /// The field layout of a `Raw` layer holding `length` bytes: one `bytes`
    /// field spanning all of them. A codec that decodes or encodes opaque
    /// bytes as `Raw` attaches this to its [`DecodedLayer`] or
    /// [`EncodedLayer`].
    pub fn layout(length: usize) -> Vec<crate::layout::FieldLayout> {
        raw_layout(length)
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
    /// First layer index whose declared coverage excludes these bytes.
    /// `None` denotes link padding excluded from every dependent payload.
    pub outside_layer: Option<usize>,
}

impl Padding {
    pub(crate) const ID: Id = Id::new("padding");

    /// Whether the layer at `layer_index` excludes these bytes from its
    /// payload: link padding is excluded everywhere, and coverage-bounded
    /// padding from the layer that declared the boundary onward.
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
            get |layer| layer.outside_layer.map(FieldValue::from),
            set |layer, value, name| match value {
                FieldValue::Unsigned(value) => {
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
    layout pub(crate) fn padding_layout(length: usize);
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
            get |layer| layer.intended_protocol.clone().map(FieldValue::Text),
            set |layer, value, name| match value {
                FieldValue::Text(value) => { layer.intended_protocol = Some(value); Ok(()) }
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
    layout pub(crate) fn malformed_layout(length: usize);
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
        return Err(crate::codec::Error::Invalid {
            protocol,
            message: "hex value must contain an even number of digits".to_owned(),
        });
    }
    let digits = compact.as_bytes();
    let mut bytes = Vec::with_capacity(digits.len() / 2);
    let mut offset = 0_usize;
    while let Some(pair) = digits.get(offset..).and_then(<[u8]>::first_chunk::<2>) {
        let high = hex_nibble(pair[0]).ok_or_else(|| crate::codec::Error::Invalid {
            protocol,
            message: format!("invalid hex at byte {offset}"),
        })?;
        let low = hex_nibble(pair[1]).ok_or_else(|| crate::codec::Error::Invalid {
            protocol,
            message: format!("invalid hex at byte {}", offset.saturating_add(1)),
        })?;
        bytes.push((high << 4) | low);
        offset = offset.saturating_add(2);
    }
    Ok(Bytes::from(bytes))
}

// each arm bounds value to its own ASCII range, so the subtraction and the plus ten stay inside u8
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

impl LayerCodec for RawCodec {
    fn protocol_id(&self) -> &'static Id {
        &raw_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Raw>(Raw::ID, layer)?;
        ensure_encode_budget(*layer.protocol_id(), layer.bytes.len(), context)?;
        Ok(
            EncodedLayer::header(layer.bytes.to_vec(), Box::new(layer.clone()))
                .with_fields(raw_layout(layer.bytes.len())),
        )
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let mut decoded = DecodedLayer::terminal(Box::new(Raw::new(input.clone())), input.len());
        decoded.fields = raw_layout(input.len());
        Ok(decoded)
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        with_fields(Raw::default(), raw_fields(fields, Raw::ID)?)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PaddingCodec;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct MalformedCodec;

impl LayerCodec for MalformedCodec {
    fn protocol_id(&self) -> &'static Id {
        &malformed_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Malformed>(Malformed::ID, layer)?;
        ensure_encode_budget(*layer.protocol_id(), layer.bytes.len(), context)?;
        Ok(
            EncodedLayer::header(layer.bytes.to_vec(), Box::new(layer.clone()))
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
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let mut decoded = DecodedLayer::terminal(
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
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        with_fields(
            Malformed::new(None, Bytes::new(), "explicit malformed bytes"),
            fields.clone(),
        )
    }
}

impl LayerCodec for PaddingCodec {
    fn protocol_id(&self) -> &'static Id {
        &padding_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Padding>(Padding::ID, layer)?;
        ensure_encode_budget(*layer.protocol_id(), layer.bytes.len(), context)?;
        Ok(
            EncodedLayer::header(layer.bytes.to_vec(), Box::new(layer.clone()))
                .with_fields(padding_layout(layer.bytes.len())),
        )
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let mut decoded =
            DecodedLayer::terminal(Box::new(Padding::new(input.clone())), input.len());
        decoded.fields = padding_layout(input.len());
        Ok(decoded)
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        with_fields(Padding::default(), raw_fields(fields, Padding::ID)?)
    }
}

fn raw_fields(
    fields: &BTreeMap<String, FieldValue>,
    name: Id,
) -> Result<BTreeMap<String, FieldValue>, crate::codec::Error> {
    let mut normalized = fields.clone();
    let derived = match normalized.remove("hex") {
        Some(value) => {
            let FieldValue::Text(value) = value else {
                return Err(invalid(name, "hex must be a quoted hexadecimal string"));
            };
            Some(FieldValue::Bytes(parse_hex(&value)?))
        }
        None => match normalized.remove("text") {
            Some(value) => {
                let FieldValue::Text(value) = value else {
                    return Err(invalid(name, "text must be a quoted string"));
                };
                Some(FieldValue::Bytes(Bytes::from(value.into_bytes())))
            }
            None => None,
        },
    };
    if let Some(value) = derived
        && normalized.insert("bytes".to_string(), value).is_some()
    {
        return Err(invalid(name, "bytes cannot be combined with hex or text"));
    }
    Ok(normalized)
}

fn with_fields<L: Layer>(
    mut layer: L,
    fields: BTreeMap<String, FieldValue>,
) -> Result<Box<dyn Layer>, crate::codec::Error> {
    for (name, value) in fields {
        layer.set_field(&name, value)?;
    }
    Ok(Box::new(layer))
}

fn typed_layer<L: Layer>(expected: Id, layer: &dyn Layer) -> Result<&L, crate::codec::Error> {
    layer
        .downcast_ref::<L>()
        .ok_or_else(|| crate::codec::Error::WrongLayer {
            expected,
            actual: *layer.protocol_id(),
        })
}

fn ensure_encode_budget(
    protocol: Id,
    contribution: usize,
    context: &LayerEncodeContext<'_>,
) -> Result<(), crate::codec::Error> {
    if contribution > context.remaining_packet_bytes {
        return Err(invalid(
            protocol,
            format!(
                "layer contributes {contribution} bytes but only {} remain in the packet-size budget",
                context.remaining_packet_bytes
            ),
        ));
    }
    Ok(())
}

fn invalid(protocol: Id, message: impl Into<String>) -> crate::codec::Error {
    crate::codec::Error::Invalid {
        protocol,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::ByteRange;

    #[test]
    fn opaque_layouts_cover_the_whole_input() {
        assert_eq!(padding_layout(2)[0].range, ByteRange::new(0, 2));
        assert_eq!(malformed_layout(4)[0].range, ByteRange::new(0, 4));
    }
}
