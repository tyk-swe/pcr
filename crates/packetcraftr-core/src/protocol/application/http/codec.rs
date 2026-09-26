// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use super::reflection::{http_layout, http_schema};
use super::{
    Body, Error, Head, Header, Http, Limit, MAX_HEADER_BYTES, MAX_HEADERS, MAX_START_LINE,
    StartLine,
};
use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::FieldValue,
    layer::{Layer, Raw, raw_layout},
    protocol::{
        BuiltinProtocol,
        common::{ensure_encode_budget, invalid, rejected, typed_layer},
    },
    registry::Discriminator,
};

mod body;

pub use body::{BodyDecoder, Progress};

pub(super) const NAME: &str = BuiltinProtocol::Http.as_str();

impl TryFrom<&[u8]> for Http {
    type Error = Error;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        let bounded = &input[..input.len().min(MAX_HEADER_BYTES)];
        let (head, length) = parse_head(&Bytes::copy_from_slice(bounded))?
            .ok_or(Error::Invalid("headers are incomplete"))?;
        if length != input.len() {
            return Err(Error::Invalid(
                "header wire includes body or trailing bytes",
            ));
        }
        Ok(Self { head })
    }
}
impl Head {
    /// RFC 9112 message-body precedence. Ambiguous framing is rejected before
    /// payload consumption; transfer/content encodings are never decoded here.
    pub fn body(&self, request_method: Option<&str>) -> Result<Body, Error> {
        if let Some(status) = self.status() {
            if status == 101 || (request_method == Some("CONNECT") && (200..300).contains(&status))
            {
                return Ok(Body::Tunnel);
            }
            if request_method == Some("HEAD")
                || (100..200).contains(&status)
                || status == 204
                || status == 304
            {
                return Ok(Body::None);
            }
        }
        let lengths: Vec<_> = self.values("content-length").collect();
        let encodings: Vec<_> = self.values("transfer-encoding").collect();
        if !lengths.is_empty() && !encodings.is_empty() {
            return Err(Error::Invalid(
                "has both Transfer-Encoding and Content-Length",
            ));
        }
        if !encodings.is_empty() {
            let mut codings = Vec::new();
            for value in encodings {
                transfer_codings(value, &mut codings)?;
            }
            let chunks = codings
                .iter()
                .filter(|coding| coding.as_slice() == b"chunked")
                .count();
            if chunks > 1
                || (chunks == 1
                    && codings
                        .last()
                        .is_none_or(|coding| coding.as_slice() != b"chunked"))
            {
                return Err(Error::Invalid("has nonfinal or repeated chunked coding"));
            }
            return if chunks == 1 {
                Ok(Body::Chunked)
            } else if self.status().is_some() {
                Ok(Body::Close)
            } else {
                Err(Error::Invalid("request transfer coding is not chunked"))
            };
        }
        let mut length = None;
        for value in lengths {
            for item in value.split(|b| *b == b',') {
                let item = trim(item);
                if item.is_empty() || !item.iter().all(u8::is_ascii_digit) {
                    return Err(Error::Invalid("has an invalid Content-Length"));
                }
                let parsed = item
                    .iter()
                    .try_fold(0u64, |n, b| {
                        n.checked_mul(10)?.checked_add(u64::from(b - b'0'))
                    })
                    .ok_or(Error::Invalid("Content-Length overflows"))?;
                if length.is_some_and(|old| old != parsed) {
                    return Err(Error::Invalid("has conflicting Content-Length values"));
                }
                length = Some(parsed);
            }
        }
        Ok(length
            .map(Body::Length)
            .unwrap_or(if self.status().is_some() {
                Body::Close
            } else {
                Body::None
            }))
    }
}
/// Parses a complete header block. `None` means more bytes are required.
/// Limits apply even while the terminator is absent; binary body bytes are untouched.
/// `input` is a refcounted handle so the retained wire and header values slice
/// rather than copy.
pub fn parse_head(input: &Bytes) -> Result<Option<(Head, usize)>, Error> {
    let end = input[..input.len().min(MAX_HEADER_BYTES)]
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .map(|n| n + 4);
    let Some(end) = end else {
        if input.len() >= MAX_HEADER_BYTES {
            return Err(Error::Limit(Limit::HeaderBytes));
        }
        if input.iter().position(|b| *b == b'\n').is_none() && input.len() > MAX_START_LINE {
            return Err(Error::Limit(Limit::StartLine));
        }
        validate_line_endings(input)?;
        return Ok(None);
    };
    if end > MAX_HEADER_BYTES {
        return Err(Error::Limit(Limit::HeaderBytes));
    }
    validate_line_endings(&input[..end])?;
    let first = input[..end]
        .windows(2)
        .position(|b| b == b"\r\n")
        .ok_or(Error::Invalid("lacks a start line"))?;
    if first > MAX_START_LINE {
        return Err(Error::Limit(Limit::StartLine));
    }
    let start = parse_start(&input.slice(..first))?;
    let headers = parse_headers(&input.slice(first + 2..end - 2))?;
    Ok(Some((
        Head {
            start,
            headers,
            wire: input.slice(..end),
        },
        end,
    )))
}
pub(crate) fn parse_headers(input: &Bytes) -> Result<Vec<Header>, Error> {
    let mut headers = Vec::new();
    let mut offset = 0;
    while offset < input.len() {
        let end = input[offset..]
            .windows(2)
            .position(|b| b == b"\r\n")
            .ok_or(Error::Invalid("has an incomplete header line"))?
            + offset;
        if end == offset {
            return Err(Error::Invalid("has an unexpected empty header line"));
        }
        if headers.len() >= MAX_HEADERS {
            return Err(Error::Limit(Limit::HeaderCount));
        }
        let line = &input[offset..end];
        let colon = line
            .iter()
            .position(|b| *b == b':')
            .ok_or(Error::Invalid("header has no colon"))?;
        let name = &line[..colon];
        let value = trim(&line[colon + 1..]);
        if name.is_empty() || !name.iter().all(|b| token(*b)) {
            return Err(Error::Invalid(
                "header name is not a token (folding is unsupported)",
            ));
        }
        if !value
            .iter()
            .all(|b| *b == b'\t' || (*b >= 0x20 && *b != 0x7f))
        {
            return Err(Error::Invalid("header value contains a control byte"));
        }
        headers.push(Header {
            name: String::from_utf8(name.to_vec()).expect("ASCII token"),
            value: input.slice_ref(value),
        });
        offset = end + 2;
    }
    Ok(headers)
}
fn parse_start(input: &Bytes) -> Result<StartLine, Error> {
    if input.starts_with(b"HTTP/") {
        let mut parts = input.splitn(3, |b| *b == b' ');
        let version = version(parts.next().unwrap_or_default())?;
        let status = parts.next().unwrap_or_default();
        let reason = parts
            .next()
            .ok_or(Error::Invalid("status line lacks a reason separator"))?;
        if status.len() != 3 || !status.iter().all(u8::is_ascii_digit) {
            return Err(Error::Invalid("status code is not three digits"));
        }
        let status = u16::from(status[0] - b'0') * 100
            + u16::from(status[1] - b'0') * 10
            + u16::from(status[2] - b'0');
        if !(100..600).contains(&status)
            || reason
                .iter()
                .any(|b| (*b < 0x20 && *b != b'\t') || *b == 0x7f)
        {
            return Err(Error::Invalid("status line contains an invalid value"));
        }
        Ok(StartLine::Response {
            version,
            status,
            reason: input.slice_ref(reason),
        })
    } else {
        let parts: Vec<_> = input.split(|b| *b == b' ').collect();
        if parts.len() != 3
            || parts[0].is_empty()
            || !parts[0].iter().all(|b| token(*b))
            || parts[1].is_empty()
            || parts[1].iter().any(|b| *b <= 0x20 || *b == 0x7f)
        {
            return Err(Error::Invalid("request line is malformed"));
        }
        Ok(StartLine::Request {
            method: String::from_utf8(parts[0].to_vec()).expect("ASCII token"),
            target: input.slice_ref(parts[1]),
            version: version(parts[2])?,
        })
    }
}
fn version(input: &[u8]) -> Result<String, Error> {
    match input {
        b"HTTP/1.0" => Ok("HTTP/1.0".to_owned()),
        b"HTTP/1.1" => Ok("HTTP/1.1".to_owned()),
        _ => Err(Error::Invalid("version is not HTTP/1.0 or HTTP/1.1")),
    }
}
/// Parses one `Transfer-Encoding` field value (`1#transfer-coding`),
/// pushing each coding name lowercased. Commas and semicolons inside a
/// parameter's quoted-string separate nothing.
fn transfer_codings(mut input: &[u8], codings: &mut Vec<Vec<u8>>) -> Result<(), Error> {
    loop {
        input = ows(input);
        let name = take_token(&mut input);
        if name.is_empty() {
            return Err(Error::Invalid("has an invalid transfer coding"));
        }
        codings.push(name.to_ascii_lowercase());
        input = ows(input);
        while input.first() == Some(&b';') {
            input = ows(&input[1..]);
            if take_token(&mut input).is_empty() {
                return Err(Error::Invalid("has an invalid transfer coding parameter"));
            }
            input = ows(input);
            if input.first() != Some(&b'=') {
                return Err(Error::Invalid("has an invalid transfer coding parameter"));
            }
            input = ows(&input[1..]);
            if input.first() == Some(&b'"') {
                input = quoted_string(input)?;
            } else if take_token(&mut input).is_empty() {
                return Err(Error::Invalid("has an invalid transfer coding parameter"));
            }
            input = ows(input);
        }
        match input.first() {
            None => return Ok(()),
            Some(b',') => input = &input[1..],
            Some(_) => return Err(Error::Invalid("has an invalid transfer coding")),
        }
    }
}
/// Consumes a `quoted-string` that opens at `input[0]`, returning the bytes
/// after its closing quote. A quoted-pair skips its escaped byte.
fn quoted_string(input: &[u8]) -> Result<&[u8], Error> {
    let mut index = 1;
    while index < input.len() {
        match input[index] {
            b'\\' => index += 2,
            b'"' => return Ok(&input[index + 1..]),
            _ => index += 1,
        }
    }
    Err(Error::Invalid(
        "has an unterminated transfer coding parameter",
    ))
}
fn take_token<'a>(input: &mut &'a [u8]) -> &'a [u8] {
    let end = input.iter().position(|b| !token(*b)).unwrap_or(input.len());
    let (name, rest) = input.split_at(end);
    *input = rest;
    name
}
fn ows(mut input: &[u8]) -> &[u8] {
    while input.first().is_some_and(|b| matches!(b, b' ' | b'\t')) {
        input = &input[1..];
    }
    input
}
pub(crate) fn token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}
pub(crate) fn trim(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(|b| matches!(b, b' ' | b'\t')) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(|b| matches!(b, b' ' | b'\t')) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}
fn validate_line_endings(input: &[u8]) -> Result<(), Error> {
    for (i, b) in input.iter().enumerate() {
        if (*b == b'\n' && (i == 0 || input[i - 1] != b'\r'))
            || (*b == b'\r' && i + 1 < input.len() && input[i + 1] != b'\n')
        {
            return Err(Error::Invalid("uses a bare CR or LF"));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct HttpCodec;
impl LayerCodec for HttpCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &http_schema().protocol
    }
    fn accepts_decoded_protocol(&self, protocol: &crate::layer::Id) -> bool {
        matches!(protocol.as_str(), NAME | "raw")
    }
    fn published_schema(&self) -> Option<&'static crate::layer::Schema> {
        Some(http_schema())
    }
    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Http>(NAME, layer)?;
        ensure_encode_budget(NAME, layer.head.wire().len(), context)?;
        Ok(
            EncodedLayer::header(layer.head.wire().to_vec(), Box::new(layer.clone()))
                .with_fields(http_layout()),
        )
    }
    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let Ok(Some((head, consumed))) = parse_head(&input) else {
            let mut raw = DecodedLayer::terminal(Box::new(Raw::new(input.clone())), input.len());
            raw.fields = raw_layout(input.len());
            return Ok(raw);
        };
        Ok(DecodedLayer {
            layer: Box::new(Http { head }),
            consumed,
            payload_len: input.len() - consumed,
            next: if consumed < input.len() {
                vec![Discriminator(0)]
            } else {
                Vec::new()
            },
            fields: http_layout(),
            diagnostics: Vec::new(),
            stop: false,
            network: None,
        })
    }
    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        let Some(FieldValue::Bytes(wire)) = fields.get("wire") else {
            return Err(invalid(
                NAME,
                "HTTP/1 dissection requires retained header wire",
            ));
        };
        let mut layer = Http::try_from(wire.as_ref()).map_err(|error| rejected(NAME, error))?;
        for (name, value) in fields {
            if layer.field(name).as_ref() != Some(value) {
                layer.set_field(name, value.clone())?;
            }
        }
        Ok(Box::new(layer))
    }
}
