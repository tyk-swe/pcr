// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::protocol::{
    common::{invalid, structured::member, unsupported},
    message::{Records, Writer, data, record},
};
use crate::{
    codec::Error,
    field,
    layer::FieldSchema,
    layout::{ByteRange, FieldLayout},
};
use bytes::Bytes;

pub(super) const HEADERS: &[FieldSchema] = &[
    member("name", field::Kind::Bytes, &[]),
    member("value", field::Kind::Bytes, &[]),
];
pub(super) fn encode(
    name: &'static str,
    start: &[u8],
    headers: &Records,
    body: &[u8],
    max: usize,
) -> Result<Vec<u8>, Error> {
    let mut w = Writer::new(name, max);
    validate_start_line(name, start)?;
    w.put(start)?;
    w.put(b"\r\n")?;
    if headers.0.len() > 256 {
        return Err(invalid(name, "too many headers"));
    }
    for h in &headers.0 {
        let key = data(h, "name", name)?;
        let value = data(h, "value", name)?;
        if !valid_name(name, key) || !valid_value(value) {
            return Err(invalid(name, "invalid header"));
        }
        w.put(key)?;
        w.u8(b':')?;
        w.put(value)?;
        w.put(b"\r\n")?;
    }
    if w.bytes.len() > 65532 {
        return Err(invalid(name, "headers too large"));
    }
    w.put(b"\r\n")?;
    w.put(body)?;
    Ok(w.bytes)
}
/// Parses a message whose start line carries `version`, with the layouts of its
/// start line, headers and body.
pub(super) fn parse_versioned(
    name: &'static str,
    version: &str,
    b: &[u8],
) -> Result<(Bytes, Records, Bytes, Vec<FieldLayout>), Error> {
    let (start_line, headers, body) = parse(name, b)?;
    let text = std::str::from_utf8(&start_line).map_err(|_| invalid(name, "invalid start line"))?;
    let parts: Vec<_> = text.splitn(3, ' ').collect();
    if parts.len() != 3
        || !(parts[0] == version
            && parts[1].len() == 3
            && parts[1].bytes().all(|b| b.is_ascii_digit())
            || parts[2] == version && !parts[1].is_empty() && is_token(name, parts[0].as_bytes()))
    {
        return Err(unsupported(name, "unsupported start line or version"));
    }
    let body_start = b.len() - body.len();
    let fields = vec![
        FieldLayout {
            index: 0,
            range: ByteRange::new(0, start_line.len()),
        },
        FieldLayout {
            index: 1,
            range: ByteRange::new(start_line.len() + 2, body_start - 2),
        },
        FieldLayout {
            index: 2,
            range: ByteRange::new(body_start, b.len()),
        },
    ];
    Ok((start_line, headers, body, fields))
}

pub(super) fn parse(name: &'static str, b: &[u8]) -> Result<(Bytes, Records, Bytes), Error> {
    let head = parse_head(name, b)?;
    if head.length.is_some_and(|n| n != b.len() - head.end) {
        return Err(invalid(name, "Content-Length does not match body"));
    }
    Ok((
        head.start,
        head.headers,
        Bytes::copy_from_slice(&b[head.end..]),
    ))
}

pub(crate) fn content_length(name: &'static str, head: &[u8]) -> Result<Option<usize>, Error> {
    Ok(parse_head(name, head)?.length)
}

pub(crate) fn datagram_length(name: &'static str, bytes: &[u8]) -> Result<usize, Error> {
    let head = parse_head(name, bytes)?;
    let Some(length) = head.length else {
        return Ok(bytes.len());
    };
    let end = head
        .end
        .checked_add(length)
        .ok_or_else(|| invalid(name, "length overflow"))?;
    if end > bytes.len() {
        return Err(crate::protocol::common::truncated(name, end, bytes.len()));
    }
    Ok(end)
}

struct Head {
    start: Bytes,
    headers: Records,
    length: Option<usize>,
    end: usize,
}

fn parse_head(name: &'static str, b: &[u8]) -> Result<Head, Error> {
    let end = b
        .windows(4)
        .position(|b| b == b"\r\n\r\n")
        .ok_or_else(|| invalid(name, "incomplete headers"))?
        + 4;
    if end > 65536 {
        return Err(invalid(name, "headers too large"));
    }
    let first = b[..end]
        .windows(2)
        .position(|v| v == b"\r\n")
        .ok_or_else(|| invalid(name, "missing start line"))?;
    validate_start_line(name, &b[..first])?;
    let start = Bytes::copy_from_slice(&b[..first]);
    let mut pos = first + 2;
    let mut headers = Records::default();
    let mut length = None;
    while pos < end - 2 {
        let len = b[pos..end]
            .windows(2)
            .position(|v| v == b"\r\n")
            .ok_or_else(|| invalid(name, "unterminated header"))?;
        let line = &b[pos..pos + len];
        let colon = line
            .iter()
            .position(|v| *v == b':')
            .ok_or_else(|| invalid(name, "header lacks colon"))?;
        let key = &line[..colon];
        let value_start = pos + colon + 1;
        let mut value_end = pos + len;
        pos = value_end + 2;
        while pos < end - 2 && matches!(b[pos], b' ' | b'\t') {
            let len = b[pos..end]
                .windows(2)
                .position(|v| v == b"\r\n")
                .ok_or_else(|| invalid(name, "unterminated continuation"))?;
            value_end = pos + len;
            pos = value_end + 2;
        }
        let value = &b[value_start..value_end];
        if !valid_name(name, key) || !valid_value(value) {
            return Err(invalid(name, "invalid header"));
        }
        let key_name = key.trim_ascii_end();
        if key_name.eq_ignore_ascii_case(b"content-length")
            || (name == "sip" && key_name.eq_ignore_ascii_case(b"l"))
        {
            // Legal folding is checked above. Only SP and HTAB are optional whitespace.
            let unfolded = std::str::from_utf8(value)
                .map_err(|_| invalid(name, "invalid Content-Length"))?
                .replace("\r\n", " ");
            let digits = unfolded.trim_matches([' ', '\t']).as_bytes();
            if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
                return Err(invalid(name, "invalid Content-Length"));
            }
            let n = std::str::from_utf8(digits)
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .ok_or_else(|| invalid(name, "invalid Content-Length"))?;
            if length.is_some_and(|old| old != n) {
                return Err(invalid(name, "conflicting Content-Length"));
            }
            length = Some(n);
        }
        if headers.0.len() == 256 {
            return Err(invalid(name, "too many headers"));
        }
        headers.0.push(record([
            ("name", Bytes::copy_from_slice(key).into()),
            ("value", Bytes::copy_from_slice(value).into()),
        ]));
    }
    Ok(Head {
        start,
        headers,
        length,
        end,
    })
}

fn validate_start_line(name: &'static str, start: &[u8]) -> Result<(), Error> {
    if start.is_empty() || start.iter().any(|b| matches!(*b, b'\r' | b'\n')) {
        return Err(invalid(name, "invalid start line"));
    }
    Ok(())
}

fn valid_name(protocol: &'static str, key: &[u8]) -> bool {
    let name = key.trim_ascii_end();
    is_token(protocol, name) && key[name.len()..].iter().all(|b| matches!(b, b' ' | b'\t'))
}

pub(super) fn is_token(protocol: &'static str, value: &[u8]) -> bool {
    let punctuation: &[u8] = if protocol == "sip" {
        b"-.!%*_+`'~"
    } else {
        b"!#$%&'*+-.^_`|~"
    };
    !value.is_empty()
        && value
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || punctuation.contains(b))
}

fn valid_value(value: &[u8]) -> bool {
    let mut pos = 0;
    while pos < value.len() {
        match value[pos] {
            b'\r'
                if value.get(pos + 1) == Some(&b'\n')
                    && matches!(value.get(pos + 2), Some(b' ' | b'\t')) =>
            {
                pos += 2;
            }
            b'\r' | b'\n' => return false,
            _ => pos += 1,
        }
    }
    true
}
