// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::protocol::{
    common::{invalid, structured::member},
    message::*,
};
use crate::{codec::Error, field, layer::FieldSchema};
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
    if start.iter().any(|b| matches!(*b, b'\r' | b'\n')) || start.is_empty() {
        return Err(invalid(name, "invalid start line"));
    }
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
            let n = std::str::from_utf8(value)
                .ok()
                .and_then(|s| s.replace("\r\n", " ").trim().parse::<usize>().ok())
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
