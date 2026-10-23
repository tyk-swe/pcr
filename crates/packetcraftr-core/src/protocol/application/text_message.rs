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
        if key.is_empty()
            || key.iter().any(|b| !b.is_ascii_alphanumeric() && *b != b'-')
            || value.iter().any(|b| matches!(*b, b'\r' | b'\n'))
        {
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
        let value = &line[colon + 1..];
        if key.is_empty()
            || key.iter().any(|b| !b.is_ascii_alphanumeric() && *b != b'-')
            || value.iter().any(|b| matches!(*b, b'\r' | b'\n'))
        {
            return Err(invalid(name, "invalid header"));
        }
        if key.eq_ignore_ascii_case(b"content-length")
            || (name == "sip" && key.eq_ignore_ascii_case(b"l"))
        {
            let n = std::str::from_utf8(value)
                .ok()
                .and_then(|s| s.trim().parse::<usize>().ok())
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
        pos += len + 2;
    }
    if length.is_some_and(|n| n != b.len() - end) {
        return Err(invalid(name, "Content-Length does not match body"));
    }
    Ok((start, headers, Bytes::copy_from_slice(&b[end..])))
}
