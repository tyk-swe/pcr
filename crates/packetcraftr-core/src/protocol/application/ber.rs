// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
//! Minimal definite-length BER. Unknown values are retained, never interpreted heuristically.
use crate::{
    codec::Error,
    protocol::{
        common::{invalid, unsupported},
        message::*,
    },
};
pub(super) fn take<'a>(r: &mut Reader<'a>) -> Result<(u8, &'a [u8]), Error> {
    let b = &r.bytes[r.pos..];
    let total = super::super::framing::ber_length(b, r.name)?
        .ok_or_else(|| invalid(r.name, "truncated BER header"))?;
    let tag = r.u8()?;
    let first = r.u8()?;
    let len = if first < 128 {
        first as usize
    } else {
        let count = (first & 127) as usize;
        let mut n = 0;
        for _ in 0..count {
            n = n * 256 + usize::from(r.u8()?);
        }
        n
    };
    if total
        > r.left()
            + 2
            + if first < 128 {
                0
            } else {
                usize::from(first & 127)
            }
    {
        return Err(invalid(r.name, "truncated BER value"));
    }
    Ok((tag, r.take(len)?))
}
pub(super) fn put(w: &mut Writer, tag: u8, b: &[u8]) -> Result<(), Error> {
    if tag & 31 == 31 {
        return Err(unsupported("ber", "high-tag-number encoding"));
    }
    w.u8(tag)?;
    if b.len() < 128 {
        w.u8(b.len() as u8)?;
    } else {
        let bytes = (b.len() as u64).to_be_bytes();
        let i = bytes.iter().position(|b| *b != 0).unwrap_or(7);
        if bytes.len() - i > 4 {
            return Err(invalid("ber", "BER length too large"));
        }
        w.u8(128 + (bytes.len() - i) as u8)?;
        w.put(&bytes[i..])?;
    }
    w.put(b)
}
pub(super) fn integer(b: &[u8], name: &'static str) -> Result<i64, Error> {
    if b.is_empty() || b.len() > 8 {
        return Err(invalid(name, "invalid BER integer width"));
    }
    if b.len() > 1 && (b[0] == 0 && b[1] & 128 == 0 || b[0] == 255 && b[1] & 128 != 0) {
        return Err(unsupported(name, "noncanonical BER integer"));
    }
    let mut n = if b[0] & 128 != 0 { -1i64 } else { 0 };
    for byte in b {
        n = (n << 8) | i64::from(*byte);
    }
    Ok(n)
}
pub(super) fn int(w: &mut Writer, tag: u8, n: i64) -> Result<(), Error> {
    let bytes = n.to_be_bytes();
    let mut i = 0;
    while i < 7
        && (bytes[i] == 0 && bytes[i + 1] & 128 == 0 || bytes[i] == 255 && bytes[i + 1] & 128 != 0)
    {
        i += 1;
    }
    put(w, tag, &bytes[i..])
}
pub(super) fn expect<'a>(r: &mut Reader<'a>, tag: u8) -> Result<&'a [u8], Error> {
    let (t, b) = take(r)?;
    if t != tag {
        return Err(invalid(r.name, "unexpected BER tag"));
    }
    Ok(b)
}
pub(super) fn validate(name: &'static str, b: &[u8]) -> Result<(), Error> {
    walk(name, b, 0, &mut 0)
}
fn walk(name: &'static str, b: &[u8], depth: usize, nodes: &mut usize) -> Result<(), Error> {
    if depth >= MAX_NESTING {
        return Err(invalid(name, "BER nesting limit"));
    }
    let mut r = Reader::new(name, b);
    while r.left() > 0 {
        *nodes += 1;
        if *nodes > MAX_RECORDS {
            return Err(invalid(name, "BER node limit"));
        }
        let (tag, value) = take(&mut r)?;
        if tag & 32 != 0 {
            walk(name, value, depth + 1, nodes)?;
        }
    }
    Ok(())
}
