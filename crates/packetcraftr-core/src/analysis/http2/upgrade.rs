// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::protocol::application::http::{Head, StartLine};
use crate::protocol::application::http2::Setting;
use std::collections::{BTreeMap, VecDeque};

pub(crate) struct Prelude {
    pub requests: VecDeque<Pending>,
    pub offers: BTreeMap<u64, Offer>,
    pub client_body: Option<crate::protocol::application::http::BodyDecoder>,
    pub server_body: Option<crate::protocol::application::http::BodyDecoder>,
    pub live_request: Option<super::stream::MsgBuild>,
    pub live_response: Option<super::stream::MsgBuild>,
    pub upgraded: bool,
    pub body_charge: [usize; 2],
}

pub(crate) struct Pending {
    pub index: u64,
    pub method: Option<String>,
    pub upgrade: bool,
}

pub(crate) struct Offer {
    pub settings: Vec<Setting>,
    pub msg: Option<super::stream::MsgBuild>,
}

impl Prelude {
    pub(crate) fn new() -> Self {
        Self {
            requests: VecDeque::new(),
            offers: BTreeMap::new(),
            client_body: None,
            server_body: None,
            live_request: None,
            live_response: None,
            upgraded: false,
            body_charge: [0; 2],
        }
    }
}

fn tokens<'a>(head: &'a Head, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
    head.values(name)
        .flat_map(|value| value.split(|b| *b == b','))
        .map(|token| {
            let token: &[u8] = token;
            let mut start = 0;
            let mut end = token.len();
            while start < end && token[start].is_ascii_whitespace() {
                start += 1;
            }
            while end > start && token[end - 1].is_ascii_whitespace() {
                end -= 1;
            }
            &token[start..end]
        })
        .filter(|token| !token.is_empty())
}

fn has_token(head: &Head, name: &str, want: &[u8]) -> bool {
    tokens(head, name).any(|token| token.eq_ignore_ascii_case(want))
}

fn http11(head: &Head) -> bool {
    let version = match &head.start {
        StartLine::Request { version, .. } | StartLine::Response { version, .. } => version,
    };
    version == "HTTP/1.1"
}

pub(crate) fn upgrade_offer(head: &Head) -> Result<Option<Vec<Setting>>, &'static str> {
    if !has_token(head, "upgrade", b"h2c") {
        return Ok(None);
    }
    if !http11(head) {
        return Err("h2c upgrade requires an HTTP/1.1 request");
    }
    if !has_token(head, "connection", b"upgrade")
        || !has_token(head, "connection", b"http2-settings")
    {
        return Err("Connection must include upgrade and HTTP2-Settings");
    }
    let mut settings = head.values("http2-settings");
    let encoded = settings.next().ok_or("HTTP2-Settings header is missing")?;
    if settings.next().is_some() {
        return Err("HTTP2-Settings must appear exactly once");
    }
    let decoded = base64url(encoded)?;
    if decoded.len() % 6 != 0 {
        return Err("HTTP2-Settings payload is not a SETTINGS list");
    }
    let mut pairs = Vec::with_capacity(decoded.len() / 6);
    for chunk in decoded.chunks(6) {
        pairs.push(Setting {
            id: u16::from_be_bytes([chunk[0], chunk[1]]),
            value: u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]),
        });
    }
    Ok(Some(pairs))
}

pub(crate) fn accepts_upgrade(head: &Head) -> bool {
    http11(head)
        && head.status() == Some(101)
        && has_token(head, "connection", b"upgrade")
        && has_token(head, "upgrade", b"h2c")
}

fn base64url(input: &[u8]) -> Result<Vec<u8>, &'static str> {
    if input.len() % 4 == 1 {
        return Err("HTTP2-Settings base64url length is impossible");
    }
    let value = |b: u8| -> Result<u8, &'static str> {
        match b {
            b'A'..=b'Z' => Ok(b - b'A'),
            b'a'..=b'z' => Ok(b - b'a' + 26),
            b'0'..=b'9' => Ok(b - b'0' + 52),
            b'-' => Ok(62),
            b'_' => Ok(63),
            _ => Err("HTTP2-Settings is not unpadded base64url"),
        }
    };
    let mut out = Vec::with_capacity(input.len() * 3 / 4 + 3);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &b in input {
        acc = (acc << 6) | u32::from(value(b)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        return Err("HTTP2-Settings base64url has nonzero tail bits");
    }
    Ok(out)
}
