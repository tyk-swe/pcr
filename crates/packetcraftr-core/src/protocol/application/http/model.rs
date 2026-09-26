// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Http {
    pub(super) head: Head,
}
impl Http {
    pub fn head(&self) -> &Head {
        &self.head
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: Bytes,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StartLine {
    Request {
        method: String,
        target: Bytes,
        version: String,
    },
    Response {
        version: String,
        status: u16,
        reason: Bytes,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub start: StartLine,
    pub headers: Vec<Header>,
    pub(super) wire: Bytes,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "type", content = "length", rename_all = "snake_case")]
pub enum Body {
    None,
    Length(u64),
    Chunked,
    Close,
    Tunnel,
}
impl Head {
    pub fn wire(&self) -> &Bytes {
        &self.wire
    }
    pub fn method(&self) -> Option<&str> {
        match &self.start {
            StartLine::Request { method, .. } => Some(method),
            StartLine::Response { .. } => None,
        }
    }
    pub fn status(&self) -> Option<u16> {
        match self.start {
            StartLine::Response { status, .. } => Some(status),
            StartLine::Request { .. } => None,
        }
    }
    pub fn values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> {
        self.headers
            .iter()
            .filter(move |h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_ref())
    }
}
