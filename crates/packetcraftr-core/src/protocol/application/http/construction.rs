// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Error, Header, Http, MAX_HEADER_BYTES, StartLine};
use crate::{
    field::FieldValue,
    protocol::common::{
        invalid, rejected,
        structured::{self, Object},
    },
};
use bytes::Bytes;
use std::collections::BTreeMap;

pub const MAX_CONSTRUCTED_BODY_BYTES: usize = 16 * 1024 * 1024;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Framing {
    #[default]
    ContentLength,
    Chunked,
}
impl Http {
    /// Builds a typed start line and ordered headers, deriving body framing.
    /// Supplied Content-Length and Transfer-Encoding headers are replaced.
    pub fn new(
        start: StartLine,
        headers: Vec<Header>,
        body: Bytes,
        framing: Framing,
    ) -> Result<Self, Error> {
        let version = match &start {
            StartLine::Request { version, .. } | StartLine::Response { version, .. } => version,
        };
        if framing == Framing::Chunked && version != "HTTP/1.1" {
            return Err(Error::Invalid("chunked framing requires HTTP/1.1"));
        }
        let start_bytes = match &start {
            StartLine::Request {
                method,
                target,
                version,
            } => method
                .len()
                .saturating_add(target.len())
                .saturating_add(version.len())
                .saturating_add(2),
            StartLine::Response {
                version, reason, ..
            } => version.len().saturating_add(reason.len()).saturating_add(5),
        };
        if start_bytes > super::MAX_START_LINE {
            return Err(Error::Limit(super::Limit::StartLine));
        }
        if body.len() > MAX_CONSTRUCTED_BODY_BYTES {
            return Err(Error::Limit(super::Limit::BodyBytes));
        }
        let no_body = matches!(&start,StartLine::Response {status,..} if (100..200).contains(status) || matches!(status,204|304));
        if no_body && (!body.is_empty() || framing == Framing::Chunked) {
            return Err(Error::Invalid("response status forbids a body"));
        }
        let retained_headers = headers
            .iter()
            .filter(|header| {
                !header.name.eq_ignore_ascii_case("content-length")
                    && !header.name.eq_ignore_ascii_case("transfer-encoding")
            })
            .count();
        if retained_headers.saturating_add(usize::from(!no_body)) > super::MAX_HEADERS {
            return Err(Error::Limit(super::Limit::HeaderCount));
        }
        for header in &headers {
            if header.name.is_empty()
                || !header.name.bytes().all(super::codec::token)
                || header
                    .value
                    .iter()
                    .any(|b| *b != b'\t' && (*b < 0x20 || *b == 0x7f))
            {
                return Err(Error::Invalid(
                    "header name or value contains an invalid byte",
                ));
            }
        }
        let mut wire = Vec::new();
        match &start {
            StartLine::Request {
                method,
                target,
                version,
            } => {
                wire.extend_from_slice(method.as_bytes());
                wire.push(b' ');
                wire.extend_from_slice(target);
                wire.push(b' ');
                wire.extend_from_slice(version.as_bytes());
            }
            StartLine::Response {
                version,
                status,
                reason,
            } => {
                wire.extend_from_slice(version.as_bytes());
                wire.push(b' ');
                wire.extend_from_slice(format!("{status:03}").as_bytes());
                wire.push(b' ');
                wire.extend_from_slice(reason);
            }
        }
        wire.extend_from_slice(b"\r\n");
        for header in headers {
            if header.name.eq_ignore_ascii_case("content-length")
                || header.name.eq_ignore_ascii_case("transfer-encoding")
            {
                continue;
            }
            if wire
                .len()
                .saturating_add(header.name.len())
                .saturating_add(header.value.len())
                .saturating_add(4)
                > MAX_HEADER_BYTES
            {
                return Err(Error::Limit(super::Limit::HeaderBytes));
            }
            wire.extend_from_slice(header.name.as_bytes());
            wire.extend_from_slice(b": ");
            wire.extend_from_slice(&header.value);
            wire.extend_from_slice(b"\r\n");
            if wire.len() > MAX_HEADER_BYTES {
                return Err(Error::Limit(super::Limit::HeaderBytes));
            }
        }
        if !no_body {
            match framing {
                Framing::ContentLength => {
                    wire.extend_from_slice(
                        format!("Content-Length: {}\r\n", body.len()).as_bytes(),
                    );
                }
                Framing::Chunked => wire.extend_from_slice(b"Transfer-Encoding: chunked\r\n"),
            }
        }
        wire.extend_from_slice(b"\r\n");
        let mut layer = Self::try_from(wire.as_slice())?;
        if layer.head.start != start {
            return Err(Error::Invalid(
                "start line or header contains framing characters",
            ));
        }
        layer.head.body(None)?;
        layer.constructed = true;
        layer.constructed_body = match framing {
            Framing::ContentLength => body,
            Framing::Chunked => {
                let mut framed = Vec::new();
                if !body.is_empty() {
                    framed.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
                    framed.extend_from_slice(&body);
                    framed.extend_from_slice(b"\r\n");
                }
                framed.extend_from_slice(b"0\r\n\r\n");
                framed.into()
            }
        };
        Ok(layer)
    }
    /// Exact body framing supplied by construction. Decoded bodies remain separate layers.
    pub fn constructed_body(&self) -> &Bytes {
        &self.constructed_body
    }
}
impl Default for Http {
    fn default() -> Self {
        Self::new(
            StartLine::Request {
                method: "GET".to_owned(),
                target: Bytes::from_static(b"/"),
                version: "HTTP/1.1".to_owned(),
            },
            Vec::new(),
            Bytes::new(),
            Framing::ContentLength,
        )
        .expect("valid default HTTP request")
    }
}
pub(super) fn from_fields(
    fields: &BTreeMap<String, FieldValue>,
) -> Result<Http, crate::codec::Error> {
    let mut object = Object::new(
        FieldValue::Object(fields.clone()),
        super::reflection::http_schema(),
        "http",
    )?;
    let version = object.value("version", "HTTP/1.1".to_owned())?;
    let start = if object.contains("status") {
        StartLine::Response {
            version,
            status: object.required_value("status")?,
            reason: object.value("reason", Bytes::new())?,
        }
    } else {
        StartLine::Request {
            method: object.value("method", "GET".to_owned())?,
            target: object.value("target", Bytes::from_static(b"/"))?,
            version,
        }
    };
    let body = object.value("body", Bytes::new())?;
    let chunked = object.value("chunked", false)?;
    let mut headers = Vec::new();
    if let Some(value) = object.take("headers") {
        for value in structured::list(
            value,
            super::MAX_HEADERS,
            super::reflection::http_schema(),
            "headers",
        )? {
            let mut header = Object::new(value, super::reflection::http_schema(), "headers")?;
            headers.push(Header {
                name: header.required_value("name")?,
                value: header.required_value("value")?,
            });
            header.finish()?;
        }
    }
    object.finish()?;
    Http::new(
        start,
        headers,
        body,
        if chunked {
            Framing::Chunked
        } else {
            Framing::ContentLength
        },
    )
    .map_err(|error| rejected("http", error))
    .and_then(|layer| {
        if layer.head.body(None).is_err() {
            return Err(invalid("http", "constructed body framing is invalid"));
        }
        Ok(layer)
    })
}
