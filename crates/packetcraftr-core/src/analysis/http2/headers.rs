// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Decoded header roles, metadata, validation, and method/status extraction.

use super::model::Header;
use bytes::Bytes;

use crate::protocol::application::http::token;

mod uri;

pub(super) use uri::{authorities_equal, valid_authority, valid_http_authority, valid_uri_path};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FieldRole {
    Request,
    Response,
    Trailer,
}

#[derive(Default)]
pub(crate) struct Meta {
    pub method: Option<Bytes>,
    pub status: Option<u16>,
    pub content_length: Option<u64>,
    pub scheme: bool,
    pub path: bool,
    pub authority: Option<Bytes>,
    pub protocol: bool,
    pub host: Option<Bytes>,
}

const FORBIDDEN: &[&[u8]] = &[
    b"connection",
    b"keep-alive",
    b"proxy-connection",
    b"transfer-encoding",
    b"upgrade",
    b"http2-settings",
];

/// Fields that RFC 9110 §6.5.1 forbids in trailers: message framing, routing,
/// request modifiers and conditionals, authentication, cache control, and the
/// fields that determine how to process the content.
const FORBIDDEN_TRAILERS: &[&[u8]] = &[
    b"authorization",
    b"cache-control",
    b"content-encoding",
    b"content-length",
    b"content-location",
    b"content-range",
    b"content-type",
    b"cookie",
    b"expect",
    b"host",
    b"if-match",
    b"if-modified-since",
    b"if-none-match",
    b"if-range",
    b"if-unmodified-since",
    b"max-forwards",
    b"proxy-authenticate",
    b"proxy-authorization",
    b"range",
    b"set-cookie",
    b"te",
    b"trailer",
    b"transfer-encoding",
    b"www-authenticate",
];

fn is_pseudo(name: &[u8]) -> bool {
    name.first() == Some(&b':')
}

fn check_name(name: &[u8], pseudo: bool) -> Result<(), &'static str> {
    let body = if pseudo { &name[1..] } else { name };
    if body.is_empty() {
        return Err("header field name is empty");
    }
    if name.iter().any(u8::is_ascii_uppercase) {
        return Err("header field name is not lowercase");
    }
    if body.iter().any(|b| !token(*b) || b.is_ascii_uppercase()) {
        return Err("header field name is not a valid token");
    }
    if !pseudo && name.contains(&b':') {
        return Err("header field name contains ':'");
    }
    Ok(())
}

fn check_value(value: &[u8]) -> Result<(), &'static str> {
    if value
        .iter()
        .any(|b| (*b < 0x20 && *b != b'\t') || *b == 0x7f)
    {
        return Err("header field value contains a forbidden control byte");
    }
    if value.first().is_some_and(|b| matches!(b, b' ' | b'\t'))
        || value.last().is_some_and(|b| matches!(b, b' ' | b'\t'))
    {
        return Err("header field value has leading or trailing whitespace");
    }
    Ok(())
}

pub(crate) fn validate(role: FieldRole, fields: &[Header]) -> Result<Meta, &'static str> {
    let mut meta = Meta::default();
    let mut regular_seen = false;
    let mut pseudo_seen = Vec::new();
    let mut asterisk = false;
    let mut http_scheme = false;
    let mut default_port = None;
    for field in fields {
        let name: &[u8] = &field.name;
        let value: &[u8] = &field.value;
        check_value(value)?;
        if is_pseudo(name) {
            check_name(name, true)?;
            if role == FieldRole::Trailer {
                return Err("trailer block carries a pseudo-header field");
            }
            if regular_seen {
                return Err("pseudo-header field follows a regular field");
            }
            if pseudo_seen.contains(&name) {
                return Err("duplicate pseudo-header field");
            }
            pseudo_seen.push(name);
            match (role, name) {
                (FieldRole::Request, b":method") => {
                    if value.is_empty() || !value.iter().all(|b| token(*b)) {
                        return Err(":method is not a valid HTTP token");
                    }
                    meta.method = Some(field.value.clone());
                }
                (FieldRole::Request, b":scheme") => {
                    if !value.first().is_some_and(u8::is_ascii_alphabetic)
                        || !value[1..]
                            .iter()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
                    {
                        return Err(":scheme is empty or invalid");
                    }
                    meta.scheme = true;
                    default_port = if value.eq_ignore_ascii_case(b"http") {
                        Some(b"80".as_slice())
                    } else if value.eq_ignore_ascii_case(b"https") {
                        Some(b"443".as_slice())
                    } else {
                        None
                    };
                    http_scheme = default_port.is_some();
                }
                (FieldRole::Request, b":path") => {
                    if value.is_empty() {
                        return Err(":path is empty");
                    }
                    if value != b"*"
                        && value
                            .iter()
                            .any(|b| matches!(*b, b' ' | b'\t' | b'#') || *b < 0x20 || *b == 0x7f)
                    {
                        return Err(":path carries a fragment, whitespace or control bytes");
                    }
                    if value != b"*" && !value.starts_with(b"/") {
                        return Err(":path must be absolute or the OPTIONS asterisk form");
                    }
                    if value != b"*" && !valid_uri_path(value) {
                        return Err(":path has invalid URI characters or percent escapes");
                    }
                    asterisk = value == b"*";
                    meta.path = true;
                }
                (FieldRole::Request, b":authority") => meta.authority = Some(field.value.clone()),
                (FieldRole::Request, b":protocol") => {
                    if value.is_empty() || !value.iter().all(|b| token(*b)) {
                        return Err(":protocol is not a protocol token");
                    }
                    meta.protocol = true;
                }
                (FieldRole::Response, b":status") => {
                    if value.len() != 3 {
                        return Err(":status is not a three-digit code");
                    }
                    let status = value
                        .iter()
                        .try_fold(0u32, |n, b| {
                            if b.is_ascii_digit() {
                                n.checked_mul(10)?.checked_add(u32::from(b - b'0'))
                            } else {
                                None
                            }
                        })
                        .and_then(|n| u16::try_from(n).ok())
                        .filter(|n| (100..=599).contains(n))
                        .ok_or(":status is not a valid status code")?;
                    meta.status = Some(status);
                }
                _ => return Err("pseudo-header field invalid for this message kind"),
            }
        } else {
            check_name(name, false)?;
            regular_seen = true;
            if FORBIDDEN.contains(&name) {
                return Err("connection-specific header field is forbidden");
            }
            if name == b"te" {
                if role != FieldRole::Request {
                    return Err("te field is only valid on requests");
                }
                if !value.eq_ignore_ascii_case(b"trailers") {
                    return Err("te field may only carry 'trailers'");
                }
            }
            if role == FieldRole::Trailer && FORBIDDEN_TRAILERS.contains(&name) {
                return Err("field is prohibited in trailers");
            }
            if name == b"host" && role == FieldRole::Request {
                if meta.host.is_some() {
                    return Err("request contains multiple Host fields");
                }
                meta.host = Some(field.value.clone());
            }
            if name == b"content-length" {
                if role == FieldRole::Trailer {
                    return Err("content-length is invalid in trailers");
                }
                if let Some(status) = meta.status
                    && role == FieldRole::Response
                    && (status < 200 || status == 204)
                {
                    return Err("content-length is invalid on this response");
                }
                if value.is_empty() {
                    return Err("content-length is not a decimal value");
                }
                let parsed = value
                    .iter()
                    .try_fold(0u64, |n, b| {
                        if b.is_ascii_digit() {
                            n.checked_mul(10)?.checked_add(u64::from(b - b'0'))
                        } else {
                            None
                        }
                    })
                    .ok_or("content-length is not a decimal value")?;
                if meta.content_length.is_some_and(|old| old != parsed) {
                    return Err("conflicting content-length values");
                }
                meta.content_length = Some(parsed);
            }
        }
    }
    match role {
        FieldRole::Request => {
            if !pseudo_seen.contains(&b":method".as_slice()) {
                return Err("request lacks :method");
            }
            if asterisk && meta.method.as_deref() != Some(b"OPTIONS") {
                return Err("asterisk :path requires OPTIONS");
            }
            if meta
                .authority
                .as_ref()
                .is_some_and(|authority| !valid_authority(authority, http_scheme))
            {
                return Err("authority has invalid URI syntax");
            }
            if http_scheme && meta.authority.is_none() && meta.host.is_none() {
                return Err("HTTP requests require :authority or Host");
            }
            if http_scheme
                && meta.authority.is_none()
                && meta
                    .host
                    .as_ref()
                    .is_some_and(|host| !valid_http_authority(host))
            {
                return Err("Host authority has an invalid host or port");
            }
            let connect = meta.method.as_deref() == Some(b"CONNECT");
            if meta.protocol && !connect {
                return Err(":protocol is only valid for CONNECT");
            }
            if connect && !meta.protocol {
                if meta.scheme || meta.path {
                    return Err("CONNECT requests omit :scheme and :path");
                }
                let Some(authority) = meta.authority.as_ref() else {
                    return Err("CONNECT requests require :authority");
                };
                if !valid_http_authority(authority)
                    || !authority.contains(&b':')
                    || authority
                        .rsplit(|b| *b == b':')
                        .next()
                        .is_none_or(|port| port.is_empty() || !port.iter().all(u8::is_ascii_digit))
                {
                    return Err("CONNECT authority requires a valid host and explicit port");
                }
            } else {
                for required in [b":scheme".as_slice(), b":path".as_slice()] {
                    if !pseudo_seen.contains(&required) {
                        return Err("request lacks a required pseudo-header field");
                    }
                }
                if meta.protocol && meta.authority.as_ref().is_none_or(Bytes::is_empty) {
                    return Err("extended CONNECT requests require :authority");
                }
            }
            if let (Some(authority), Some(host)) = (&meta.authority, &meta.host)
                && !authorities_equal(authority, host, default_port)
            {
                return Err("host differs from :authority");
            }
        }
        FieldRole::Response => {
            if meta.status.is_none() {
                return Err("response lacks :status");
            }
            if meta.status == Some(101) {
                return Err("101 is not a valid HTTP/2 response status");
            }
        }
        FieldRole::Trailer => {}
    }
    Ok(meta)
}

/// Recover only an unambiguous, syntactically valid response status after
/// other header semantics failed, so informational/final sequencing survives.
pub(crate) fn response_status(fields: &[Header]) -> Option<u16> {
    let mut statuses = fields
        .iter()
        .filter(|field| field.name.as_ref() == b":status");
    let value = &statuses.next()?.value;
    if statuses.next().is_some() || value.len() != 3 || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let status = value.iter().fold(0u16, |n, b| n * 10 + u16::from(b - b'0'));
    (100..=599).contains(&status).then_some(status)
}

/// Preserve method-dependent response semantics after unrelated field errors.
pub(crate) fn request_method(fields: &[Header]) -> Option<Bytes> {
    let mut methods = fields
        .iter()
        .filter(|field| field.name.as_ref() == b":method");
    let value = &methods.next()?.value;
    if methods.next().is_some() || value.is_empty() || !value.iter().all(|b| token(*b)) {
        return None;
    }
    Some(value.clone())
}

#[cfg(test)]
mod tests;
