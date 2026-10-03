// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::model::{Header, MessageKind};
use crate::analysis::provenance::SourceSet;
use bytes::Bytes;

pub(crate) const CLIENT: usize = 0;
pub(crate) const SERVER: usize = 1;
pub(crate) fn peer(side: usize) -> usize {
    1 - side
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Reserved,
    Open,
    Closed,
}

pub(crate) struct MsgBuild {
    pub index: u64,
    pub stream_id: u32,
    pub kind: MessageKind,
    pub request: Option<u64>,
    pub promised_by: Option<u32>,
    pub headers: Vec<Header>,
    pub trailers: Vec<Header>,
    pub header_blocks: Vec<Bytes>,
    pub upgrade_head: Option<crate::protocol::application::http::Head>,
    pub body_bytes: u64,
    pub sets: Vec<SourceSet>,
    pub compression: Vec<SourceSet>,
    pub failure: Option<crate::analysis::http2::Status>,
    pub saw_body: bool,
    pub trailers_seen: bool,
    pub content_length: Option<u64>,
    pub status_code: Option<u16>,
    pub charged: usize,
    pub charged_spans: usize,
}

impl MsgBuild {
    pub(crate) fn new(index: u64, stream_id: u32, kind: MessageKind) -> Self {
        Self {
            index,
            stream_id,
            kind,
            request: None,
            promised_by: None,
            headers: Vec::new(),
            trailers: Vec::new(),
            header_blocks: Vec::new(),
            upgrade_head: None,
            body_bytes: 0,
            sets: Vec::new(),
            compression: Vec::new(),
            failure: None,
            saw_body: false,
            trailers_seen: false,
            content_length: None,
            status_code: None,
            charged: 0,
            charged_spans: 0,
        }
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct EarlyResponse {
    pub final_seen: bool,
    pub forbids_trailers: bool,
    pub ended: bool,
}

pub(crate) struct StreamState {
    pub phase: Phase,
    pub by_client: bool,
    pub promised_by: Option<u32>,
    pub ended: [bool; 2],
    pub request: Option<u64>,
    pub msgs: [Option<MsgBuild>; 2],
    pub send_window: [i64; 2],
    pub credit_exceeded: [bool; 2],
    pub window_granted: [i64; 2],
    pub early_response: Option<EarlyResponse>,
    pub method: Option<Bytes>,
    pub response_bodyless: bool,
    pub unprocessed: bool,
}

impl StreamState {
    pub(crate) fn open(by_client: bool, windows: [i64; 2]) -> Self {
        Self {
            phase: Phase::Open,
            by_client,
            promised_by: None,
            ended: [false, false],
            request: None,
            msgs: [None, None],
            send_window: windows,
            credit_exceeded: [false; 2],
            window_granted: [0; 2],
            early_response: None,
            method: None,
            response_bodyless: false,
            unprocessed: false,
        }
    }
    pub(crate) fn reserved(promised_by: u32, windows: [i64; 2]) -> Self {
        let mut stream = Self::open(false, windows);
        stream.phase = Phase::Reserved;
        stream.promised_by = Some(promised_by);
        stream.ended = [true, false];
        stream
    }
}

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

fn token(b: u8) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_'
        | b'`' | b'|' | b'~' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

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

pub(super) fn valid_uri_path(path: &[u8]) -> bool {
    let mut pos = 0;
    while pos < path.len() {
        let byte = path[pos];
        if byte == b'%' {
            if !path
                .get(pos + 1..pos + 3)
                .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
            {
                return false;
            }
            pos += 3;
        } else {
            if !byte.is_ascii_alphanumeric()
                && !matches!(
                    byte,
                    b'-' | b'.'
                        | b'_'
                        | b'~'
                        | b'!'
                        | b'$'
                        | b'&'
                        | b'\''
                        | b'('
                        | b')'
                        | b'*'
                        | b'+'
                        | b','
                        | b';'
                        | b'='
                        | b':'
                        | b'@'
                        | b'/'
                        | b'?'
                )
            {
                return false;
            }
            pos += 1;
        }
    }
    true
}

pub(super) fn valid_http_authority(authority: &[u8]) -> bool {
    valid_authority(authority, true)
}

// RFC 3986 authority, with HTTP's stricter userinfo and nonempty-host rules.
pub(super) fn valid_authority(authority: &[u8], http: bool) -> bool {
    fn host_char(byte: u8) -> bool {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
            )
    }
    fn port(suffix: &[u8]) -> bool {
        suffix.is_empty()
            || suffix
                .strip_prefix(b":")
                .is_some_and(|digits| digits.iter().all(u8::is_ascii_digit))
    }
    let authority = if !http {
        if let Some(at) = authority.iter().position(|byte| *byte == b'@') {
            let userinfo = &authority[..at];
            if !valid_uri_path(userinfo)
                || userinfo
                    .iter()
                    .any(|byte| matches!(byte, b'/' | b'?' | b'@'))
            {
                return false;
            }
            &authority[at + 1..]
        } else {
            authority
        }
    } else {
        authority
    };
    if let Some(literal) = authority.strip_prefix(b"[") {
        let Some(end) = literal.iter().position(|byte| *byte == b']') else {
            return false;
        };
        let address = &literal[..end];
        let valid_address = if address
            .first()
            .is_some_and(|byte| matches!(byte, b'v' | b'V'))
        {
            address[1..]
                .iter()
                .position(|byte| *byte == b'.')
                .is_some_and(|dot| {
                    let version = &address[1..1 + dot];
                    let host = &address[2 + dot..];
                    !version.is_empty()
                        && version.iter().all(u8::is_ascii_hexdigit)
                        && !host.is_empty()
                        && host.iter().all(|byte| host_char(*byte) || *byte == b':')
                })
        } else {
            std::str::from_utf8(address)
                .ok()
                .and_then(|text| text.parse::<std::net::Ipv6Addr>().ok())
                .is_some()
        };
        return valid_address && port(&literal[end + 1..]);
    }
    let end = authority
        .iter()
        .position(|byte| *byte == b':')
        .unwrap_or(authority.len());
    let host = &authority[..end];
    if (http && host.is_empty()) || !port(&authority[end..]) {
        return false;
    }
    let mut pos = 0;
    while pos < host.len() {
        if host[pos] == b'%' {
            if !host
                .get(pos + 1..pos + 3)
                .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
            {
                return false;
            }
            pos += 3;
        } else {
            if !host_char(host[pos]) {
                return false;
            }
            pos += 1;
        }
    }
    true
}

fn authorities_equal(a: &[u8], b: &[u8], default_port: Option<&'static [u8]>) -> bool {
    fn normalized(value: &[u8], fold_case: bool) -> impl Iterator<Item = u8> + '_ {
        let mut pos = 0;
        std::iter::from_fn(move || {
            let mut byte = *value.get(pos)?;
            if byte == b'%'
                && let Some(hex) = value.get(pos + 1..pos + 3)
                && let (Some(high), Some(low)) =
                    ((hex[0] as char).to_digit(16), (hex[1] as char).to_digit(16))
            {
                let decoded = (high * 16 + low) as u8;
                if decoded.is_ascii_alphanumeric() || matches!(decoded, b'-' | b'.' | b'_' | b'~') {
                    byte = decoded;
                    pos += 2;
                }
            }
            pos += 1;
            Some(if fold_case {
                byte.to_ascii_lowercase()
            } else {
                byte
            })
        })
    }
    fn user_host(value: &[u8]) -> (Option<&[u8]>, &[u8]) {
        value
            .iter()
            .position(|byte| *byte == b'@')
            .map_or((None, value), |at| (Some(&value[..at]), &value[at + 1..]))
    }
    fn parts<'a>(
        value: &'a [u8],
        default_port: Option<&'static [u8]>,
    ) -> (&'a [u8], Option<&'a [u8]>) {
        let end = if value.starts_with(b"[") {
            value
                .iter()
                .position(|byte| *byte == b']')
                .map_or(value.len(), |end| end + 1)
        } else {
            value
                .iter()
                .position(|byte| *byte == b':')
                .unwrap_or(value.len())
        };
        let port = value
            .get(end..)
            .and_then(|suffix| suffix.strip_prefix(b":"))
            .filter(|port| !port.is_empty())
            .or(default_port)
            .map(|port| {
                &port[port
                    .iter()
                    .position(|byte| *byte != b'0')
                    .unwrap_or(port.len() - 1)..]
            });
        (&value[..end], port)
    }
    fn ipv6(host: &[u8]) -> Option<std::net::Ipv6Addr> {
        let host = host.strip_prefix(b"[")?.strip_suffix(b"]")?;
        std::str::from_utf8(host).ok()?.parse().ok()
    }
    let (user_a, a) = user_host(a);
    let (user_b, b) = user_host(b);
    if user_a.is_some() != user_b.is_some()
        || !normalized(user_a.unwrap_or_default(), false)
            .eq(normalized(user_b.unwrap_or_default(), false))
    {
        return false;
    }
    let (host_a, port_a) = parts(a, default_port);
    let (host_b, port_b) = parts(b, default_port);
    port_a == port_b
        && match (ipv6(host_a), ipv6(host_b)) {
            (Some(a), Some(b)) => a == b,
            _ => normalized(host_a, true).eq(normalized(host_b, true)),
        }
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
                (FieldRole::Request, b":protocol") => meta.protocol = true,
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
            if name == b"host" && role == FieldRole::Trailer {
                return Err("Host routing information is invalid in trailers");
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
