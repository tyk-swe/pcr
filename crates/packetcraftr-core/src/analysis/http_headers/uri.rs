// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! RFC 3986 path and authority syntax, and authority equivalence.

pub(crate) fn valid_uri_path(path: &[u8]) -> bool {
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

pub(crate) fn valid_http_authority(authority: &[u8]) -> bool {
    valid_authority(authority, true)
}

// RFC 3986 authority, with HTTP's stricter userinfo and nonempty-host rules.
pub(crate) fn valid_authority(authority: &[u8], http: bool) -> bool {
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

pub(crate) fn authorities_equal(a: &[u8], b: &[u8], default_port: Option<&'static [u8]>) -> bool {
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
