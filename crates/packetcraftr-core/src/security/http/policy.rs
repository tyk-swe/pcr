// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Header-specific parsing for passive HTTP security findings.

use std::collections::BTreeSet;

use crate::protocol::application::http::token;

/// RFC 6797 sections 6.1 and 8.1: validate the entire first STS field,
/// including extensions, before recognizing a positive max-age.
pub(super) fn positive_hsts(mut input: &[u8]) -> bool {
    let mut seen = BTreeSet::new();
    let mut positive = false;
    while !input.is_empty() {
        input = trim_start(input);
        if input.is_empty() {
            break;
        }
        if input[0] == b';' {
            input = &input[1..];
            continue;
        }
        let length = input.iter().take_while(|byte| token(**byte)).count();
        if length == 0 {
            return false;
        }
        let name = input[..length].to_ascii_lowercase();
        if !seen.insert(name.clone()) {
            return false;
        }
        input = trim_start(&input[length..]);
        let value = if input.first() == Some(&b'=') {
            input = trim_start(&input[1..]);
            let Some(value) = directive_value(&mut input) else {
                return false;
            };
            Some(value)
        } else {
            None
        };
        match name.as_slice() {
            b"max-age" => {
                let Some(value) = value else {
                    return false;
                };
                if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                    return false;
                }
                // We only need positivity, not a platform-sized expiry time.
                positive = value.iter().any(|byte| *byte != b'0');
            }
            b"includesubdomains" if value.is_some() => return false,
            _ => {}
        }
        input = trim_start(input);
        if !input.is_empty() && input[0] != b';' {
            return false;
        }
    }
    positive
}

fn trim_start(mut input: &[u8]) -> &[u8] {
    while input
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        input = &input[1..];
    }
    input
}

fn directive_value(input: &mut &[u8]) -> Option<Vec<u8>> {
    if input.first() != Some(&b'"') {
        let length = input.iter().take_while(|byte| token(**byte)).count();
        if length == 0 {
            return None;
        }
        let value = input[..length].to_vec();
        *input = &input[length..];
        return Some(value);
    }
    let mut value = Vec::new();
    let mut cursor = 1;
    while let Some(&byte) = input.get(cursor) {
        cursor += 1;
        match byte {
            b'"' => {
                *input = &input[cursor..];
                return Some(value);
            }
            b'\\' => {
                let &escaped = input.get(cursor)?;
                if escaped != b'\t' && !(0x20..=0x7e).contains(&escaped) {
                    return None;
                }
                value.push(escaped);
                cursor += 1;
            }
            b'\t' | 0x20..=0x21 | 0x23..=0x5b | 0x5d..=0x7e => value.push(byte),
            _ => return None,
        }
    }
    None
}

/// Whether framing is restricted, given the raw `Content-Security-Policy` and
/// `X-Frame-Options` field values. Report-only policies never protect, and an
/// enforced `frame-ancestors` directive makes browsers ignore X-Frame-Options
/// (CSP3 "Relation to X-Frame-Options").
pub(super) fn framing_protected<'a>(
    csp: impl IntoIterator<Item = &'a [u8]>,
    x_frame_options: impl IntoIterator<Item = &'a [u8]>,
) -> bool {
    match frame_ancestors(csp) {
        FrameAncestors::Restricted => true,
        FrameAncestors::Unconfirmed => false,
        FrameAncestors::Absent => x_frame_options_protect(x_frame_options),
    }
}

/// Variants are ordered so the effective state of several enforced policies is
/// their maximum: one restrictive policy blocks framing for all of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum FrameAncestors {
    Absent,
    /// The directive is enforced but admits arbitrary origins (`*`, a
    /// scheme-source, or host `*`), or it is empty or has no recognized
    /// ancestor-source, so we cannot confirm a restriction.
    Unconfirmed,
    Restricted,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AncestorSource {
    Specific,
    AnyOrigin,
}

fn frame_ancestors<'a>(fields: impl IntoIterator<Item = &'a [u8]>) -> FrameAncestors {
    fields
        .into_iter()
        .flat_map(|field| field.split(|byte| *byte == b','))
        .map(policy_frame_ancestors)
        .max()
        .unwrap_or(FrameAncestors::Absent)
}

/// CSP3 "Parse a serialized CSP": the first directive with a given name wins.
fn policy_frame_ancestors(policy: &[u8]) -> FrameAncestors {
    let Some(sources) = policy
        .split(|byte| *byte == b';')
        .filter(|token| token.is_ascii())
        .filter_map(|token| str::from_utf8(token).ok())
        .map(str::split_ascii_whitespace)
        .find_map(|mut words| {
            words
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case("frame-ancestors"))
                .then(|| words.collect::<Vec<_>>())
        })
    else {
        return FrameAncestors::Absent;
    };
    if let [only] = sources.as_slice()
        && only.eq_ignore_ascii_case("'none'")
    {
        return FrameAncestors::Restricted;
    }
    let mut recognized = sources
        .iter()
        .filter_map(|source| ancestor_source(source))
        .peekable();
    if recognized.peek().is_some() && recognized.all(|source| source == AncestorSource::Specific) {
        FrameAncestors::Restricted
    } else {
        FrameAncestors::Unconfirmed
    }
}

/// CSP3 ancestor-source grammar. `None` is any other expression, which
/// matches nothing.
fn ancestor_source(expression: &str) -> Option<AncestorSource> {
    if expression.eq_ignore_ascii_case("'self'") {
        return Some(AncestorSource::Specific);
    }
    if expression.strip_suffix(':').is_some_and(scheme) {
        return Some(AncestorSource::AnyOrigin);
    }
    let rest = match expression.split_once("://") {
        Some((name, rest)) if scheme(name) => rest,
        Some(_) => return None,
        None => expression,
    };
    let (host, rest) = rest.split_at(rest.find([':', '/']).unwrap_or(rest.len()));
    if let Some(port) = rest.strip_prefix(':') {
        let port = &port[..port.find('/').unwrap_or(port.len())];
        if port != "*" && (port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit())) {
            return None;
        }
    }
    if host == "*" {
        return Some(AncestorSource::AnyOrigin);
    }
    host_part(host).then_some(AncestorSource::Specific)
}

fn scheme(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

fn host_part(host: &str) -> bool {
    let host = host.strip_prefix("*.").unwrap_or(host);
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// HTML "check a navigation response's adherence to X-Frame-Options", with the
/// field values combined and split per Fetch "get, decode, and split".
fn x_frame_options_protect<'a>(fields: impl IntoIterator<Item = &'a [u8]>) -> bool {
    let combined = fields.into_iter().collect::<Vec<_>>().join(&b", "[..]);
    let values: BTreeSet<Vec<u8>> = split_list(&combined)
        .map(|value| trim_tab_or_space(value).to_ascii_lowercase())
        .collect();
    let blocking: &[&[u8]] = if values.len() > 1 {
        &[b"deny", b"allowall", b"sameorigin"]
    } else {
        &[b"deny", b"sameorigin"]
    };
    values
        .iter()
        .any(|value| blocking.contains(&value.as_slice()))
}

/// Splits on commas outside HTTP quoted strings, keeping the quotes.
fn split_list(value: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut quoted = false;
    let mut escaped = false;
    value.split(move |&byte| {
        if escaped {
            escaped = false;
        } else if quoted {
            escaped = byte == b'\\';
            quoted = byte != b'"';
        } else if byte == b'"' {
            quoted = true;
        } else {
            return byte == b',';
        }
        false
    })
}

fn trim_tab_or_space(input: &[u8]) -> &[u8] {
    let content = |byte: &u8| !matches!(byte, b' ' | b'\t');
    let start = input.iter().position(content).unwrap_or(input.len());
    let end = input
        .iter()
        .rposition(content)
        .map_or(start, |last| last + 1);
    &input[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hsts_rejects_duplicate_directives_case_insensitively() {
        for value in [
            "max-age=0; max-age=1",
            "max-age=1; MAX-AGE=1",
            "max-age=1; includeSubDomains; includesubdomains",
        ] {
            assert!(!positive_hsts(value.as_bytes()), "{value}");
        }
    }

    #[test]
    fn hsts_accepts_quoted_values_and_quoted_pairs() {
        assert!(positive_hsts(br#"max-age="123""#));
        assert!(positive_hsts(br#"max-age="\1\2\3"; extension="a;b""#));
    }

    #[test]
    fn hsts_accepts_optional_whitespace_around_equals() {
        assert!(positive_hsts(b" max-age \t=\t 1 ; includeSubDomains "));
    }

    #[test]
    fn hsts_delta_seconds_are_digits_not_signed_integers() {
        for value in [
            "max-age=+1",
            "max-age=-1",
            "max-age=1.0",
            "max-age=0",
            "max-age=000",
        ] {
            assert!(!positive_hsts(value.as_bytes()), "{value}");
        }
    }

    #[test]
    fn hsts_positive_lifetime_need_not_fit_u64() {
        assert!(positive_hsts(b"max-age=184467440737095516160"));
    }

    #[test]
    fn malformed_extensions_invalidate_the_entire_hsts_field() {
        for value in [
            "max-age=1; includeSubDomains=yes",
            "max-age=1; bad@name",
            "max-age=1; x=",
            "max-age=1; x=\"unfinished",
        ] {
            assert!(!positive_hsts(value.as_bytes()), "{value}");
        }
        assert!(positive_hsts(b"max-age=1; preload; x=token"));
    }

    #[test]
    fn hsts_quoted_pairs_reject_unescapable_characters() {
        assert!(positive_hsts(b"max-age=1; x=\"a\\\tb\""));
        assert!(!positive_hsts(b"max-age=1; x=\"a\\\x01b\""));
        assert!(!positive_hsts(b"max-age=1; x=\"a\\\x7fb\""));
        assert!(!positive_hsts(b"max-age=1; x=\"a\\\""));
    }

    fn policy(value: &str) -> FrameAncestors {
        frame_ancestors([value.as_bytes()])
    }

    #[test]
    fn csp_directive_names_are_ascii_case_insensitive() {
        assert_eq!(policy("FrAmE-AnCeStOrS 'none'"), FrameAncestors::Restricted);
    }

    #[test]
    fn csp_uses_the_first_directive_in_each_policy() {
        assert_eq!(
            policy("frame-ancestors *; frame-ancestors 'none'"),
            FrameAncestors::Unconfirmed
        );
        assert_eq!(
            policy("frame-ancestors 'none'; frame-ancestors *"),
            FrameAncestors::Restricted
        );
        assert_eq!(
            policy("frame-ancestors *, frame-ancestors 'none'"),
            FrameAncestors::Restricted
        );
    }

    #[test]
    fn csp_does_not_treat_unicode_whitespace_as_a_separator() {
        assert_eq!(
            policy("frame-ancestors\u{a0}'none'"),
            FrameAncestors::Absent
        );
    }

    #[test]
    fn present_but_unconfirmed_frame_ancestors_is_distinct_from_absent() {
        assert_eq!(policy("default-src 'self'"), FrameAncestors::Absent);
        for value in [
            "frame-ancestors",
            "frame-ancestors 'unsafe-inline'",
            "frame-ancestors data:",
            "frame-ancestors https://*:*/path",
            "frame-ancestors 'none' *.",
            "frame-ancestors a.example:bad",
            "frame-ancestors 1a://a.example",
            "frame-ancestors -://a.example",
        ] {
            assert_eq!(policy(value), FrameAncestors::Unconfirmed, "{value}");
        }
    }
}
