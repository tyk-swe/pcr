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
    while input.first().is_some_and(|byte| matches!(byte, b' ' | b'\t')) {
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

/// CSP directive names are ASCII-insensitive; the first duplicate wins.
/// Multiple comma-separated policies are each enforced independently.
pub(super) fn framing_csp(value: &str) -> bool {
    value.split(',').any(|policy| {
        for directive in policy.split(';').filter(|directive| directive.is_ascii()) {
            let mut words = directive.split_ascii_whitespace();
            if words
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case("frame-ancestors"))
            {
                let mut found = false;
                for source in words {
                    if source == "*" {
                        return false;
                    }
                    found = true;
                }
                return found;
            }
        }
        false
    })
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
    fn csp_directive_names_are_ascii_case_insensitive() {
        assert!(framing_csp("FrAmE-AnCeStOrS 'none'"));
    }

    #[test]
    fn csp_uses_the_first_directive_in_each_policy() {
        assert!(!framing_csp("frame-ancestors *; frame-ancestors 'none'"));
        assert!(framing_csp("frame-ancestors 'none'; frame-ancestors *"));
        assert!(framing_csp("frame-ancestors *, frame-ancestors 'none'"));
    }

    #[test]
    fn csp_does_not_treat_unicode_whitespace_as_a_separator() {
        assert!(!framing_csp("frame-ancestors\u{a0}'none'"));
    }
}
