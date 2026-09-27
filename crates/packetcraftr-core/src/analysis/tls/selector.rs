// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Which assembled sessions a consumer keeps.

use std::str::FromStr;

use super::{Session, Status};

/// Selects finished sessions by SNI, server port, and status.
///
/// Every test here runs on an assembled session rather than on a frame. A
/// frame filter would drop the ServerHello and turn each session into
/// [`Status::ClientOnly`]; only conversation selection
/// ([`Options::stream`](crate::analysis::Options::stream)) is safe to push
/// down to the frames. An empty selector keeps every session.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Selector {
    /// Keeps sessions whose client offered a matching server name.
    pub sni: Option<SniPattern>,
    /// Keeps sessions whose server listens on this port.
    pub server_port: Option<u16>,
    /// Keeps sessions with any of these statuses; empty keeps every status.
    pub statuses: Vec<Status>,
}

impl Selector {
    /// Whether `session` passes every test this selector sets.
    #[must_use]
    pub fn matches(&self, session: &Session) -> bool {
        if let Some(port) = self.server_port
            && session.server_endpoint.port != port
        {
            return false;
        }
        if !self.statuses.is_empty() && !self.statuses.contains(&session.status) {
            return false;
        }
        if let Some(pattern) = &self.sni {
            let name = session
                .client
                .as_ref()
                .and_then(|client| client.sni.as_deref());
            return name.is_some_and(|name| pattern.matches(name));
        }
        true
    }
}

/// A server-name pattern: a literal compared case-insensitively, optionally
/// loosened at either end by `*`.
///
/// `*` at the start, the end, or both is the whole vocabulary; it is not a
/// glob dialect.
///
/// ```
/// use packetcraftr_core::analysis::tls::SniPattern;
///
/// let pattern: SniPattern = "*.Example.test".parse().unwrap();
/// assert!(pattern.matches("api.example.test"));
/// assert!(!pattern.matches("example.test.invalid"));
/// assert!("a*b".parse::<SniPattern>().is_err());
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SniPattern {
    literal: String,
    leading: bool,
    trailing: bool,
}

impl SniPattern {
    /// Whether `name` matches, ignoring case.
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        let name = name.to_lowercase();
        match (self.leading, self.trailing) {
            (true, true) => name.contains(&self.literal),
            (true, false) => name.ends_with(&self.literal),
            (false, true) => name.starts_with(&self.literal),
            (false, false) => name == self.literal,
        }
    }
}

impl FromStr for SniPattern {
    type Err = crate::analysis::Error;

    fn from_str(pattern: &str) -> Result<Self, Self::Err> {
        let (leading, rest) = match pattern.strip_prefix('*') {
            Some(rest) => (true, rest),
            None => (false, pattern),
        };
        let (trailing, literal) = match rest.strip_suffix('*') {
            Some(literal) => (true, literal),
            None => (false, rest),
        };
        if literal.contains('*') {
            return Err(crate::analysis::Error::SniPattern {
                pattern: pattern.to_owned(),
            });
        }
        Ok(Self {
            literal: literal.to_lowercase(),
            leading,
            trailing,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_match_case_insensitively_with_optional_wildcard_ends() {
        let names = ["api.example.test", "files.example.test", "example.test"];
        let kept = |pattern: &str| {
            let pattern = pattern.parse::<SniPattern>().expect("valid pattern");
            names
                .into_iter()
                .filter(|name| pattern.matches(name))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            kept("*.example.test"),
            ["api.example.test", "files.example.test"]
        );
        assert_eq!(kept("api*"), ["api.example.test"]);
        assert_eq!(kept("*FILES*"), ["files.example.test"]);
        assert_eq!(kept("Example.Test"), ["example.test"]);
        assert!(kept("absent*").is_empty());
    }

    #[test]
    fn an_inner_wildcard_is_refused() {
        for pattern in ["a*b", "*a*b*", "**x"] {
            let error = pattern
                .parse::<SniPattern>()
                .expect_err("only the ends may be wildcards");
            assert!(
                matches!(&error, crate::analysis::Error::SniPattern { pattern: refused } if refused == pattern),
                "{error:?}"
            );
            assert_eq!(
                crate::error::Classified::classification(&error).code,
                "cli.error"
            );
        }
    }
}
