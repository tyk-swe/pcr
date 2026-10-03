// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::str::FromStr;

use super::{Session, Status};

/// Runs on assembled sessions: a frame filter would drop the ServerHello.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Selector {
    pub sni: Option<SniPattern>,
    pub server_port: Option<u16>,
    pub statuses: Vec<Status>,
}

impl Selector {
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

/// A server-name literal compared case-insensitively, optionally loosened at either end by `*`.
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
