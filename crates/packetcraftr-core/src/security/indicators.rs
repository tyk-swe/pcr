// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::Error;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::IpAddr};

pub const SCHEMA: &str = "packetcraftr.indicators/v1";
pub const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;
pub const MAX_INDICATORS: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Ip,
    Cidr,
    Domain,
    DomainSuffix,
    Ja3,
    Ja4,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Indicator {
    pub id: String,
    pub kind: Kind,
    pub value: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub schema: String,
    pub indicators: Vec<Indicator>,
}

impl Document {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(Error::Limit {
                field: "indicator_bytes",
                limit: MAX_DOCUMENT_BYTES,
            });
        }
        let mut doc: Self =
            serde_json::from_slice(bytes).map_err(|e| Error::Invalid(e.to_string()))?;
        doc.validate()?;
        Ok(doc)
    }

    /// Validate indicator identities and normalize values for matching.
    pub fn validate(&mut self) -> Result<(), Error> {
        if self.schema != SCHEMA
            || self.indicators.is_empty()
            || self.indicators.len() > MAX_INDICATORS
        {
            return Err(Error::Invalid(
                "expected indicators/v1 with 1..4096 indicators".into(),
            ));
        }
        let mut ids = BTreeSet::new();
        for i in &mut self.indicators {
            if i.id.trim().is_empty()
                || i.id.len() > 128
                || i.id.chars().any(char::is_control)
                || !ids.insert(i.id.clone())
            {
                return Err(Error::Invalid(
                    "indicator IDs must be unique, printable, and 1..128 bytes".into(),
                ));
            }
            i.value = i.value.to_ascii_lowercase();
            let valid = match i.kind {
                Kind::Ip => i.value.parse::<IpAddr>().is_ok(),
                Kind::Cidr => network(&i.value).is_some(),
                Kind::Domain | Kind::DomainSuffix => {
                    i.value = i.value.strip_suffix('.').unwrap_or(&i.value).into();
                    valid_domain(&i.value)
                }
                Kind::Ja3 => i.value.len() == 32 && i.value.bytes().all(|b| b.is_ascii_hexdigit()),
                Kind::Ja4 => {
                    let parts: Vec<_> = i.value.split('_').collect();
                    parts.len() == 3
                        && parts[0].len() == 10
                        && parts[0].bytes().all(|b| b.is_ascii_alphanumeric())
                        && parts[1..]
                            .iter()
                            .all(|s| s.len() == 12 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                }
            };
            if !valid {
                return Err(Error::Invalid(format!(
                    "invalid value for indicator {}",
                    i.id
                )));
            }
        }
        Ok(())
    }
}
fn valid_domain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}
fn network(s: &str) -> Option<(IpAddr, u8)> {
    let (ip, prefix) = s.split_once('/')?;
    let ip = ip.parse::<IpAddr>().ok()?;
    if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let prefix = prefix.parse::<u8>().ok()?;
    let bits = if ip.is_ipv4() { 32 } else { 128 };
    if prefix > bits {
        return None;
    }
    Some((ip, prefix))
}
impl Indicator {
    pub fn matches_ip(&self, candidate: IpAddr) -> bool {
        match self.kind {
            Kind::Ip => self.value.parse::<IpAddr>() == Ok(candidate),
            Kind::Cidr => {
                network(&self.value).is_some_and(|(base, prefix)| match (base, candidate) {
                    (IpAddr::V4(a), IpAddr::V4(b)) => {
                        prefix == 0
                            || (u32::from(a) >> (32 - prefix)) == (u32::from(b) >> (32 - prefix))
                    }
                    (IpAddr::V6(a), IpAddr::V6(b)) => {
                        prefix == 0
                            || (u128::from(a) >> (128 - prefix))
                                == (u128::from(b) >> (128 - prefix))
                    }
                    _ => false,
                })
            }
            _ => false,
        }
    }
    pub fn matches_domain(&self, candidate: &str) -> bool {
        if !matches!(self.kind, Kind::Domain | Kind::DomainSuffix) {
            return false;
        }
        let candidate = candidate.strip_suffix('.').unwrap_or(candidate);
        let value = self.value.strip_suffix('.').unwrap_or(&self.value);
        if !valid_domain(candidate) || !valid_domain(value) {
            return false;
        }
        if candidate.eq_ignore_ascii_case(value) {
            return true;
        }
        // Validation guarantees ASCII, so the suffix boundary is a UTF-8 boundary.
        matches!(self.kind, Kind::DomainSuffix)
            && candidate.len() > value.len()
            && candidate.as_bytes()[candidate.len() - value.len() - 1] == b'.'
            && candidate[candidate.len() - value.len()..].eq_ignore_ascii_case(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipv6_cidr_domain_boundaries_and_validation() {
        let d=Document::parse(br#"{"schema":"packetcraftr.indicators/v1","indicators":[{"id":"net","kind":"cidr","value":"2001:db8::/32"},{"id":"dns","kind":"domain_suffix","value":"Example.Test."}]}"#).unwrap();
        assert!(d.indicators[0].matches_ip("2001:db8::1".parse().unwrap()));
        assert!(!d.indicators[0].matches_ip("2001:db9::1".parse().unwrap()));
        assert!(d.indicators[1].matches_domain("A.EXAMPLE.TEST."));
        assert!(!d.indicators[1].matches_domain("badexample.test"));
        for input in [br#"{"schema":"packetcraftr.indicators/v2","indicators":[]}"#.as_slice(),br#"{"schema":"packetcraftr.indicators/v1","indicators":[{"id":"a","kind":"ja3","value":"invalid"}]}"#,br#"{"schema":"packetcraftr.indicators/v1","indicators":[{"id":"a","kind":"ip","value":"127.0.0.1"},{"id":"a","kind":"ip","value":"127.0.0.2"}]}"#] { assert!(Document::parse(input).is_err()); }
    }
}

#[cfg(test)]
mod input_regressions {
    use super::*;

    fn document(id: &str, kind: Kind, value: &str) -> Result<Document, Error> {
        let bytes = serde_json::to_vec(&Document {
            schema: SCHEMA.into(),
            indicators: vec![Indicator {
                id: id.into(),
                kind,
                value: value.into(),
            }],
        })
        .unwrap();
        Document::parse(&bytes)
    }

    #[test]
    fn domains_have_at_most_one_root_terminator() {
        let parsed = document("dns", Kind::Domain, "example.test.").unwrap();
        assert!(parsed.indicators[0].matches_domain("EXAMPLE.TEST."));
        assert!(!parsed.indicators[0].matches_domain("badexample.test"));
        assert!(document("dns", Kind::Domain, "example.test..").is_err());
    }

    #[test]
    fn cidr_prefixes_are_decimal_not_signed() {
        assert!(document("net", Kind::Cidr, "192.0.2.0/+24").is_err());
        let parsed = document("net", Kind::Cidr, "2001:db8::/0").unwrap();
        assert!(parsed.indicators[0].matches_ip("2001:db9::7".parse().unwrap()));
        assert!(parsed.indicators[0].matches_ip("::1".parse().unwrap()));
        assert!(!parsed.indicators[0].matches_ip("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn blank_identifiers_are_not_useful_evidence_names() {
        assert!(document("   ", Kind::Ip, "192.0.2.1").is_err());
        let parsed = document("dns name", Kind::Domain, "example.test").unwrap();
        assert_eq!(parsed.indicators[0].id, "dns name");
        assert!(parsed.indicators[0].matches_domain("example.test"));
    }

    #[test]
    fn domain_matching_validates_candidate_labels() {
        let indicator = Indicator {
            id: "dns".into(),
            kind: Kind::DomainSuffix,
            value: "example.test".into(),
        };
        for candidate in [
            ".example.test",
            "a..example.test",
            "example.test..",
            "-a.example.test",
            "a\0.example.test",
        ] {
            assert!(!indicator.matches_domain(candidate), "{candidate:?}");
        }
        assert!(!indicator.matches_domain(&format!("{}.example.test", "a".repeat(64))));
    }

    #[test]
    fn public_indicators_match_case_insensitively_without_normalization() {
        let indicator = Indicator {
            id: "dns".into(),
            kind: Kind::DomainSuffix,
            value: "EXAMPLE.TEST.".into(),
        };
        assert!(indicator.matches_domain("a.example.test."));
        assert!(!indicator.matches_domain("badexample.test"));
        assert!(
            !Indicator {
                value: ".".into(),
                ..indicator
            }
            .matches_domain("anything.")
        );
    }
}
