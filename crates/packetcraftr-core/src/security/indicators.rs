// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::Error;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    hash::Hash,
    net::IpAddr,
};

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

    pub(crate) fn compile(&mut self) -> Result<Matcher, Error> {
        self.validate()?;
        let positions = || self.indicators.iter().enumerate();
        let values = |kinds: &'static [Kind]| {
            positions()
                .filter(|(_, indicator)| kinds.contains(&indicator.kind))
                .map(|(position, indicator)| (indicator.value.clone(), position))
        };
        let networks = index(
            positions()
                .filter_map(|(position, indicator)| Some((indicator.network_key()?, position))),
        );
        Ok(Matcher {
            entries: self
                .indicators
                .iter()
                .map(|indicator| (indicator.id.clone(), indicator.kind))
                .collect(),
            prefixes: networks
                .keys()
                .map(|(base, prefix)| (base.is_ipv6(), *prefix))
                .collect(),
            networks,
            fingerprints: index(values(&[Kind::Ja3, Kind::Ja4])),
            domains: index(values(&[Kind::Domain, Kind::DomainSuffix])),
            suffixes: index(values(&[Kind::DomainSuffix])),
        })
    }
}

/// Validated indicators indexed by the value an observation is looked up by.
pub(crate) struct Matcher {
    entries: Vec<(String, Kind)>,
    networks: HashMap<(IpAddr, u8), Vec<usize>>,
    prefixes: BTreeSet<(bool, u8)>,
    fingerprints: HashMap<String, Vec<usize>>,
    domains: HashMap<String, Vec<usize>>,
    suffixes: HashMap<String, Vec<usize>>,
}

impl Matcher {
    pub(crate) fn ip(&self, candidate: IpAddr) -> Vec<String> {
        let family = candidate.is_ipv6();
        self.ids(
            self.prefixes
                .range((family, 0)..=(family, u8::MAX))
                .filter_map(|&(_, prefix)| {
                    self.networks.get(&(prefix_key(candidate, prefix), prefix))
                })
                .flatten()
                .copied(),
        )
    }

    pub(crate) fn fingerprint(&self, kind: Kind, value: &str) -> Vec<String> {
        self.ids(
            self.fingerprints
                .get(value)
                .into_iter()
                .flatten()
                .copied()
                .filter(|&position| self.entries[position].1 == kind),
        )
    }

    pub(crate) fn domain(&self, candidate: &str) -> Vec<String> {
        let candidate = candidate.strip_suffix('.').unwrap_or(candidate);
        if !valid_domain(candidate) {
            return Vec::new();
        }
        let candidate = candidate.to_ascii_lowercase();
        let suffixes = candidate
            .match_indices('.')
            .filter_map(|(dot, _)| self.suffixes.get(&candidate[dot + 1..]));
        self.ids(
            self.domains
                .get(&candidate)
                .into_iter()
                .chain(suffixes)
                .flatten()
                .copied(),
        )
    }

    fn ids(&self, positions: impl Iterator<Item = usize>) -> Vec<String> {
        positions
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|position| self.entries[position].0.clone())
            .collect()
    }
}

fn index<K: Hash + Eq>(keys: impl Iterator<Item = (K, usize)>) -> HashMap<K, Vec<usize>> {
    let mut index: HashMap<K, Vec<usize>> = HashMap::new();
    for (key, position) in keys {
        index.entry(key).or_default().push(position);
    }
    index
}

fn prefix_key(ip: IpAddr, prefix: u8) -> IpAddr {
    let prefix = u32::from(prefix);
    match ip {
        IpAddr::V4(ip) => IpAddr::V4(
            (u32::from(ip)
                & u32::MAX
                    .checked_shl(32_u32.saturating_sub(prefix))
                    .unwrap_or(0))
            .into(),
        ),
        IpAddr::V6(ip) => IpAddr::V6(
            (u128::from(ip)
                & u128::MAX
                    .checked_shl(128_u32.saturating_sub(prefix))
                    .unwrap_or(0))
            .into(),
        ),
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
        self.network_key()
            .is_some_and(|(base, prefix)| prefix_key(candidate, prefix) == base)
    }
    fn network_key(&self) -> Option<(IpAddr, u8)> {
        match self.kind {
            Kind::Ip => {
                let ip = self.value.parse::<IpAddr>().ok()?;
                Some((ip, if ip.is_ipv4() { 32 } else { 128 }))
            }
            Kind::Cidr => {
                network(&self.value).map(|(base, prefix)| (prefix_key(base, prefix), prefix))
            }
            _ => None,
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
    fn compiled_matcher_agrees_with_each_indicator() {
        let ja3 = "a".repeat(32);
        let ja4 = format!("t13d1516h2_{}_{}", "b".repeat(12), "c".repeat(12));
        let mut document = Document {
            schema: SCHEMA.into(),
            indicators: [
                ("host4", Kind::Ip, "192.0.2.1"),
                ("host6", Kind::Ip, "2001:db8::1"),
                ("mapped", Kind::Ip, "::ffff:192.0.2.1"),
                ("net24", Kind::Cidr, "192.0.2.0/24"),
                ("unmasked", Kind::Cidr, "203.0.113.200/25"),
                ("single", Kind::Cidr, "198.51.100.7/32"),
                ("any4", Kind::Cidr, "0.0.0.0/0"),
                ("net6", Kind::Cidr, "2001:db8::/32"),
                ("any6", Kind::Cidr, "::/0"),
                ("exact", Kind::Domain, "Example.Test."),
                ("suffix", Kind::DomainSuffix, "example.test"),
                ("tld", Kind::DomainSuffix, "test"),
                ("ja3", Kind::Ja3, &ja3),
                ("ja4", Kind::Ja4, &ja4),
            ]
            .into_iter()
            .map(|(id, kind, value)| Indicator {
                id: id.into(),
                kind,
                value: value.into(),
            })
            .collect(),
        };
        let matcher = document.compile().unwrap();
        let ids = |matches: &dyn Fn(&Indicator) -> bool| -> Vec<String> {
            document
                .indicators
                .iter()
                .filter(|indicator| matches(indicator))
                .map(|indicator| indicator.id.clone())
                .collect()
        };
        for candidate in [
            "192.0.2.1",
            "192.0.2.255",
            "192.0.3.1",
            "198.51.100.7",
            "198.51.100.6",
            "203.0.113.128",
            "203.0.113.127",
            "2001:db8::1",
            "2001:db8:ffff::1",
            "2001:db9::1",
            "::ffff:192.0.2.1",
        ] {
            let ip = candidate.parse().unwrap();
            assert_eq!(matcher.ip(ip), ids(&|i| i.matches_ip(ip)), "{candidate}");
        }
        for candidate in [
            "example.test",
            "A.EXAMPLE.TEST.",
            "badexample.test",
            "test",
            "other.test",
            "a..example.test",
            ".example.test",
            "example.org",
            "",
        ] {
            assert_eq!(
                matcher.domain(candidate),
                ids(&|i| i.matches_domain(candidate)),
                "{candidate}"
            );
        }
        for (kind, value) in [
            (Kind::Ja3, &ja3),
            (Kind::Ja4, &ja4),
            (Kind::Ja4, &ja3),
            (Kind::Ja3, &ja3.to_uppercase()),
        ] {
            assert_eq!(
                matcher.fingerprint(kind, value),
                ids(&|i| i.kind == kind && i.value == *value),
                "{kind:?} {value}"
            );
        }
        assert_eq!(
            matcher.ip("192.0.2.1".parse().unwrap()),
            ["host4", "net24", "any4"]
        );
        assert_eq!(
            matcher.ip("203.0.113.128".parse().unwrap()),
            ["unmasked", "any4"]
        );
        assert_eq!(
            matcher.ip("2001:db8:ffff::1".parse().unwrap()),
            ["net6", "any6"]
        );
        assert_eq!(matcher.domain("A.EXAMPLE.TEST."), ["suffix", "tld"]);
        assert_eq!(matcher.domain("example.test"), ["exact", "suffix", "tld"]);
    }

    #[test]
    fn domains_allow_one_root_terminator() {
        assert!(document("dns", Kind::Domain, "example.test.").is_ok());
        assert!(document("dns", Kind::Domain, "example.test..").is_err());
    }

    #[test]
    fn cidr_prefixes_are_decimal_not_signed() {
        assert!(document("net", Kind::Cidr, "192.0.2.0/+24").is_err());
        assert!(document("net", Kind::Cidr, "2001:db8::/0").is_ok());
    }

    #[test]
    fn blank_evidence_identifiers_are_rejected() {
        assert!(document("   ", Kind::Ip, "192.0.2.1").is_err());
        assert!(document("dns name", Kind::Domain, "example.test").is_ok());
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
    fn deeply_nested_json_is_rejected() {
        let depth = 100_000;
        let nested = [vec![b'['; depth], vec![b']'; depth]].concat();
        assert!(nested.len() < MAX_DOCUMENT_BYTES);
        assert!(Document::parse(&nested).is_err());
    }

    #[test]
    fn public_indicators_match_ignoring_case() {
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
