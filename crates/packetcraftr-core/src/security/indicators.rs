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
        if doc.schema != SCHEMA
            || doc.indicators.is_empty()
            || doc.indicators.len() > MAX_INDICATORS
        {
            return Err(Error::Invalid(
                "expected indicators/v1 with 1..4096 indicators".into(),
            ));
        }
        let mut ids = BTreeSet::new();
        for i in &mut doc.indicators {
            if i.id.is_empty()
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
                    i.value = i.value.trim_end_matches('.').into();
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
        Ok(doc)
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
        let candidate = candidate.trim_end_matches('.').to_ascii_lowercase();
        match self.kind {
            Kind::Domain => candidate == self.value,
            Kind::DomainSuffix => {
                candidate == self.value
                    || candidate
                        .strip_suffix(&self.value)
                        .is_some_and(|s| s.ends_with('.'))
            }
            _ => false,
        }
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
