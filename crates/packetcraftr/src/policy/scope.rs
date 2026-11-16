// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::model::{DestinationConstraint, Error, MAX_DESTINATION_CONSTRAINTS, Policy};

pub const SCHEMA: &str = "packetcraftr.scope/v1";
pub const MAX_SCOPE_DOCUMENT_BYTES: usize = 1024 * 1024;
const MAX_LABEL_BYTES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawScope {
    schema: String,
    label: String,
    #[serde(default)]
    allowed_destinations: Vec<String>,
    #[serde(default)]
    denied_destinations: Vec<String>,
    #[serde(default)]
    allow_public_destinations: bool,
    #[serde(default)]
    allow_hostname_resolution: bool,
    #[serde(default)]
    allow_permissive_packets: bool,
    #[serde(default)]
    allow_source_spoofing: bool,
    #[serde(default)]
    max_packets: Option<u64>,
    #[serde(default)]
    max_bytes: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    pub label: String,
    pub allowed_destinations: Vec<DestinationConstraint>,
    pub denied_destinations: Vec<DestinationConstraint>,
    pub allow_public_destinations: bool,
    pub allow_hostname_resolution: bool,
    pub allow_permissive_packets: bool,
    pub allow_source_spoofing: bool,
    pub max_packets: Option<u64>,
    pub max_bytes: Option<u64>,
}

fn invalid(reason: String) -> Error {
    Error::InvalidScopeDocument { reason }
}

fn parse_constraints(
    values: Vec<String>,
    field: &str,
) -> Result<Vec<DestinationConstraint>, Error> {
    if values.len() > MAX_DESTINATION_CONSTRAINTS {
        return Err(invalid(format!(
            "{field} declares {} destinations, over the {MAX_DESTINATION_CONSTRAINTS} limit",
            values.len()
        )));
    }
    values
        .iter()
        .map(|value| {
            value.parse::<DestinationConstraint>().map_err(|_| {
                invalid(format!(
                    "{field} entry {value:?} is not an IP address or canonical CIDR network"
                ))
            })
        })
        .collect()
}

impl Scope {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_SCOPE_DOCUMENT_BYTES {
            return Err(invalid(format!(
                "scope document is {} bytes, over the {MAX_SCOPE_DOCUMENT_BYTES} byte limit",
                bytes.len()
            )));
        }
        let raw: RawScope =
            serde_json::from_slice(bytes).map_err(|source| invalid(source.to_string()))?;
        if raw.schema != SCHEMA {
            return Err(invalid(format!(
                "expected schema {SCHEMA:?}, got {:?}",
                raw.schema
            )));
        }
        if raw.label.trim().is_empty()
            || raw.label.len() > MAX_LABEL_BYTES
            || raw.label.chars().any(char::is_control)
        {
            return Err(invalid(
                "scope label must be printable and 1..=128 bytes".to_owned(),
            ));
        }
        Ok(Self {
            allowed_destinations: parse_constraints(
                raw.allowed_destinations,
                "allowed_destinations",
            )?,
            denied_destinations: parse_constraints(raw.denied_destinations, "denied_destinations")?,
            label: raw.label,
            allow_public_destinations: raw.allow_public_destinations,
            allow_hostname_resolution: raw.allow_hostname_resolution,
            allow_permissive_packets: raw.allow_permissive_packets,
            allow_source_spoofing: raw.allow_source_spoofing,
            max_packets: raw.max_packets,
            max_bytes: raw.max_bytes,
        })
    }

    #[must_use]
    pub fn digest(&self) -> String {
        let allowed = sorted(&self.allowed_destinations);
        let denied = sorted(&self.denied_destinations);
        let canonical = format!(
            "packetcraftr.scope/v1\nlabel={}\nallowed={}\ndenied={}\npublic={}\nhostname={}\npermissive={}\nspoofing={}\nmax_packets={}\nmax_bytes={}\n",
            self.label,
            allowed.join(","),
            denied.join(","),
            self.allow_public_destinations,
            self.allow_hostname_resolution,
            self.allow_permissive_packets,
            self.allow_source_spoofing,
            self.max_packets
                .map_or_else(|| "-".to_owned(), |value| value.to_string()),
            self.max_bytes
                .map_or_else(|| "-".to_owned(), |value| value.to_string()),
        );
        packetcraftr_core::field::hex::compact_hex(&Sha256::digest(canonical.as_bytes()))
    }

    /// A scope only narrows a policy. Boolean fields are ceilings, budgets
    /// keep the smaller value, denied destinations accumulate, and allowed
    /// destinations become one more group a destination must satisfy.
    #[must_use]
    pub fn narrow(&self, policy: &Policy) -> Policy {
        let mut narrowed = policy.clone();
        narrowed.allow_public_destinations &= self.allow_public_destinations;
        narrowed.allow_hostname_resolution &= self.allow_hostname_resolution;
        narrowed.allow_permissive_packets &= self.allow_permissive_packets;
        narrowed.allow_source_spoofing &= self.allow_source_spoofing;
        if let Some(max_packets) = self.max_packets {
            narrowed.max_packets_per_operation =
                narrowed.max_packets_per_operation.min(max_packets);
        }
        if let Some(max_bytes) = self.max_bytes {
            narrowed.max_bytes_per_operation = narrowed.max_bytes_per_operation.min(max_bytes);
        }
        narrowed
            .denied_destinations
            .extend(self.denied_destinations.iter().copied());
        if !self.allowed_destinations.is_empty() {
            narrowed
                .required_destination_groups
                .push(self.allowed_destinations.clone());
        }
        narrowed
    }
}

fn sorted(constraints: &[DestinationConstraint]) -> Vec<String> {
    let mut values: Vec<String> = constraints.iter().map(ToString::to_string).collect();
    values.sort();
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(document: &str) -> Result<Scope, Error> {
        Scope::parse(document.as_bytes())
    }

    #[test]
    fn rejects_wrong_schema_unknown_fields_and_bad_constraints() {
        for document in [
            r#"{"schema":"packetcraftr.scope/v2","label":"lab"}"#,
            r#"{"schema":"packetcraftr.scope/v1","label":"lab","extra":true}"#,
            r#"{"schema":"packetcraftr.scope/v1","label":"  "}"#,
            r#"{"schema":"packetcraftr.scope/v1","label":"lab","allowed_destinations":["example.test"]}"#,
            r#"{"schema":"packetcraftr.scope/v1","label":"lab","allowed_destinations":["192.0.2.1/24"]}"#,
        ] {
            assert!(parse(document).is_err(), "{document}");
        }
    }

    #[test]
    fn digest_ignores_json_formatting_and_list_order() {
        let first = parse(
            r#"{"schema":"packetcraftr.scope/v1","label":"lab","allowed_destinations":["192.0.2.0/24","10.0.0.1"],"max_packets":10}"#,
        )
        .unwrap();
        let second = parse(
            "{\n \"max_packets\": 10,\n \"allowed_destinations\": [\"10.0.0.1\", \"192.0.2.0/24\"],\n \"label\": \"lab\",\n \"schema\": \"packetcraftr.scope/v1\"\n}",
        )
        .unwrap();
        assert_eq!(first.digest(), second.digest());
        let relabeled = parse(
            r#"{"schema":"packetcraftr.scope/v1","label":"other","allowed_destinations":["192.0.2.0/24","10.0.0.1"],"max_packets":10}"#,
        )
        .unwrap();
        assert_ne!(first.digest(), relabeled.digest());
    }

    #[test]
    fn narrowing_never_grants_what_the_policy_denies() {
        let scope = parse(
            r#"{"schema":"packetcraftr.scope/v1","label":"lab","allow_public_destinations":true,"allow_hostname_resolution":true,"allow_permissive_packets":true,"allow_source_spoofing":true,"max_packets":1000000,"max_bytes":1000000}"#,
        )
        .unwrap();
        let narrowed = scope.narrow(&Policy::default());
        assert!(!narrowed.allow_public_destinations);
        assert!(!narrowed.allow_hostname_resolution);
        assert!(!narrowed.allow_permissive_packets);
        assert!(!narrowed.allow_source_spoofing);
        assert_eq!(
            narrowed.max_packets_per_operation,
            Policy::default().max_packets_per_operation
        );
    }
}
