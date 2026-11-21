// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::model::{DestinationConstraint, Error, MAX_DESTINATION_CONSTRAINTS, Policy, Window};

pub const SCHEMA: &str = "packetcraftr.scope/v1";
pub const SCHEMA_V2: &str = "packetcraftr.scope/v2";
pub const MAX_SCOPE_DOCUMENT_BYTES: usize = 1024 * 1024;
const MAX_LABEL_CHARS: usize = 128;

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
    #[serde(default)]
    not_before_unix_seconds: Option<u64>,
    #[serde(default)]
    not_after_unix_seconds: Option<u64>,
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
    pub window: Option<Window>,
}

fn parse_window(raw: &RawScope) -> Result<Option<Window>, Error> {
    let window = Window {
        not_before_unix_seconds: raw.not_before_unix_seconds,
        not_after_unix_seconds: raw.not_after_unix_seconds,
    };
    let declared =
        window.not_before_unix_seconds.is_some() || window.not_after_unix_seconds.is_some();
    if raw.schema == SCHEMA {
        if declared {
            return Err(invalid(
                "window bounds require schema packetcraftr.scope/v2".to_owned(),
            ));
        }
        return Ok(None);
    }
    if !declared {
        return Err(invalid(
            "packetcraftr.scope/v2 requires not_before_unix_seconds or not_after_unix_seconds"
                .to_owned(),
        ));
    }
    if let (Some(start), Some(end)) = (
        window.not_before_unix_seconds,
        window.not_after_unix_seconds,
    ) && start >= end
    {
        return Err(invalid(format!(
            "scope window start {start} must be before its end {end}"
        )));
    }
    Ok(Some(window))
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
        if raw.schema != SCHEMA && raw.schema != SCHEMA_V2 {
            return Err(invalid(format!(
                "expected schema {SCHEMA:?} or {SCHEMA_V2:?}, got {:?}",
                raw.schema
            )));
        }
        let window = parse_window(&raw)?;
        if raw.label.trim().is_empty()
            || raw.label.chars().count() > MAX_LABEL_CHARS
            || raw.label.chars().any(char::is_control)
        {
            return Err(invalid(
                "scope label must be printable and 1..=128 characters".to_owned(),
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
            window,
        })
    }

    #[must_use]
    pub fn digest(&self) -> String {
        let allowed = sorted(&self.allowed_destinations);
        let denied = sorted(&self.denied_destinations);
        let body = format!(
            "label={}\nallowed={}\ndenied={}\npublic={}\nhostname={}\npermissive={}\nspoofing={}\nmax_packets={}\nmax_bytes={}\n",
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
        let canonical = match self.window {
            None => format!("packetcraftr.scope/v1\n{body}"),
            Some(window) => format!(
                "packetcraftr.scope/v2\n{body}not_before={}\nnot_after={}\n",
                window
                    .not_before_unix_seconds
                    .map_or_else(|| "-".to_owned(), |value| value.to_string()),
                window
                    .not_after_unix_seconds
                    .map_or_else(|| "-".to_owned(), |value| value.to_string()),
            ),
        };
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
        if let Some(window) = self.window {
            narrowed.window = Some(match narrowed.window {
                Some(existing) => existing.intersect(window),
                None => window,
            });
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
            r#"{"schema":"packetcraftr.scope/v3","label":"lab"}"#,
            r#"{"schema":"packetcraftr.scope/v1","label":"lab","extra":true}"#,
            r#"{"schema":"packetcraftr.scope/v1","label":"  "}"#,
            r#"{"schema":"packetcraftr.scope/v1","label":"lab","allowed_destinations":["example.test"]}"#,
            r#"{"schema":"packetcraftr.scope/v1","label":"lab","allowed_destinations":["192.0.2.1/24"]}"#,
        ] {
            assert!(parse(document).is_err(), "{document}");
        }
    }

    #[test]
    fn label_limit_counts_characters_like_the_schema() {
        let fits = "é".repeat(MAX_LABEL_CHARS);
        assert!(
            parse(&format!(
                "{{\"schema\":\"packetcraftr.scope/v1\",\"label\":\"{fits}\"}}"
            ))
            .is_ok()
        );
        let too_long = "é".repeat(MAX_LABEL_CHARS + 1);
        assert!(
            parse(&format!(
                "{{\"schema\":\"packetcraftr.scope/v1\",\"label\":\"{too_long}\"}}"
            ))
            .is_err()
        );
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
        let narrower = parse(
            r#"{"schema":"packetcraftr.scope/v1","label":"lab","allowed_destinations":["192.0.2.0/24"],"max_packets":10}"#,
        )
        .unwrap();
        assert_ne!(first.digest(), narrower.digest());
    }

    #[test]
    fn document_and_destination_limits_are_inclusive() {
        let minimal = r#"{"schema":"packetcraftr.scope/v1","label":"lab"}"#;
        let padded = |len: usize| minimal.to_owned() + &" ".repeat(len - minimal.len());
        assert!(parse(&padded(MAX_SCOPE_DOCUMENT_BYTES)).is_ok());
        assert!(matches!(
            parse(&padded(MAX_SCOPE_DOCUMENT_BYTES + 1)),
            Err(Error::InvalidScopeDocument { .. })
        ));

        for field in ["allowed_destinations", "denied_destinations"] {
            let with = |count: usize| {
                let destinations = vec![r#""192.0.2.1""#; count].join(",");
                parse(&format!(
                    r#"{{"schema":"packetcraftr.scope/v1","label":"lab","{field}":[{destinations}]}}"#
                ))
            };
            assert!(with(MAX_DESTINATION_CONSTRAINTS).is_ok(), "{field}");
            assert!(
                matches!(
                    with(MAX_DESTINATION_CONSTRAINTS + 1),
                    Err(Error::InvalidScopeDocument { .. })
                ),
                "{field}"
            );
        }
    }

    #[test]
    fn window_bounds_require_v2_and_a_nonempty_interval() {
        for document in [
            r#"{"schema":"packetcraftr.scope/v1","label":"lab","not_before_unix_seconds":10}"#,
            r#"{"schema":"packetcraftr.scope/v1","label":"lab","not_after_unix_seconds":20}"#,
            r#"{"schema":"packetcraftr.scope/v2","label":"lab"}"#,
            r#"{"schema":"packetcraftr.scope/v2","label":"lab","not_before_unix_seconds":20,"not_after_unix_seconds":20}"#,
            r#"{"schema":"packetcraftr.scope/v2","label":"lab","not_before_unix_seconds":21,"not_after_unix_seconds":20}"#,
        ] {
            assert!(
                matches!(parse(document), Err(Error::InvalidScopeDocument { .. })),
                "{document}"
            );
        }
        for document in [
            r#"{"schema":"packetcraftr.scope/v2","label":"lab","not_before_unix_seconds":10}"#,
            r#"{"schema":"packetcraftr.scope/v2","label":"lab","not_after_unix_seconds":20}"#,
            r#"{"schema":"packetcraftr.scope/v2","label":"lab","not_before_unix_seconds":10,"not_after_unix_seconds":11}"#,
        ] {
            let scope = parse(document).unwrap();
            assert!(scope.window.is_some(), "{document}");
        }
    }

    #[test]
    fn v1_digest_keeps_its_original_canonical_form() {
        let scope = parse(
            r#"{"schema":"packetcraftr.scope/v1","label":"lab","allowed_destinations":["192.0.2.0/24","10.0.0.1"],"max_packets":10}"#,
        )
        .unwrap();
        let canonical = "packetcraftr.scope/v1\nlabel=lab\nallowed=10.0.0.1,192.0.2.0/24\ndenied=\npublic=false\nhostname=false\npermissive=false\nspoofing=false\nmax_packets=10\nmax_bytes=-\n";
        let expected =
            packetcraftr_core::field::hex::compact_hex(&Sha256::digest(canonical.as_bytes()));
        assert_eq!(scope.digest(), expected);

        let windowed = parse(
            r#"{"schema":"packetcraftr.scope/v2","label":"lab","allowed_destinations":["192.0.2.0/24","10.0.0.1"],"max_packets":10,"not_before_unix_seconds":100,"not_after_unix_seconds":200}"#,
        )
        .unwrap();
        assert_ne!(windowed.digest(), expected);
        let later_end = parse(
            r#"{"schema":"packetcraftr.scope/v2","label":"lab","allowed_destinations":["192.0.2.0/24","10.0.0.1"],"max_packets":10,"not_before_unix_seconds":100,"not_after_unix_seconds":201}"#,
        )
        .unwrap();
        assert_ne!(windowed.digest(), later_end.digest());
    }

    #[test]
    fn narrowing_intersects_windows_and_disjoint_windows_deny_everything() {
        let scope = parse(
            r#"{"schema":"packetcraftr.scope/v2","label":"lab","not_before_unix_seconds":100,"not_after_unix_seconds":300}"#,
        )
        .unwrap();
        assert_eq!(
            scope.narrow(&Policy::default()).window,
            Some(Window {
                not_before_unix_seconds: Some(100),
                not_after_unix_seconds: Some(300),
            })
        );
        let policy = Policy {
            window: Some(Window {
                not_before_unix_seconds: Some(200),
                not_after_unix_seconds: Some(400),
            }),
            ..Policy::default()
        };
        assert_eq!(
            scope.narrow(&policy).window,
            Some(Window {
                not_before_unix_seconds: Some(200),
                not_after_unix_seconds: Some(300),
            })
        );
        let disjoint = Policy {
            window: Some(Window {
                not_before_unix_seconds: Some(400),
                not_after_unix_seconds: Some(500),
            }),
            ..Policy::default()
        };
        let empty = scope.narrow(&disjoint).window.unwrap();
        for instant in [0, 100, 250, 400, 499, u64::MAX] {
            assert!(!empty.contains_at(instant), "{instant}");
        }
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
