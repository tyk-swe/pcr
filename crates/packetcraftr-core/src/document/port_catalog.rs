// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Versioned port catalogs: port-name hints and named selections of them.
//!
//! A catalog name is a hint attached to a port number, never service
//! identification. Presets are curated lists and make no frequency claim.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::{Classification, Classified, Kind, Source};

pub const PORT_CATALOG_SCHEMA_V1: &str = "packetcraftr.port-catalog/v1";
pub const MAX_CATALOG_BYTES: usize = 256 * 1024;
pub const MAX_CATALOG_ENTRIES: usize = 2048;
pub const MAX_CATALOG_PRESETS: usize = 32;
pub const MAX_NAME_BYTES: usize = 32;
pub const MAX_TEXT_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// One port-name hint and the standard or document it is cited from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub transport: Transport,
    pub port: u16,
    pub name: String,
    pub reference: String,
}

/// A named selection of catalog entries, listed by entry name per transport.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preset {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub tcp: Vec<String>,
    #[serde(default)]
    pub udp: Vec<String>,
}

impl Preset {
    pub fn members(&self) -> impl Iterator<Item = (Transport, &str)> {
        let tcp = self.tcp.iter().map(|name| (Transport::Tcp, name.as_str()));
        let udp = self.udp.iter().map(|name| (Transport::Udp, name.as_str()));
        tcp.chain(udp)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub schema: String,
    pub name: String,
    pub version: String,
    pub entries: Vec<Entry>,
    #[serde(default)]
    pub presets: Vec<Preset>,
}

impl Catalog {
    pub fn entry(&self, transport: Transport, port: u16) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|entry| entry.transport == transport && entry.port == port)
    }

    pub fn named(&self, transport: Transport, name: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|entry| entry.transport == transport && entry.name == name)
    }

    pub fn preset(&self, name: &str) -> Option<&Preset> {
        self.presets.iter().find(|preset| preset.name == name)
    }
}

/// Parses and validates a catalog; every preset member names an entry.
pub fn parse(document: &[u8]) -> Result<Catalog, Error> {
    if document.len() > MAX_CATALOG_BYTES {
        return Err(Error::DocumentSize {
            actual: document.len(),
            limit: MAX_CATALOG_BYTES,
        });
    }
    let catalog: Catalog =
        serde_json::from_slice(document).map_err(|source| Error::Syntax(Source::new(source)))?;
    validate(&catalog)?;
    Ok(catalog)
}

fn validate(catalog: &Catalog) -> Result<(), Error> {
    if catalog.schema != PORT_CATALOG_SCHEMA_V1 {
        return Err(Error::Schema {
            schema: catalog.schema.clone(),
        });
    }
    check_name("catalog name", &catalog.name)?;
    check_text("catalog version", &catalog.version)?;
    if catalog.entries.is_empty() || catalog.entries.len() > MAX_CATALOG_ENTRIES {
        return Err(Error::Count {
            field: "entries",
            count: catalog.entries.len(),
            limit: MAX_CATALOG_ENTRIES,
        });
    }
    if catalog.presets.len() > MAX_CATALOG_PRESETS {
        return Err(Error::Count {
            field: "presets",
            count: catalog.presets.len(),
            limit: MAX_CATALOG_PRESETS,
        });
    }
    let mut ports = BTreeSet::new();
    let mut names = BTreeSet::new();
    for entry in &catalog.entries {
        check_name("entry name", &entry.name)?;
        check_text("entry reference", &entry.reference)?;
        if entry.port == 0 {
            return Err(Error::Invalid {
                field: "entry port",
                value: entry.name.clone(),
                reason: "port 0 is not a destination port",
            });
        }
        if !ports.insert((entry.transport, entry.port)) {
            return Err(duplicate(
                "entry port",
                entry.transport,
                &entry.port.to_string(),
            ));
        }
        if !names.insert((entry.transport, entry.name.as_str())) {
            return Err(duplicate("entry name", entry.transport, &entry.name));
        }
    }
    let mut presets = BTreeSet::new();
    for preset in &catalog.presets {
        check_name("preset name", &preset.name)?;
        check_text("preset description", &preset.description)?;
        if !presets.insert(preset.name.as_str()) {
            return Err(Error::Invalid {
                field: "preset name",
                value: preset.name.clone(),
                reason: "is declared more than once",
            });
        }
        let mut members = BTreeSet::new();
        for (transport, name) in preset.members() {
            if !names.contains(&(transport, name)) {
                return Err(Error::Invalid {
                    field: "preset member",
                    value: format!("{}/{name}", transport.as_str()),
                    reason: "names no catalog entry",
                });
            }
            if !members.insert((transport, name)) {
                return Err(duplicate("preset member", transport, name));
            }
        }
        if members.is_empty() {
            return Err(Error::Invalid {
                field: "preset",
                value: preset.name.clone(),
                reason: "selects no entries",
            });
        }
    }
    Ok(())
}

/// Names start with a lowercase letter so they never read as port numbers.
fn check_name(field: &'static str, value: &str) -> Result<(), Error> {
    let mut bytes = value.bytes();
    let valid = value.len() <= MAX_NAME_BYTES
        && bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if valid {
        Ok(())
    } else {
        Err(Error::Invalid {
            field,
            value: value.chars().take(MAX_NAME_BYTES).collect(),
            reason: "expected 1 to 32 lowercase letters, digits, or hyphens starting with a letter",
        })
    }
}

fn check_text(field: &'static str, value: &str) -> Result<(), Error> {
    if !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && value.chars().all(|character| !character.is_control())
    {
        Ok(())
    } else {
        Err(Error::Invalid {
            field,
            value: value.chars().take(MAX_NAME_BYTES).collect(),
            reason: "expected 1 to 256 bytes of text without control characters",
        })
    }
}

fn duplicate(field: &'static str, transport: Transport, value: &str) -> Error {
    Error::Invalid {
        field,
        value: format!("{}/{value}", transport.as_str()),
        reason: "is declared more than once",
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("port catalog has {actual} bytes, exceeding limit {limit}")]
    DocumentSize { actual: usize, limit: usize },
    #[error("invalid port catalog")]
    Syntax(#[source] Source),
    #[error("unsupported port catalog schema {schema}; expected {PORT_CATALOG_SCHEMA_V1}")]
    Schema { schema: String },
    #[error("port catalog holds {count} {field}; expected at most {limit}")]
    Count {
        field: &'static str,
        count: usize,
        limit: usize,
    },
    #[error("port catalog {field} {value:?} {reason}")]
    Invalid {
        field: &'static str,
        value: String,
        reason: &'static str,
    },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        Classification::new("cli.error", Kind::Usage, None)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn document() -> Value {
        json!({
            "schema": PORT_CATALOG_SCHEMA_V1,
            "name": "fixture",
            "version": "1",
            "entries": [
                {"transport": "tcp", "port": 22, "name": "ssh", "reference": "RFC 4253"},
                {"transport": "udp", "port": 53, "name": "domain", "reference": "RFC 1035"},
                {"transport": "tcp", "port": 53, "name": "domain", "reference": "RFC 7766"}
            ],
            "presets": [{"name": "small", "description": "fixture", "tcp": ["ssh"], "udp": ["domain"]}]
        })
    }

    fn parsed(value: &Value) -> Result<Catalog, Error> {
        parse(&serde_json::to_vec(value).expect("serializes"))
    }

    #[test]
    fn lookups_keep_transports_apart() {
        let catalog = parsed(&document()).expect("valid catalog");
        assert_eq!(
            catalog.entry(Transport::Udp, 53).expect("udp").reference,
            "RFC 1035"
        );
        assert_eq!(
            catalog.named(Transport::Tcp, "domain").expect("tcp").port,
            53
        );
        assert!(catalog.named(Transport::Udp, "ssh").is_none());
        let members: Vec<_> = catalog.preset("small").expect("preset").members().collect();
        assert_eq!(
            members,
            [(Transport::Tcp, "ssh"), (Transport::Udp, "domain")]
        );
    }

    #[test]
    fn invalid_catalogs_are_rejected_with_the_offending_field() {
        type Mutation = fn(&mut Value);
        let cases: [(&str, Mutation); 8] = [
            ("schema", |value| {
                value["schema"] = json!("packetcraftr.port-catalog/v0");
            }),
            ("entry port", |value| value["entries"][0]["port"] = json!(0)),
            ("entry port", |value| {
                value["entries"][2]["port"] = json!(22);
            }),
            ("entry name", |value| {
                value["entries"][2]["name"] = json!("ssh");
            }),
            ("entry name", |value| {
                value["entries"][0]["name"] = json!("8080");
            }),
            ("preset member", |value| {
                value["presets"][0]["udp"] = json!(["ssh"]);
            }),
            ("preset member", |value| {
                value["presets"][0]["tcp"] = json!(["ssh", "ssh"]);
            }),
            ("preset", |value| {
                value["presets"][0] = json!({"name": "none", "description": "x"});
            }),
        ];
        for (field, mutate) in cases {
            let mut value = document();
            mutate(&mut value);
            let error = parsed(&value).expect_err(field);
            if field == "schema" {
                assert!(matches!(error, Error::Schema { .. }), "{error}");
            } else {
                assert!(error.to_string().contains(field), "{field}: {error}");
            }
        }
        let mut oversized = document();
        oversized["entries"] = json!(vec![
            document()["entries"][0].clone();
            MAX_CATALOG_ENTRIES + 1
        ]);
        assert!(matches!(
            parsed(&oversized),
            Err(Error::Count {
                field: "entries",
                ..
            })
        ));
        assert!(matches!(
            parse(&vec![b' '; MAX_CATALOG_BYTES + 1]),
            Err(Error::DocumentSize { .. })
        ));
    }
}
