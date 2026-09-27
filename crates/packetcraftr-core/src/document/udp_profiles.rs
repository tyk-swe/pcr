// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{Classification, Classified, Kind, Source};

pub const UDP_PROFILES_SCHEMA_V1: &str = "packetcraftr.udp-profiles/v1";
pub const MAX_PROFILE_ASSIGNMENTS: usize = 256;
pub const MAX_PROFILE_PORTS: usize = 4096;
pub const MAX_PROFILE_BYTES: usize = 1024 * 1024;
/// The most bytes a request payload or byte check decodes to: the largest IPv4 UDP payload.
pub const MAX_PAYLOAD_BYTES: usize = 65_507;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Payload {
    Bytes {
        #[serde(with = "hex")]
        data: Bytes,
    },
    /// One DNS question; each probe's transaction ID advances from `id_base`.
    Dns {
        name: String,
        #[serde(default = "one")]
        query_type: u16,
        #[serde(default = "one")]
        class: u16,
        #[serde(default = "yes")]
        recursion_desired: bool,
        #[serde(default)]
        id_base: u16,
    },
}

fn one() -> u16 {
    1
}

fn yes() -> bool {
    true
}

fn maximum_response() -> usize {
    65_535
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ByteCheck {
    pub offset: usize,
    #[serde(with = "hex")]
    pub data: Bytes,
    #[serde(default, with = "optional_hex")]
    pub mask: Option<Bytes>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseCheck {
    Any,
    Dns,
    Bytes {
        checks: Vec<ByteCheck>,
        #[serde(default)]
        min_length: usize,
        #[serde(default = "maximum_response")]
        max_length: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub name: String,
    pub request: Payload,
    pub response: ResponseCheck,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    pub ports: Vec<u16>,
    pub profile: Config,
}

// serde names this type in published syntax messages, so the name stays as it was.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema: String,
    profiles: Vec<Assignment>,
}

pub fn parse(document: &[u8]) -> Result<Vec<Assignment>, Error> {
    if document.len() > MAX_PROFILE_BYTES {
        return Err(Error::DocumentSize {
            actual: document.len(),
            limit: MAX_PROFILE_BYTES,
        });
    }
    let document: Document =
        serde_json::from_slice(document).map_err(|source| Error::Syntax(Source::new(source)))?;
    if document.schema != UDP_PROFILES_SCHEMA_V1 {
        return Err(Error::Schema {
            schema: document.schema,
        });
    }
    if document.profiles.is_empty() || document.profiles.len() > MAX_PROFILE_ASSIGNMENTS {
        return Err(Error::AssignmentCount {
            count: document.profiles.len(),
        });
    }
    Ok(document.profiles)
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("UDP profiles document has {actual} bytes, exceeding limit {limit}")]
    DocumentSize { actual: usize, limit: usize },
    #[error("invalid UDP profiles")]
    Syntax(#[source] Source),
    #[error("unsupported UDP profiles schema {schema}; expected {UDP_PROFILES_SCHEMA_V1}")]
    Schema { schema: String },
    #[error("UDP profiles hold {count} assignments; expected 1 to {MAX_PROFILE_ASSIGNMENTS}")]
    AssignmentCount { count: usize },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        Classification::new("cli.error", Kind::Usage, None)
    }
}

mod hex {
    use super::{Bytes, Deserialize, MAX_PAYLOAD_BYTES};

    pub(super) fn serialize<S: serde::Serializer>(
        value: &Bytes,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        use std::fmt::Write;
        let mut text = String::with_capacity(value.len() * 2);
        for byte in value {
            write!(text, "{byte:02x}").expect("string write");
        }
        serializer.serialize_str(&text)
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Bytes, D::Error> {
        let value = String::deserialize(deserializer)?;
        decode(&value).map_err(serde::de::Error::custom)
    }

    pub(super) fn decode(value: &str) -> Result<Bytes, &'static str> {
        if value.len() > MAX_PAYLOAD_BYTES * 2
            || !value.len().is_multiple_of(2)
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("expected bounded even-length hexadecimal bytes");
        }
        Ok((0..value.len())
            .step_by(2)
            .map(|index| {
                u8::from_str_radix(&value[index..index + 2], 16).expect("validated hexadecimal")
            })
            .collect::<Vec<_>>()
            .into())
    }
}

mod optional_hex {
    use super::{Bytes, Deserialize, hex};

    pub(super) fn serialize<S: serde::Serializer>(
        value: &Option<Bytes>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => hex::serialize(value, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Bytes>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|value| hex::decode(&value).map_err(serde::de::Error::custom))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hexadecimal_payloads_round_trip_and_stay_bounded() {
        let config: Config = serde_json::from_value(serde_json::json!({
            "name": "fixture",
            "request": {"type": "bytes", "data": "00ffA0"},
            "response": {"type": "bytes", "checks": [{"offset": 1, "data": "a0", "mask": "f0"}]}
        }))
        .expect("valid profile");
        let Payload::Bytes { data } = &config.request else {
            panic!("bytes payload");
        };
        assert_eq!(data.as_ref(), [0x00, 0xff, 0xa0]);
        assert_eq!(
            serde_json::to_value(&config).expect("serializes")["request"]["data"],
            "00ffa0"
        );
        for invalid in ["0", "zz", &"00".repeat(MAX_PAYLOAD_BYTES + 1)] {
            assert!(hex::decode(invalid).is_err(), "{}", invalid.len());
        }
    }
}
