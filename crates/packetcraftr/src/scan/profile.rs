// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Explicit UDP fixture payloads and bounded application response checks.
//! Confirmation means the configured checks matched, not authenticated identity.
use bytes::Bytes;
use packetcraftr_core::{
    decode::DecodedPacket,
    error::{Classification, Classified, Kind},
    field::WireValue,
    packet::{Packet, semantics},
    protocol::{
        application::dns::{Dns, Name, Question},
        transport::Udp,
    },
};
use serde::{Deserialize, Serialize};

pub const MAX_PROFILE_PORTS: usize = 4096;
pub const MAX_PROFILE_BYTES: usize = 1024 * 1024;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Payload {
    Bytes {
        #[serde(with = "hex")]
        data: Bytes,
    },
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
#[derive(Clone, Debug, PartialEq, Eq)]
enum Compiled {
    Bytes(Bytes),
    Dns {
        question: Question,
        recursion: bool,
        id_base: u16,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpProfile {
    config: Config,
    payload: Compiled,
    charge: usize,
}
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid UDP profile: {0}")]
pub struct Error(pub &'static str);
impl Classified for Error {
    fn classification(&self) -> Classification {
        Classification::new("cli.udp_profile", Kind::Cli, None)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    NotObserved,
    Unchecked,
    Confirmed,
    Rejected,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Evidence {
    pub profile: String,
    pub status: Status,
    pub reason: String,
}
impl Evidence {
    pub(crate) fn rank(&self) -> u8 {
        match self.status {
            Status::NotObserved => 0,
            Status::Rejected => 1,
            Status::Unchecked => 2,
            Status::Confirmed => 3,
        }
    }
}
impl Serialize for UdpProfile {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.config.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for UdpProfile {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(Config::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}
impl UdpProfile {
    pub fn new(config: Config) -> Result<Self, Error> {
        // Counted in characters, as the published schema's maxLength counts.
        if config.name.is_empty()
            || config.name.chars().count() > 128
            || config.name.chars().any(char::is_control)
        {
            return Err(Error("name must contain 1..=128 non-control characters"));
        }
        let payload = match &config.request {
            Payload::Bytes { data } => {
                if data.len() > super::MAX_UDP_PAYLOAD_BYTES {
                    return Err(Error("payload exceeds UDP wire limit"));
                }
                Compiled::Bytes(data.clone())
            }
            Payload::Dns {
                name,
                query_type,
                class,
                recursion_desired,
                id_base,
            } => Compiled::Dns {
                question: Question {
                    name: name
                        .parse::<Name>()
                        .map_err(|_| Error("invalid DNS question name"))?,
                    query_type: *query_type,
                    class: *class,
                },
                recursion: *recursion_desired,
                id_base: *id_base,
            },
        };
        let mut charge = config.name.len() + 512;
        match &config.request {
            Payload::Bytes { data } => charge += data.len(),
            Payload::Dns { name, .. } => charge += name.len() * 32,
        }
        if let ResponseCheck::Bytes {
            checks,
            min_length,
            max_length,
        } = &config.response
        {
            if checks.is_empty()
                || checks.len() > 64
                || min_length > max_length
                || *max_length > 65_535
            {
                return Err(Error(
                    "byte validation requires 1..=64 checks and lengths within 0..=65535",
                ));
            }
            for check in checks {
                if check.data.is_empty()
                    || check.data.len() > 1024
                    || check
                        .offset
                        .checked_add(check.data.len())
                        .is_none_or(|end| end > *max_length)
                    || check
                        .mask
                        .as_ref()
                        .is_some_and(|mask| mask.len() != check.data.len())
                {
                    return Err(Error(
                        "byte check exceeds its offset, pattern, or mask bounds",
                    ));
                }
                charge += 128 + check.data.len() + check.mask.as_ref().map_or(0, Bytes::len);
            }
        }
        if charge > MAX_PROFILE_BYTES {
            return Err(Error("profile storage exceeds 1 MiB"));
        }
        let profile = Self {
            config,
            payload,
            charge,
        };
        if matches!(profile.config.response, ResponseCheck::Dns) {
            let query = Dns::try_from(profile.payload(0))
                .map_err(|_| Error("DNS response validation needs a valid DNS request"))?;
            if query.response || query.questions.is_empty() {
                return Err(Error(
                    "DNS response validation needs a query with questions",
                ));
            }
        }
        Ok(profile)
    }
    pub(crate) fn raw_payload(&self) -> bool {
        matches!(self.payload, Compiled::Bytes(_))
    }
    pub fn name(&self) -> &str {
        &self.config.name
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn storage_bytes(&self) -> usize {
        self.charge
    }
    pub fn payload(&self, sequence: u64) -> Bytes {
        match &self.payload {
            Compiled::Bytes(data) => data.clone(),
            Compiled::Dns {
                question,
                recursion,
                id_base,
            } => {
                let mut query = Dns::default();
                query.id = id_base.wrapping_add(sequence as u16);
                query.recursion_desired = *recursion;
                query.questions.push(question.clone());
                // A validated Name is at most 255 wire bytes. One question and
                // a fixed DNS header fit the encoder's 65535-byte ceiling.
                query
                    .to_wire()
                    .expect("validated single DNS question fits its wire bounds")
            }
        }
    }
    pub fn payload_length(&self) -> usize {
        match &self.payload {
            Compiled::Bytes(data) => data.len(),
            Compiled::Dns { question, .. } => {
                17 + question
                    .name
                    .labels()
                    .iter()
                    .map(|label| label.len() + 1)
                    .sum::<usize>()
            }
        }
    }
    pub fn not_observed(&self) -> Evidence {
        self.evidence(Status::NotObserved, "no UDP application reply was observed")
    }
    fn evidence(&self, status: Status, reason: impl Into<String>) -> Evidence {
        Evidence {
            profile: self.config.name.clone(),
            status,
            reason: reason.into(),
        }
    }
    pub fn evaluate(&self, query: &[u8], response: &[u8]) -> Evidence {
        match &self.config.response {
            ResponseCheck::Any => self.evidence(
                Status::Unchecked,
                "UDP reply observed; no application checks configured",
            ),
            ResponseCheck::Dns => {
                let (Ok(query), Ok(response)) = (
                    Dns::try_from(Bytes::copy_from_slice(query)),
                    Dns::try_from(Bytes::copy_from_slice(response)),
                ) else {
                    return self.evidence(
                        Status::Rejected,
                        "DNS response could not be validated within decoder bounds",
                    );
                };
                if !query.response
                    && response.response
                    && response.id == query.id
                    && response.opcode == query.opcode
                    && response.questions == query.questions
                {
                    self.evidence(
                        Status::Confirmed,
                        "DNS response ID, opcode, and questions match the request",
                    )
                } else {
                    self.evidence(
                        Status::Rejected,
                        "DNS response flag, ID, opcode, or questions do not match",
                    )
                }
            }
            ResponseCheck::Bytes {
                checks,
                min_length,
                max_length,
            } => {
                if response.len() < *min_length || response.len() > *max_length {
                    return self.evidence(
                        Status::Rejected,
                        "response length is outside configured bounds",
                    );
                }
                for check in checks {
                    let Some(actual) = response.get(check.offset..check.offset + check.data.len())
                    else {
                        return self.evidence(
                            Status::Rejected,
                            format!("response does not reach byte offset {}", check.offset),
                        );
                    };
                    if actual.iter().zip(&check.data).enumerate().any(
                        |(index, (actual, expected))| {
                            let mask = check.mask.as_ref().map_or(255, |mask| mask[index]);
                            actual & mask != expected & mask
                        },
                    ) {
                        return self.evidence(
                            Status::Rejected,
                            format!("byte check at offset {} did not match", check.offset),
                        );
                    }
                }
                self.evidence(Status::Confirmed, "configured response byte checks matched")
            }
        }
    }
}
/// Application payload is considered only after exact outer IP/UDP reversal.
pub(crate) fn evidence(
    probe: &super::Probe,
    request: &Packet,
    response: &DecodedPacket,
) -> Option<Evidence> {
    let profile = probe.udp_profile.as_ref()?;
    let Some(payload) = udp_payload(request, response) else {
        return Some(profile.not_observed());
    };
    Some(profile.evaluate(&probe.udp_payload, &payload))
}
fn udp_payload(request: &Packet, response: &DecodedPacket) -> Option<Bytes> {
    let sent = semantics::outer_ip_path(request).ok()??;
    let received = semantics::outer_ip_path(&response.packet).ok()??;
    if sent.source != received.final_destination || sent.final_destination != received.source {
        return None;
    }
    let sent_udp =
        semantics::outer_layers(request).find_map(|layer| layer.downcast_ref::<Udp>())?;
    let (index, udp) = response
        .packet
        .iter()
        .take(semantics::outer_scope_len(&response.packet))
        .enumerate()
        .find_map(|(index, layer)| layer.downcast_ref::<Udp>().map(|udp| (index, udp)))?;
    if sent_udp.source_port != udp.destination_port || sent_udp.destination_port != udp.source_port
    {
        return None;
    }
    let WireValue::Exact(length) = udp.length else {
        return None;
    };
    if length < 8 {
        return None;
    }
    let start = response.layout.layer(index)?.range.end;
    let end = start.checked_add(usize::from(length) - 8)?;
    (end <= response.original.len()).then(|| response.original.slice(start..end))
}
mod hex {
    use super::*;
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
        if value.len() > super::super::MAX_UDP_PAYLOAD_BYTES * 2
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
    use super::*;
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

    fn named(name: String) -> Result<UdpProfile, Error> {
        UdpProfile::new(Config {
            name,
            request: Payload::Bytes {
                data: Bytes::from_static(b"probe"),
            },
            response: ResponseCheck::Any,
        })
    }

    #[test]
    fn profile_names_are_bounded_in_characters_as_the_schema_counts() {
        assert!(named("\u{e9}".repeat(128)).is_ok());
        assert!(named("\u{e9}".repeat(129)).is_err());
        assert!(named(String::new()).is_err());
        assert!(named("tab\tname".to_owned()).is_err());
    }
}
