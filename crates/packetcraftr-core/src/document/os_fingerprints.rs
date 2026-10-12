// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Original, bounded OS-family signatures over stable packet observations.
//!
//! Matching qualifies a stack fingerprint; it does not authenticate an OS.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::{Classification, Classified, Kind};

mod matching;
mod observation;
#[cfg(test)]
mod tests;

pub use matching::{Candidate, Confidence, Match, Outcome, evaluate};
pub use observation::{Observation, TcpFingerprint, extract};

pub const SCHEMA_V1: &str = "packetcraftr.os-fingerprints/v1";
pub const PROBE_SET_V1: &str = "packetcraftr.os-probes/v1";
pub const MAX_DOCUMENT_BYTES: usize = 512 * 1024;
pub const MAX_SIGNATURES: usize = 512;
pub const MAX_PREDICATES: usize = 64;
pub const MAX_OBSERVATIONS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Probe {
    OpenSyn,
    ClosedSyn,
    TimestampSyn,
    Echo,
}

impl Probe {
    pub const REQUIRED: [Self; 3] = [Self::OpenSyn, Self::ClosedSyn, Self::TimestampSyn];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    Linux,
    Windows,
    Macos,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

/// Only stable fields can be signature predicates. Dynamic observations are
/// deliberately absent from this interface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "field",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Test {
    Flags(u16),
    Window(u16),
    OptionKinds(Vec<u8>),
    Mss(u16),
    WindowScale(u8),
    SackPermitted(bool),
    Timestamps(bool),
    IcmpType(u8),
    IcmpCode(u8),
}

impl Test {
    pub const fn field(&self) -> &'static str {
        match self {
            Self::Flags(_) => "flags",
            Self::Window(_) => "window",
            Self::OptionKinds(_) => "option_kinds",
            Self::Mss(_) => "mss",
            Self::WindowScale(_) => "window_scale",
            Self::SackPermitted(_) => "sack_permitted",
            Self::Timestamps(_) => "timestamps",
            Self::IcmpType(_) => "icmp_type",
            Self::IcmpCode(_) => "icmp_code",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Predicate {
    pub probe: Probe,
    pub test: Test,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub id: String,
    pub family: Family,
    pub address_family: AddressFamily,
    /// A bounded reference to the independently labeled training capture.
    pub reference: String,
    pub predicates: Vec<Predicate>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Corpus {
    pub schema: String,
    pub probe_set: String,
    pub name: String,
    pub version: String,
    pub maintainer: String,
    pub signatures: Vec<Signature>,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid OS fingerprint document: {0}")]
    Invalid(String),
    #[error("invalid OS fingerprint JSON")]
    Syntax(#[source] serde_json::Error),
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        Classification::new("document.os_fingerprints", Kind::Usage, None)
    }
}

fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid(message.into())
}

fn text(value: &str, maximum: usize) -> Result<(), Error> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(invalid("empty, oversized, or control-containing text"));
    }
    Ok(())
}

impl Corpus {
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema != SCHEMA_V1 || self.probe_set != PROBE_SET_V1 {
            return Err(invalid("unsupported schema or probe set"));
        }
        for value in [&self.name, &self.version, &self.maintainer] {
            text(value, 128)?;
        }
        if self.signatures.len() > MAX_SIGNATURES {
            return Err(invalid("more than 512 signatures"));
        }
        let mut ids = BTreeSet::new();
        for signature in &self.signatures {
            text(&signature.id, 128)?;
            text(&signature.reference, 1024)?;
            if !ids.insert(&signature.id) {
                return Err(invalid("duplicate signature identifier"));
            }
            if signature.predicates.len() > MAX_PREDICATES {
                return Err(invalid("more than 64 predicates per signature"));
            }
            let mut fields = BTreeSet::new();
            for predicate in &signature.predicates {
                if !fields.insert((predicate.probe, predicate.test.field())) {
                    return Err(invalid("duplicate probe field predicate"));
                }
                let icmp = matches!(predicate.test, Test::IcmpType(_) | Test::IcmpCode(_));
                if icmp != (predicate.probe == Probe::Echo) {
                    return Err(invalid("predicate field does not belong to its probe"));
                }
                match &predicate.test {
                    Test::OptionKinds(kinds) if kinds.len() > 40 => {
                        return Err(invalid("more than 40 TCP option kinds"));
                    }
                    Test::WindowScale(value) if *value > 14 => {
                        return Err(invalid("TCP window scale exceeds 14"));
                    }
                    _ => {}
                }
            }
            for probe in Probe::REQUIRED {
                let flags = if probe == Probe::ClosedSyn {
                    0x14
                } else {
                    0x12
                };
                if !signature.predicates.iter().any(|predicate| {
                    predicate.probe == probe && predicate.test == Test::Flags(flags)
                }) || fields.iter().filter(|(kind, _)| *kind == probe).count() < 2
                {
                    return Err(invalid(
                        "each required TCP probe needs its expected flags and another stable field",
                    ));
                }
            }
        }
        // In-memory documents obey the same byte bound as parsed documents.
        if serde_json::to_vec(self).map_err(Error::Syntax)?.len() > MAX_DOCUMENT_BYTES {
            return Err(invalid("document exceeds 512 KiB"));
        }
        Ok(())
    }
}

pub fn parse(document: &[u8]) -> Result<Corpus, Error> {
    if document.len() > MAX_DOCUMENT_BYTES {
        return Err(invalid("document exceeds 512 KiB"));
    }
    let corpus: Corpus = serde_json::from_slice(document).map_err(Error::Syntax)?;
    corpus.validate()?;
    Ok(corpus)
}
