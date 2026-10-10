// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, reproducible service observations and matching without native I/O.
//!
//! Product and version fields are unauthenticated claims. Matching a claim
//! never authenticates an endpoint or makes a vulnerability assertion.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub use super::port_catalog::Transport;
use super::udp_profiles::Payload;
use crate::{
    error::{Classification, Classified, Kind, Source},
    protocol::application::dns::{Dns, Name, Question},
};

mod matching;
mod observation;

pub use observation::{observe, ssh_collection_complete};

pub const SERVICE_PROBES_SCHEMA_V1: &str = "packetcraftr.service-probes/v1";
pub const MAX_DOCUMENT_BYTES: usize = 512 * 1024;
pub const MAX_PROBES: usize = 64;
pub const MAX_MATCHES: usize = 512;
pub const MAX_RESPONSE_BYTES: usize = 65_535;
pub const MAX_FIELD_BYTES: usize = 1024;
pub const MAX_OBSERVED_FIELDS: usize = 512;
pub const MAX_CANDIDATES: usize = 512;
pub const MAX_INTENSITY: u8 = 9;
/// Unicode scalar-value limit corresponding to the schemas' `maxLength`.
pub const MAX_TEXT_CHARACTERS: usize = 512;
/// Separate worst-case UTF-8 byte cap for a bounded descriptive text value.
pub const MAX_TEXT_BYTES: usize = 4 * MAX_TEXT_CHARACTERS;

/// Entry-specific source review and maintenance, independent of binary version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub source: String,
    pub reference: String,
    pub license: String,
    pub maintainer: String,
    pub updated: String,
}

/// The request set is closed: operator documents cannot introduce arbitrary
/// bytes, authentication, mutation, URL targets, or redirect behavior.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Banner {},
    HttpHead {},
    /// Reuses the UDP profile DNS payload representation and encoder inputs.
    /// Validation permits only root IN A and version.bind CH TXT queries.
    Dns {
        payload: Payload,
    },
}

impl Request {
    pub const fn protocol(&self) -> Protocol {
        match self {
            Self::Banner {} => Protocol::Ssh,
            Self::HttpHead {} => Protocol::Http,
            Self::Dns { .. } => Protocol::Dns,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadOnlyReview {
    pub reviewed_by: String,
    pub reviewed: String,
    pub statement: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    pub id: String,
    pub transport: Transport,
    pub intensity: u8,
    pub request: Request,
    pub metadata: Metadata,
    pub read_only_review: ReadOnlyReview,
}

impl Probe {
    /// Returns application bytes; transport framing belongs to the workflow.
    /// Each DNS attempt supplies its transaction ID explicitly.
    /// DNS uses the supplied header transaction ID, independently of `id_base`.
    pub fn request_bytes(&self, transaction_id: u16) -> Result<Vec<u8>, Error> {
        validate_probe(self)?;
        match &self.request {
            Request::Banner {} => Ok(Vec::new()),
            Request::HttpHead {} => Ok(b"HEAD / HTTP/1.0\r\n\r\n".to_vec()),
            Request::Dns {
                payload:
                    Payload::Dns {
                        name,
                        query_type,
                        class,
                        recursion_desired,
                        ..
                    },
            } => {
                let question = Question {
                    name: name
                        .parse()
                        .map_err(|source| Error::Dns(Source::new(source)))?,
                    query_type: *query_type,
                    class: *class,
                };
                let mut dns = Dns::default();
                dns.edit(|dns| {
                    dns.id = transaction_id;
                    dns.recursion_desired = *recursion_desired;
                    dns.questions = vec![question];
                });
                dns.to_wire()
                    .map(|wire| wire.to_vec())
                    .map_err(|source| Error::Dns(Source::new(source)))
            }
            Request::Dns { .. } => Err(invalid("DNS request", "expected a DNS payload")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Ssh,
    Http,
    Dns,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    SshBanner,
    SshSoftware,
    HttpStatus,
    HttpServer,
    DnsRcode,
    DnsTxt,
}

impl Field {
    pub const fn protocol(self) -> Protocol {
        match self {
            Self::SshBanner | Self::SshSoftware => Protocol::Ssh,
            Self::HttpStatus | Self::HttpServer => Protocol::Http,
            Self::DnsRcode | Self::DnsTxt => Protocol::Dns,
        }
    }
}

/// Extracts at most `max_bytes` from the remainder after an anchored prefix.
/// Extraction stops at any listed ASCII delimiter and accepts version tokens
/// beginning with a digit. An overlong token is not silently shortened.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionExtraction {
    pub max_bytes: usize,
    pub stop_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchRule {
    pub id: String,
    pub probe: String,
    pub field: Field,
    pub prefix: String,
    pub product: String,
    pub version: Option<VersionExtraction>,
    pub metadata: Metadata,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Corpus {
    pub schema: String,
    pub name: String,
    pub version: String,
    pub probes: Vec<Probe>,
    pub matches: Vec<MatchRule>,
}

impl Corpus {
    pub fn validate(&self) -> Result<(), Error> {
        validate(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationOutcome {
    Complete,
    Unknown,
    Malformed,
    Truncated,
}

/// Exact field octets, including non-UTF-8 values, stay available as evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedField {
    pub field: Field,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub protocol: Option<Protocol>,
    pub outcome: ObservationOutcome,
    pub fields: Vec<ObservedField>,
    pub diagnostic: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchOutcome {
    Matched,
    Unknown,
    Ambiguous,
    Malformed,
    Truncated,
}

/// Ordinal evidence categories, not measured probabilities. `Claim` is only
/// an unauthenticated software field; `Protocol` confirms protocol syntax and
/// never supports a product version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Claim,
    Protocol,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchProvenance {
    pub corpus: String,
    pub version: String,
    pub probe: String,
    pub rule: String,
    pub field_indices: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub product: String,
    pub version: Option<String>,
    pub confidence: Confidence,
    pub provenance: MatchProvenance,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identification {
    pub outcome: MatchOutcome,
    pub candidates: Vec<Candidate>,
}

pub fn parse(document: &[u8]) -> Result<Corpus, Error> {
    if document.len() > MAX_DOCUMENT_BYTES {
        return Err(Error::DocumentSize {
            actual: document.len(),
            limit: MAX_DOCUMENT_BYTES,
        });
    }
    let corpus: Corpus =
        serde_json::from_slice(document).map_err(|source| Error::Syntax(Source::new(source)))?;
    validate(&corpus)?;
    Ok(corpus)
}

fn validate(corpus: &Corpus) -> Result<(), Error> {
    if corpus.schema != SERVICE_PROBES_SCHEMA_V1 {
        return Err(invalid("schema", "unsupported service-probes schema"));
    }
    identifier("corpus name", &corpus.name)?;
    text("corpus version", &corpus.version)?;
    count("probes", corpus.probes.len(), MAX_PROBES)?;
    count("matches", corpus.matches.len(), MAX_MATCHES)?;
    let mut probes = BTreeSet::new();
    for probe in &corpus.probes {
        validate_probe(probe)?;
        if !probes.insert(probe.id.as_str()) {
            return Err(invalid("probe ID", "duplicate"));
        }
    }
    let mut rules = BTreeSet::new();
    for rule in &corpus.matches {
        identifier("match ID", &rule.id)?;
        if !rules.insert(rule.id.as_str()) {
            return Err(invalid("match ID", "duplicate"));
        }
        let Some(probe) = corpus.probes.iter().find(|probe| probe.id == rule.probe) else {
            return Err(invalid("match probe", "names no probe"));
        };
        if rule.field.protocol() != probe.request.protocol() {
            return Err(invalid(
                "match field",
                "does not belong to the probe protocol",
            ));
        }
        text("product", &rule.product)?;
        if matches!(rule.field, Field::DnsRcode) && rule.product != "DNS service"
            || matches!(rule.field, Field::HttpStatus) && rule.product != "HTTP service"
        {
            return Err(invalid(
                "product",
                "protocol fields can identify only their protocol service",
            ));
        }
        text("match prefix", &rule.prefix)?;
        if !rule.prefix.is_ascii() || rule.prefix.len() > MAX_FIELD_BYTES {
            return Err(invalid("match prefix", "expected bounded ASCII literal"));
        }
        if let Some(version) = &rule.version
            && (matches!(rule.field, Field::DnsRcode | Field::HttpStatus)
                || version.max_bytes == 0
                || version.max_bytes > 64
                || version.stop_at.is_empty()
                || version.stop_at.len() > 32
                || !version.stop_at.is_ascii())
        {
            return Err(invalid(
                "version extraction",
                "expected bounded claim-field extraction",
            ));
        }
        metadata(&rule.metadata)?;
    }
    Ok(())
}

fn validate_probe(probe: &Probe) -> Result<(), Error> {
    identifier("probe ID", &probe.id)?;
    if probe.intensity == 0 || probe.intensity > MAX_INTENSITY {
        return Err(invalid("probe intensity", "expected 1 to 9"));
    }
    if probe.transport == Transport::Udp && !matches!(probe.request, Request::Dns { .. }) {
        return Err(invalid("probe transport", "only DNS probes support UDP"));
    }
    if let Request::Dns { payload } = &probe.request {
        let Payload::Dns {
            name,
            query_type,
            class,
            recursion_desired,
            ..
        } = payload
        else {
            return Err(invalid(
                "DNS request",
                "arbitrary byte payloads are forbidden",
            ));
        };
        let parsed: Name = name
            .parse()
            .map_err(|source| Error::Dns(Source::new(source)))?;
        let version_name: Name = "version.bind.".parse().expect("constant name");
        if *recursion_desired
            || !((parsed == Name::root() && *query_type == 1 && *class == 1)
                || (parsed == version_name && *query_type == 16 && *class == 3))
        {
            return Err(invalid(
                "DNS request",
                "expected nonrecursive root IN A or version.bind CH TXT",
            ));
        }
    }
    metadata(&probe.metadata)?;
    text("reviewer", &probe.read_only_review.reviewed_by)?;
    date("review date", &probe.read_only_review.reviewed)?;
    text("read-only review", &probe.read_only_review.statement)?;
    Ok(())
}

pub(super) fn metadata(value: &Metadata) -> Result<(), Error> {
    text("source", &value.source)?;
    text("reference", &value.reference)?;
    text("license", &value.license)?;
    text("maintainer", &value.maintainer)?;
    date("updated date", &value.updated)
}

pub(super) fn text(field: &'static str, value: &str) -> Result<(), Error> {
    // JSON Schema maxLength counts Unicode characters. Keep a separate finite
    // UTF-8 allocation bound and the enclosing document's byte-size boundary.
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.chars().count() > MAX_TEXT_CHARACTERS
        || value.chars().any(char::is_control)
    {
        Err(invalid(
            field,
            "expected 1 to 512 text characters without controls",
        ))
    } else {
        Ok(())
    }
}

pub(super) fn identifier(field: &'static str, value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 64
        || !value.starts_with(|character: char| character.is_ascii_lowercase())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        Err(invalid(
            field,
            "expected lowercase identifier of at most 64 bytes",
        ))
    } else {
        Ok(())
    }
}

fn date(field: &'static str, value: &str) -> Result<(), Error> {
    if value.len() == 10
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 4 | 7) {
                byte == b'-'
            } else {
                byte.is_ascii_digit()
            }
        })
    {
        Ok(())
    } else {
        Err(invalid(field, "expected YYYY-MM-DD"))
    }
}

fn count(field: &'static str, actual: usize, limit: usize) -> Result<(), Error> {
    if actual == 0 || actual > limit {
        Err(invalid(
            field,
            "entry count is empty or exceeds the finite limit",
        ))
    } else {
        Ok(())
    }
}

pub(super) fn invalid(field: &'static str, reason: &'static str) -> Error {
    Error::Invalid { field, reason }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("service document has {actual} bytes, exceeding limit {limit}")]
    DocumentSize { actual: usize, limit: usize },
    #[error("invalid service document syntax")]
    Syntax(#[source] Source),
    #[error("service document {field}: {reason}")]
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
    #[error("invalid service DNS request")]
    Dns(#[source] Source),
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        Classification::new("document.service_probes", Kind::Usage, None)
    }
}
