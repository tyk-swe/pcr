// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use crate::errors::CliError;
use packetcraftr_core::{
    error::Kind,
    registry::Registry,
    transform::{ChecksumMode, FieldAssignment, FieldEdits, HeaderRewrite, VlanRewrite},
};
use std::path::Path;

/// How field edits treat the checksums covering changed bytes.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub(crate) enum ChecksumArg {
    /// Recompute every supported checksum covering a changed field.
    Repair,
    /// Retain checksum bytes exactly, for deliberately malformed fixtures.
    Preserve,
}

impl From<ChecksumArg> for ChecksumMode {
    fn from(mode: ChecksumArg) -> Self {
        match mode {
            ChecksumArg::Repair => Self::Repair,
            ChecksumArg::Preserve => Self::Preserve,
        }
    }
}

/// One ordered rewrite rule: header edits, field assignments, or both.
#[derive(Debug)]
pub(super) struct Rule {
    pub(super) filter: Option<String>,
    pub(super) patch: HeaderRewrite,
    pub(super) edits: Option<FieldEdits>,
}

impl Rule {
    pub(super) fn has_edits(&self) -> bool {
        self.edits.is_some()
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema: String,
    rules: Vec<PatchRule>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchRule {
    filter: Option<String>,
    patch: HeaderRewrite,
}

/// `packetcraftr.rewrite/v2` rules assign canonical field paths in place.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AssignDocument {
    schema: String,
    rules: Vec<AssignRule>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AssignRule {
    filter: Option<String>,
    assign: Vec<FieldAssignment>,
}

pub(super) fn load(
    path: &Path,
    registry: &Registry,
    checksum_mode: ChecksumMode,
) -> Result<Vec<Rule>, CliError> {
    let bytes = crate::input::read_bounded_json_document(path, 1_048_576)?;
    let schema: String = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|value| value.get("schema")?.as_str().map(str::to_owned))
        .unwrap_or_default();
    if schema == "packetcraftr.rewrite/v2" {
        return load_assignments(&bytes, registry, checksum_mode);
    }
    let document: Document = serde_json::from_slice(&bytes)
        .map_err(|source| CliError::new(Kind::Usage, format!("invalid rewrite rules: {source}")))?;
    if document.schema != "packetcraftr.rewrite/v1"
        || document.rules.is_empty()
        || document.rules.len() > 64
    {
        return Err(CliError::new(
            Kind::Usage,
            "rewrite rules require schema packetcraftr.rewrite/v1 or /v2 and 1..=64 rules",
        ));
    }
    let mut rules = Vec::with_capacity(document.rules.len());
    for rule in document.rules {
        rule.patch.validate().map_err(CliError::classified)?;
        if rule.patch.is_empty() {
            return Err(CliError::new(
                Kind::Usage,
                "rewrite rules cannot contain empty patches",
            ));
        }
        rules.push(Rule {
            filter: rule.filter,
            patch: rule.patch,
            edits: None,
        });
    }
    Ok(rules)
}

fn load_assignments(
    bytes: &[u8],
    registry: &Registry,
    checksum_mode: ChecksumMode,
) -> Result<Vec<Rule>, CliError> {
    let document: AssignDocument = serde_json::from_slice(bytes)
        .map_err(|source| CliError::new(Kind::Usage, format!("invalid rewrite rules: {source}")))?;
    if document.schema != "packetcraftr.rewrite/v2"
        || document.rules.is_empty()
        || document.rules.len() > 64
    {
        return Err(CliError::new(
            Kind::Usage,
            "rewrite rules require schema packetcraftr.rewrite/v1 or /v2 and 1..=64 rules",
        ));
    }
    let mut rules = Vec::with_capacity(document.rules.len());
    for rule in document.rules {
        if rule.assign.is_empty() {
            return Err(CliError::new(
                Kind::Usage,
                "rewrite rules cannot contain empty assignments",
            ));
        }
        let edits = FieldEdits::compile(&rule.assign, checksum_mode, registry)
            .map_err(|error| CliError::caused(Kind::Usage, &error))?;
        rules.push(Rule {
            filter: rule.filter,
            patch: HeaderRewrite::default(),
            edits: Some(edits),
        });
    }
    Ok(rules)
}

/// Parses one `--set <field>=<value>` assignment.
pub(super) fn assignment(value: &str) -> Result<FieldAssignment, CliError> {
    value
        .parse()
        .map_err(|error| CliError::caused(Kind::Usage, &error))
}

pub(super) fn mac(value: &str) -> Result<[u8; 6], CliError> {
    let parts: Vec<_> = value.split(':').collect();
    if parts.len() != 6 || parts.iter().any(|part| part.len() != 2) {
        return Err(CliError::new(
            Kind::Usage,
            "MAC addresses require six colon-separated hexadecimal bytes",
        ));
    }
    let mut address = [0; 6];
    for (part, byte) in parts.iter().zip(&mut address) {
        *byte = u8::from_str_radix(part, 16)
            .map_err(|_| CliError::new(Kind::Usage, "invalid hexadecimal MAC address"))?;
    }
    Ok(address)
}
pub(super) fn vlan(value: &str) -> Result<VlanRewrite, CliError> {
    fn number(value: &str) -> Result<u16, CliError> {
        if let Some(value) = value.strip_prefix("0x") {
            u16::from_str_radix(value, 16)
        } else {
            value.parse()
        }
        .map_err(|_| CliError::new(Kind::Usage, "invalid VLAN number"))
    }
    let parts: Vec<_> = value.split(':').collect();
    let tag = match parts.as_slice() {
        [id] => VlanRewrite {
            ether_type: 0x8100,
            identifier: number(id)?,
            priority: 0,
            drop_eligible: false,
        },
        [kind, id, rest @ ..] if rest.len() <= 2 => {
            let priority = rest.first().map(|s| number(s)).transpose()?.unwrap_or(0);
            let dei = rest.get(1).map(|s| number(s)).transpose()?.unwrap_or(0);
            if priority > 7 || dei > 1 {
                return Err(CliError::new(
                    Kind::Usage,
                    "VLAN priority must be 0..=7 and DEI 0 or 1",
                ));
            }
            VlanRewrite {
                ether_type: number(kind)?,
                identifier: number(id)?,
                priority: priority as u8,
                drop_eligible: dei == 1,
            }
        }
        _ => {
            return Err(CliError::new(
                Kind::Usage,
                "use VID or TPID:VID[:PRIORITY[:DEI]]",
            ));
        }
    };
    HeaderRewrite {
        vlans: Some(vec![tag]),
        ..Default::default()
    }
    .validate()
    .map_err(CliError::classified)?;
    Ok(tag)
}
