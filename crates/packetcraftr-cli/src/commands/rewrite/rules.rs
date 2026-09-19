// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use crate::errors::CliError;
use packetcraftr_core::{
    analysis::pcap,
    error::Kind,
    transform::{HeaderRewrite, VlanRewrite},
};
use std::{io::Read, path::Path};
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema: String,
    rules: Vec<Rule>,
}
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Rule {
    pub(super) filter: Option<String>,
    pub(super) patch: HeaderRewrite,
}
pub(super) fn load(path: &Path) -> Result<Vec<Rule>, CliError> {
    let mut bytes = Vec::new();
    let file = std::fs::File::open(path)
        .map_err(pcap::Error::from)
        .map_err(CliError::classified)?;
    file.take(1_048_577)
        .read_to_end(&mut bytes)
        .map_err(pcap::Error::from)
        .map_err(CliError::classified)?;
    if bytes.len() > 1_048_576 {
        return Err(CliError::classified(
            packetcraftr_core::transform::Error::Limit {
                field: "rewrite rule bytes",
                limit: 1_048_576,
            },
        ));
    }
    let document: Document = serde_json::from_slice(&bytes)
        .map_err(|source| CliError::new(Kind::Cli, format!("invalid rewrite rules: {source}")))?;
    if document.schema != "packetcraftr.rewrite/v1"
        || document.rules.is_empty()
        || document.rules.len() > 64
    {
        return Err(CliError::new(
            Kind::Cli,
            "rewrite rules require schema packetcraftr.rewrite/v1 and 1..=64 rules",
        ));
    }
    for rule in &document.rules {
        rule.patch.validate().map_err(CliError::classified)?;
        if rule.patch.is_empty() {
            return Err(CliError::new(
                Kind::Cli,
                "rewrite rules cannot contain empty patches",
            ));
        }
    }
    Ok(document.rules)
}
pub(super) fn mac(value: &str) -> Result<[u8; 6], CliError> {
    let parts: Vec<_> = value.split(':').collect();
    if parts.len() != 6 || parts.iter().any(|part| part.len() != 2) {
        return Err(CliError::new(
            Kind::Cli,
            "MAC addresses require six colon-separated hexadecimal bytes",
        ));
    }
    let mut address = [0; 6];
    for (part, byte) in parts.iter().zip(&mut address) {
        *byte = u8::from_str_radix(part, 16)
            .map_err(|_| CliError::new(Kind::Cli, "invalid hexadecimal MAC address"))?;
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
        .map_err(|_| CliError::new(Kind::Cli, "invalid VLAN number"))
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
                    Kind::Cli,
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
                Kind::Cli,
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
