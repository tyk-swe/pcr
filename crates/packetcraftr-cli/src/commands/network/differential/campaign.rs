// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{net::Ipv4Addr, path::Path};

use packetcraftr::differential as lib;
use packetcraftr_core::{error::Kind, security::input};
use serde::Deserialize;

use crate::{errors::CliError, invocation::Invocation, output::contract::Command};

const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;

pub(crate) struct JoinInputs {
    pub(crate) campaign: lib::Aggregate,
    pub(crate) receptions: Vec<lib::ReceptionRecord>,
}

#[derive(Deserialize)]
struct Campaign {
    provisional: bool,
    plan_digest: String,
    source_port: u16,
    // Require the field even when its value is null.
    #[serde(deserialize_with = "Option::<Ipv4Addr>::deserialize")]
    spoof_source: Option<Ipv4Addr>,
    attempts: Vec<Attempt>,
}

#[derive(Deserialize)]
struct Attempt {
    variant: String,
    attempt_seq: u32,
    answered: bool,
    packets_sent: usize,
    payload_sha256: String,
}

impl TryFrom<Attempt> for lib::AttemptEvidence {
    type Error = CliError;

    fn try_from(attempt: Attempt) -> Result<Self, Self::Error> {
        let variant_index = lib::catalog::catalog()
            .iter()
            .position(|variant| variant.id == attempt.variant)
            .ok_or_else(|| {
                CliError::new(
                    Kind::Usage,
                    format!("campaign names unknown variant {}", attempt.variant),
                )
            })?;
        Ok(Self {
            variant_index,
            attempt_seq: attempt.attempt_seq,
            answered: attempt.answered,
            packets_sent: attempt.packets_sent,
            payload_sha256: parse_hash(&attempt.payload_sha256)?,
            reply: None,
        })
    }
}

fn parse_hash(value: &str) -> Result<[u8; 32], CliError> {
    if value.len() != 64 {
        return Err(CliError::new(
            Kind::Usage,
            "campaign payload_sha256 must be 64 hex characters",
        ));
    }
    let mut hash = [0_u8; 32];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let text = std::str::from_utf8(pair)
            .map_err(|_| CliError::new(Kind::Usage, "campaign payload_sha256 must be hex"))?;
        hash[index] = u8::from_str_radix(text, 16)
            .map_err(|_| CliError::new(Kind::Usage, "campaign payload_sha256 must be hex"))?;
    }
    Ok(hash)
}

pub(crate) fn load(
    invocation: &Invocation,
    campaign_path: &Path,
    log_path: &Path,
) -> Result<JoinInputs, CliError> {
    let bytes =
        crate::input::read_bounded_json_document(invocation, campaign_path, MAX_INPUT_BYTES)?;
    invocation.check()?;
    let campaign = input::aggregate::<Campaign>(
        &bytes,
        &[
            Command::Differential.as_str(),
            Command::DifferentialJoin.as_str(),
        ],
    )
    .map_err(|error| CliError::new(Kind::Usage, error.to_string()))?
    .result;
    let attempts = campaign
        .attempts
        .into_iter()
        .map(lib::AttemptEvidence::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    let campaign = lib::Aggregate {
        valid: false,
        provisional: campaign.provisional,
        plan_digest: campaign.plan_digest,
        source_port: campaign.source_port,
        spoof_source: campaign.spoof_source,
        rows: lib::rows_for(&attempts),
        attempts,
        diagnostics: Vec::new(),
        stats: Default::default(),
    };
    let bytes = crate::input::read_bounded_json_document(invocation, log_path, MAX_INPUT_BYTES)?;
    invocation.check()?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| CliError::new(Kind::Usage, "responder log is not UTF-8 JSON lines"))?;
    let receptions = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<lib::ReceptionRecord>(line).map_err(|error| {
                CliError::new(
                    Kind::Usage,
                    format!("responder log line is not a reception record: {error}"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    invocation.check()?;
    Ok(JoinInputs {
        campaign,
        receptions,
    })
}
