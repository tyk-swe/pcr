// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The scan's file and stdin inputs: UDP payloads and profiles, and target
//! and exclusion manifests.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use packetcraftr::scan::{
    MAX_UDP_PAYLOAD_BYTES,
    profile::{self, UdpProfile},
};
use packetcraftr_core::document::udp_profiles::{self, MAX_PROFILE_BYTES};
use packetcraftr_core::error::{Classified, Kind};

use crate::errors::CliError;
use crate::input::{InputKind, manifest, read_bounded_file_allow_empty};

pub(super) fn read_udp_payload(
    udp: bool,
    hex: Option<&str>,
    path: Option<&Path>,
) -> Result<Bytes, CliError> {
    if (hex.is_some() || path.is_some()) && !udp {
        return Err(CliError::new(
            Kind::Usage,
            "--udp-payload-hex and --udp-payload-file require --transport udp",
        ));
    }
    if let Some(hex) = hex {
        // Bound both source text and decoded digits before parse_hex allocates.
        let digits = hex
            .strip_prefix("0x")
            .or_else(|| hex.strip_prefix("0X"))
            .unwrap_or(hex);
        if hex.len() > MAX_UDP_PAYLOAD_BYTES * 4 + 2
            || digits
                .chars()
                .filter(|c| !c.is_ascii_whitespace() && *c != ':' && *c != '-')
                .count()
                > MAX_UDP_PAYLOAD_BYTES * 2
        {
            return Err(CliError::new(
                Kind::Usage,
                "UDP payload exceeds 65507 bytes or its bounded hex representation",
            ));
        }
        return packetcraftr_core::layer::parse_hex(hex)
            .map_err(|source| CliError::caused(Kind::Usage, &source));
    }
    if let Some(path) = path {
        if manifest::is_stdin(path) {
            return crate::input::read_stdin_bounded_allow_empty(
                MAX_UDP_PAYLOAD_BYTES,
                InputKind::Payload,
            )
            .map(Bytes::from);
        }
        return read_bounded_file_allow_empty(path, MAX_UDP_PAYLOAD_BYTES, InputKind::Payload)
            .map(Bytes::from);
    }
    Ok(Bytes::new())
}

pub(super) fn load_udp_profiles(
    path: Option<&Path>,
    udp: bool,
) -> Result<BTreeMap<u16, Arc<UdpProfile>>, CliError> {
    let Some(path) = path else {
        return Ok(BTreeMap::new());
    };
    if !udp {
        return Err(CliError::new(
            Kind::Usage,
            "--udp-profiles requires --transport udp",
        ));
    }
    let document = if manifest::is_stdin(path) {
        crate::input::read_stdin_bounded(MAX_PROFILE_BYTES, InputKind::UdpProfiles)?
    } else {
        crate::input::read_bounded_json_document(path, MAX_PROFILE_BYTES)?
    };
    let assignments = udp_profiles::parse(&document).map_err(CliError::classified)?;
    profile::compile(assignments).map_err(CliError::classified)
}

pub(super) struct Ingested {
    pub(crate) targets: packetcraftr::target::Selection,
    pub(crate) origins: Vec<manifest::Declaration>,
}

pub(super) fn ingest_targets(
    positional: &[String],
    targets_file: &[PathBuf],
    exclusions: &[packetcraftr::target::Network],
    exclude_file: &[PathBuf],
    max_manifest_bytes: Option<usize>,
    max_manifest_lines: Option<usize>,
) -> Result<Ingested, CliError> {
    let bounds = manifest::ManifestBounds::new(
        max_manifest_bytes.unwrap_or(manifest::MAX_MANIFEST_BYTES),
        max_manifest_lines.unwrap_or(manifest::MAX_MANIFEST_LINES),
    )?;
    let mut budget = bounds.budget();
    let mut origins = positional
        .iter()
        .enumerate()
        .map(|(position, target)| manifest::Declaration {
            token: target.clone(),
            source: manifest::DeclarationSource::Argument {
                position: position + 1,
            },
            line: None,
        })
        .collect::<Vec<_>>();
    origins.extend(manifest::read_with_budget(
        &manifest_sources(targets_file),
        &mut budget,
    )?);
    let include = parse_declarations(&origins)?;
    if include.is_empty() {
        return Err(CliError::new(
            Kind::Usage,
            "at least one target is required: pass TARGET or --targets-file",
        ));
    }
    let mut exclude = exclusions.to_vec();
    exclude.extend(parse_declarations::<packetcraftr::target::Network>(
        &manifest::read_with_budget(&manifest_sources(exclude_file), &mut budget)?,
    )?);
    Ok(Ingested {
        targets: packetcraftr::target::Selection { include, exclude },
        origins,
    })
}

fn manifest_sources(paths: &[PathBuf]) -> Vec<manifest::ManifestSource> {
    paths
        .iter()
        .map(|path| manifest::ManifestSource::open(path))
        .collect()
}

fn parse_declarations<T>(declarations: &[manifest::Declaration]) -> Result<Vec<T>, CliError>
where
    T: std::str::FromStr,
    T::Err: Classified,
{
    declarations
        .iter()
        .map(|declaration| {
            declaration
                .token
                .parse()
                .map_err(|source| declaration_error(source, declaration))
        })
        .collect()
}

fn declaration_error(source: impl Classified, declaration: &manifest::Declaration) -> CliError {
    CliError::from_classification(
        source.classification(),
        format!("invalid declaration at {declaration}: {source}"),
        crate::output::envelope::source_causes(&source),
    )
    .with_context(source.context())
}
