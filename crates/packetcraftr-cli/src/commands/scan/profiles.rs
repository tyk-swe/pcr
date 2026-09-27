// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use crate::errors::CliError;
use packetcraftr::scan::profile::{self, UdpProfile};
use packetcraftr_core::document::udp_profiles::{self, MAX_PROFILE_BYTES};
use packetcraftr_core::error::Kind;
use std::{collections::BTreeMap, path::Path, sync::Arc};

/// Reads the `--udp-profiles` document, which only a UDP scan accepts.
pub(super) fn load(
    path: Option<&Path>,
    transport: super::arguments::Transport,
) -> Result<BTreeMap<u16, Arc<UdpProfile>>, CliError> {
    let Some(path) = path else {
        return Ok(BTreeMap::new());
    };
    if !matches!(transport, super::arguments::Transport::Udp) {
        return Err(CliError::new(
            Kind::Usage,
            "--udp-profiles requires --transport udp",
        ));
    }
    let document = crate::input::read_bounded_json_document(path, MAX_PROFILE_BYTES)?;
    let assignments = udp_profiles::parse(&document).map_err(CliError::classified)?;
    profile::compile(assignments).map_err(CliError::classified)
}
