// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;

pub(crate) fn parse_target(target: String) -> Result<packetcraftr::target::Target, CliError> {
    target
        .parse::<packetcraftr::target::Target>()
        .map_err(CliError::classified)
}
