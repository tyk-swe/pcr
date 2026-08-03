// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;
use crate::runtime::validate_interface_selector;

pub(crate) fn validate_live_interface_selector(
    command: &str,
    selector: Option<&str>,
) -> Result<(), CliError> {
    validate_interface_selector(command, selector).map(|_| ())
}
