// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::{CANCELLED_EXIT_CODE, CliError};
use packetcraftr_core::budget::Cancellation;
use std::sync::OnceLock;

pub(crate) fn signal() -> &'static Cancellation {
    static SIGNAL: OnceLock<Cancellation> = OnceLock::new();
    SIGNAL.get_or_init(Cancellation::default)
}

pub(crate) fn check() -> Result<(), CliError> {
    signal().check().map_err(CliError::classified)?;
    crate::invocation::check()
}

pub(crate) fn install() -> Result<(), CliError> {
    let signal = signal().clone();
    ctrlc::set_handler(move || {
        if signal.is_cancelled() {
            std::process::exit(i32::from(CANCELLED_EXIT_CODE));
        }
        signal.cancel();
    })
    .map_err(|error| {
        CliError::new(
            packetcraftr_core::error::Kind::Io,
            format!("install interrupt handler failed: {error}"),
        )
    })
}
