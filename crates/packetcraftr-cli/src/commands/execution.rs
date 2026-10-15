// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{errors::CliError, invocation::Invocation, rendering::StreamEncoder};

/// A typed sink owns the invocation so worker threads enforce the same deadline.
pub(crate) fn emitter<E: 'static>(
    invocation: &Invocation,
    mut publish: impl FnMut(E, &StreamEncoder) -> Result<(), CliError> + Send + 'static,
) -> impl FnMut(E) -> Result<(), packetcraftr_core::error::BoundaryError> + Send + 'static {
    let invocation = invocation.clone();
    move |event| {
        invocation.check().map_err(CliError::into_boundary_error)?;
        publish(event, &invocation.output).map_err(CliError::into_boundary_error)
    }
}
