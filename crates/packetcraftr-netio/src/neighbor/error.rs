// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Neighbor resolution error mapping and construction.

#![forbid(unsafe_code)]

use std::net::IpAddr;

use crate::{
    Error as LiveIoError,
    route::{InterfaceId, NeighborError},
};

pub(super) fn resolution_error(
    interface: &InterfaceId,
    target: IpAddr,
    message: String,
) -> NeighborError {
    NeighborError::Resolution {
        interface: interface.name.clone(),
        target,
        message,
    }
}

pub(super) fn map_io_error(
    request: &crate::route::NeighborRequest,
    operation: &'static str,
    error: LiveIoError,
) -> NeighborError {
    NeighborError::Io {
        interface: request.interface.name.clone(),
        target: request.target,
        operation,
        source: error,
    }
}

pub(super) fn invalid_configuration(message: String) -> NeighborError {
    NeighborError::InvalidConfiguration { message }
}
