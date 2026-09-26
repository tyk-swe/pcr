// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Fail-closed live traffic policy for protocol tests and authorized diagnostics.

mod authorization;
mod capture;
mod model;
mod operation;
mod wire;

pub use capture::CaptureBudget;
pub use model::{
    DEFAULT_MAX_RESOLVED_ADDRESSES, MAX_DESTINATION_CONSTRAINTS, MAX_RESOLVED_ADDRESSES,
};
pub use model::{DestinationConstraint, Error, Policy};

pub use operation::{
    Authorizer, DeclaredPackets, DnsOperation, LimitOverflow, Operation, PermissiveLive,
    PolicyAuthorizer, ReplayFrame, SocketLimits, SocketOperation, WireLimits,
    unsupported_operation,
};
pub use wire::requires_live_opt_in;
pub(crate) use wire::{
    authorize_permissive_live, authorize_wire, authorize_wire_destinations, authorize_wire_sources,
    decode_wire,
};
