// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Fail-closed live traffic policy for protocol tests and authorized diagnostics.

mod authorization;
mod capture;
mod model;
mod operation;
mod wire;

pub use capture::CaptureBudget;
pub use model::{DEFAULT_MAX_RESOLVED_ADDRESSES, MAX_RESOLVED_ADDRESSES};
pub use model::{Error, Policy};

pub use operation::{
    Authorizer, BudgetOverflow, DeclaredPackets, DnsOperation, Operation, PermissiveLive,
    PolicyAuthorizer, ReplayFrame, SocketBudget, WireBudget, unsupported_operation,
};
pub(crate) use wire::{
    PermissiveLiveDenial, WireAuthorizationError, authorize_permissive_live, authorize_wire,
    check_permissive_live, decode_wire,
};

pub(crate) use model::INVALID_PACKET_SEMANTICS;
