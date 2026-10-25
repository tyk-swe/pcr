// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private plumbing shared by live workflows: statistics, wire correlation,
//! staged packet preparation, and the execution context of one operation.

pub(crate) mod correlation;
pub(crate) mod execution;
mod mtu;
pub(crate) mod operation;
pub(crate) mod preparation;
pub(crate) mod stats;
