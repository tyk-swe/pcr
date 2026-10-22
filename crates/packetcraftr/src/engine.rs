// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private plumbing shared by every live workflow: statistics, wire
//! correlation, route planning, staged packet preparation, and the execution
//! context of one operation.

pub(crate) mod admission;
pub(crate) mod correlation;
pub(crate) mod execution;
mod mtu;
pub(crate) mod planning;
pub(crate) mod preparation;
pub(crate) mod stats;
