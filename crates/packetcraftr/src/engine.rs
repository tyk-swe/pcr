// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private plumbing shared by live workflows: staged packet preparation,
//! send options, and the execution context of one operation.

pub(crate) mod execution;
mod mtu;
pub(crate) mod operation;
pub(crate) mod options;
pub(crate) mod preparation;
