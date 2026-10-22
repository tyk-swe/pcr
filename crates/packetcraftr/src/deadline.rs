// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deadlines shared by workflows and their callers.

/// Allowance for a passive route or interface lookup whose operation has no deadline.
pub const PASSIVE_LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
