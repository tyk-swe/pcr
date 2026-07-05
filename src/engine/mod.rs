// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

pub(crate) mod config;
pub(crate) mod core;
#[cfg(feature = "daemon")]
pub(crate) mod daemon;
pub(crate) mod error;
pub(crate) mod oneshot;
pub(crate) mod ports;
pub(crate) mod rule_send;
pub(crate) mod send;
#[cfg(test)]
pub(crate) mod test_support;
