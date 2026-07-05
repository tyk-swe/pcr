// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(feature = "metrics")]
mod enabled;
#[cfg(not(feature = "metrics"))]
mod noop;

#[cfg(feature = "metrics")]
pub(crate) use enabled::*;
#[cfg(not(feature = "metrics"))]
pub(crate) use noop::*;
