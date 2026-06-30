// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(feature = "daemon")]
mod enabled;
#[cfg(not(feature = "daemon"))]
mod unavailable;

#[cfg(feature = "daemon")]
pub(crate) use enabled::DaemonBootstrap;
#[cfg(not(feature = "daemon"))]
pub(crate) use unavailable::DaemonBootstrap;
