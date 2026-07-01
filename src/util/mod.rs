// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(feature = "daemon")]
pub(crate) mod daemon;
pub(crate) mod error;
pub(crate) mod logging;
pub(crate) mod net;
pub(crate) mod paths;
pub(crate) mod privileges;
pub(crate) mod source_ip;
#[cfg(any(feature = "metrics", feature = "scan"))]
pub(crate) mod sync;
pub(crate) mod telemetry;
