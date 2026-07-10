// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Portable workflow boundary for replay, scan, traceroute, DNS, and fuzz tooling.
//!
//! Tool implementations are added incrementally behind this module so the
//! eventual `packetcraftr-tools` extraction does not change root imports.

mod replay;

pub use replay::{
    replay_capture, ReplayAuthorizationError, ReplayAuthorizer, ReplayClock, ReplayError,
    ReplayFrameEvidence, ReplayLimits, ReplayOptions, ReplaySummary, ReplayTransmission,
    ReplayTransmitter, SystemReplayClock, MAX_REPLAY_DURATION,
};
