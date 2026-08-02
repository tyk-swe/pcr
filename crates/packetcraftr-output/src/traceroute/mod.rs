// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured traceroute output.

mod model;
pub use crate::frame::{Captured as Frame, Timestamp};
pub use model::{
    TraceCompletionReason as Completion, TraceHopOutput as Hop, TraceProbeOutput as Probe,
    TraceProbeStatus as ProbeStatus, TraceResponseKind as ResponseKind,
    TraceUndecodedOutput as Undecoded, TracerouteCommandResult as Result,
    TracerouteStreamCommandResult as Event,
};
