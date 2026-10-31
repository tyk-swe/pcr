// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod collector;
mod handoff;
mod model;
mod rtt;

pub use collector::Collector;
pub(in crate::scan) use collector::WinnerKey;
pub use model::{
    Aggregate, Attribution, Classification, ClassificationCounts, Endpoint, Event, PendingEvidence,
    ProbeEvidence, Report, Rtt, SentProbe, Unattributed,
};
pub(crate) use rtt::RttAccumulator;
