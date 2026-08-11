// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded wire primitives and timestamp conversion.

mod primitives;
mod timestamp;

pub(in crate::analysis::pcap) use primitives::*;
pub(in crate::analysis::pcap) use timestamp::*;
