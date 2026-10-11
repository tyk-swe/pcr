// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Preserve the original Serde struct and its field order. Flattened maps
//! cannot represent these limits in non-self-describing binary formats.

use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(super) struct Limits {
    max_probes: usize,
    max_duration: Duration,
    max_evidence_frames: usize,
    max_evidence_bytes: usize,
    max_undecoded: usize,
}

impl From<super::Limits> for Limits {
    fn from(value: super::Limits) -> Self {
        Self {
            max_probes: value.max_probes,
            max_duration: value.max_duration,
            max_evidence_frames: value.evidence.max_frames,
            max_evidence_bytes: value.evidence.max_bytes,
            max_undecoded: value.evidence.max_undecoded,
        }
    }
}

impl From<Limits> for super::Limits {
    fn from(value: Limits) -> Self {
        Self {
            max_probes: value.max_probes,
            max_duration: value.max_duration,
            evidence: crate::evidence::Limits {
                max_frames: value.max_evidence_frames,
                max_bytes: value.max_evidence_bytes,
                max_undecoded: value.max_undecoded,
            },
        }
    }
}
