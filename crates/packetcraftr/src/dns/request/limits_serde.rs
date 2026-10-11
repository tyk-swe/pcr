// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Preserve the original Serde struct and its field order. Flattened maps
//! cannot represent these limits in non-self-describing binary formats.

use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(super) struct Limits {
    message: super::MessageLimits,
    max_evidence_frames: usize,
    max_evidence_bytes: usize,
    max_undecoded: usize,
    max_duration: Duration,
}

impl From<super::Limits> for Limits {
    fn from(value: super::Limits) -> Self {
        Self {
            message: value.message,
            max_evidence_frames: value.evidence.max_frames,
            max_evidence_bytes: value.evidence.max_bytes,
            max_undecoded: value.evidence.max_undecoded,
            max_duration: value.max_duration,
        }
    }
}

impl From<Limits> for super::Limits {
    fn from(value: Limits) -> Self {
        Self {
            message: value.message,
            evidence: crate::evidence::Limits {
                max_frames: value.max_evidence_frames,
                max_bytes: value.max_evidence_bytes,
                max_undecoded: value.max_undecoded,
            },
            max_duration: value.max_duration,
        }
    }
}
