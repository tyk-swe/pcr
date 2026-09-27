// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use packetcraftr_core::frame::Frame as CaptureFrame;

use crate::Error;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Stats {
    pub received_frames: u64,
    pub received_bytes: u64,
    pub dropped_frames: u64,
    pub dropped_bytes: u64,
    pub overflow_events: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub receiver_dropped_frames: u64,
}

impl Stats {
    pub fn checked_add(self, value: Self) -> Option<Self> {
        Some(Self {
            received_frames: self.received_frames.checked_add(value.received_frames)?,
            received_bytes: self.received_bytes.checked_add(value.received_bytes)?,
            dropped_frames: self.dropped_frames.checked_add(value.dropped_frames)?,
            dropped_bytes: self.dropped_bytes.checked_add(value.dropped_bytes)?,
            overflow_events: self.overflow_events.checked_add(value.overflow_events)?,
            receiver_dropped_frames: self
                .receiver_dropped_frames
                .checked_add(value.receiver_dropped_frames)?,
        })
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.dropped_frames == 0 && self.dropped_bytes != 0 {
            return Err(Error::InvalidCaptureStatistics {
                message: "dropped bytes were reported without a dropped frame".to_owned(),
            });
        }
        if self.receiver_dropped_frames > self.dropped_frames {
            return Err(Error::InvalidCaptureStatistics {
                message: "receiver-dropped frames exceed total dropped frames".to_owned(),
            });
        }
        Ok(())
    }

    pub fn evidence_loss_error(self) -> Option<Error> {
        if self.overflow_events != 0 {
            Some(Error::CaptureQueueOverflow {
                dropped_frames: self.dropped_frames,
                dropped_bytes: self.dropped_bytes,
                overflow_events: self.overflow_events,
            })
        } else if self.dropped_frames != 0
            || self.dropped_bytes != 0
            || self.receiver_dropped_frames != 0
        {
            Some(Error::CaptureEvidenceLoss {
                dropped_frames: self.dropped_frames,
                dropped_bytes: self.dropped_bytes,
                receiver_dropped_frames: self.receiver_dropped_frames,
            })
        } else {
            None
        }
    }
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RecordIdentity(u64);

static NEXT_RECORD_ID: AtomicU64 = AtomicU64::new(1);

/// Wall-clock time is output-only; freshness and latency use `received_at`.
#[derive(Clone, Debug)]
pub struct Captured {
    identity: RecordIdentity,
    pub source: usize,
    pub frame: CaptureFrame,
    pub received_at: Option<Instant>,
}

impl Captured {
    pub fn new(frame: CaptureFrame, received_at: Instant) -> Self {
        Self::with_ingress_time(frame, Some(received_at))
    }

    pub fn with_ingress_time(frame: CaptureFrame, received_at: Option<Instant>) -> Self {
        let identity = NEXT_RECORD_ID
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .expect("capture record identity space exhausted");
        Self {
            identity: RecordIdentity(identity),
            source: 0,
            frame,
            received_at,
        }
    }

    pub fn without_ingress_time(frame: CaptureFrame) -> Self {
        Self::with_ingress_time(frame, None)
    }

    pub fn identity(&self) -> RecordIdentity {
        self.identity
    }
}
