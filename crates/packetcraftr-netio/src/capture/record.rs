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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_add_sums_every_field_and_rejects_overflow() {
        let summed = Stats {
            received_frames: 1,
            received_bytes: 2,
            dropped_frames: 3,
            dropped_bytes: 4,
            overflow_events: 5,
            receiver_dropped_frames: 6,
        }
        .checked_add(Stats {
            received_frames: 10,
            received_bytes: 20,
            dropped_frames: 30,
            dropped_bytes: 40,
            overflow_events: 50,
            receiver_dropped_frames: 60,
        })
        .unwrap();
        assert_eq!(
            summed,
            Stats {
                received_frames: 11,
                received_bytes: 22,
                dropped_frames: 33,
                dropped_bytes: 44,
                overflow_events: 55,
                receiver_dropped_frames: 66,
            }
        );
        let cases: [(Stats, Stats); 6] = [
            (
                Stats {
                    received_frames: u64::MAX,
                    ..Stats::default()
                },
                Stats {
                    received_frames: 1,
                    ..Stats::default()
                },
            ),
            (
                Stats {
                    received_bytes: u64::MAX,
                    ..Stats::default()
                },
                Stats {
                    received_bytes: 1,
                    ..Stats::default()
                },
            ),
            (
                Stats {
                    dropped_frames: u64::MAX,
                    ..Stats::default()
                },
                Stats {
                    dropped_frames: 1,
                    ..Stats::default()
                },
            ),
            (
                Stats {
                    dropped_bytes: u64::MAX,
                    ..Stats::default()
                },
                Stats {
                    dropped_bytes: 1,
                    ..Stats::default()
                },
            ),
            (
                Stats {
                    overflow_events: u64::MAX,
                    ..Stats::default()
                },
                Stats {
                    overflow_events: 1,
                    ..Stats::default()
                },
            ),
            (
                Stats {
                    receiver_dropped_frames: u64::MAX,
                    ..Stats::default()
                },
                Stats {
                    receiver_dropped_frames: 1,
                    ..Stats::default()
                },
            ),
        ];
        for (left, right) in cases {
            assert_eq!(left.checked_add(right), None, "{left:?} + {right:?}");
        }
    }

    #[test]
    fn serialized_stats_omit_zero_receiver_drops() {
        let rendered = serde_json::to_string(&Stats::default()).unwrap();
        assert!(!rendered.contains("receiver_dropped_frames"), "{rendered}");
        let rendered = serde_json::to_string(&Stats {
            receiver_dropped_frames: 3,
            ..Stats::default()
        })
        .unwrap();
        assert!(
            rendered.contains("\"receiver_dropped_frames\":3"),
            "{rendered}"
        );
    }

    #[test]
    fn validate_rejects_inconsistent_drop_accounting() {
        assert!(Stats::default().validate().is_ok());
        assert!(matches!(
            Stats {
                dropped_bytes: 1,
                ..Stats::default()
            }
            .validate(),
            Err(Error::InvalidCaptureStatistics { .. })
        ));
        assert!(matches!(
            Stats {
                dropped_frames: 1,
                receiver_dropped_frames: 2,
                ..Stats::default()
            }
            .validate(),
            Err(Error::InvalidCaptureStatistics { .. })
        ));
        assert!(
            Stats {
                dropped_frames: 2,
                dropped_bytes: 8,
                receiver_dropped_frames: 2,
                ..Stats::default()
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn any_single_drop_counter_alone_is_evidence_loss() {
        for stats in [
            Stats {
                dropped_frames: 1,
                ..Stats::default()
            },
            Stats {
                dropped_bytes: 1,
                ..Stats::default()
            },
            Stats {
                receiver_dropped_frames: 1,
                ..Stats::default()
            },
        ] {
            assert!(
                matches!(
                    stats.evidence_loss_error(),
                    Some(Error::CaptureEvidenceLoss { .. })
                ),
                "{stats:?}"
            );
        }
    }

    #[test]
    fn evidence_loss_prefers_overflow_over_plain_loss() {
        assert!(Stats::default().evidence_loss_error().is_none());
        let loss = Stats {
            dropped_frames: 1,
            ..Stats::default()
        }
        .evidence_loss_error()
        .unwrap();
        assert!(matches!(
            loss,
            Error::CaptureEvidenceLoss {
                dropped_frames: 1,
                dropped_bytes: 0,
                receiver_dropped_frames: 0
            }
        ));
        let overflow = Stats {
            dropped_frames: 2,
            dropped_bytes: 9,
            overflow_events: 3,
            ..Stats::default()
        }
        .evidence_loss_error()
        .unwrap();
        assert!(matches!(
            overflow,
            Error::CaptureQueueOverflow {
                dropped_frames: 2,
                dropped_bytes: 9,
                overflow_events: 3
            }
        ));
        let overflow_alone = Stats {
            overflow_events: 1,
            ..Stats::default()
        }
        .evidence_loss_error()
        .unwrap();
        assert!(matches!(
            overflow_alone,
            Error::CaptureQueueOverflow {
                dropped_frames: 0,
                ..
            }
        ));
    }
}
