// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::Error;

pub const MAX_CAPTURE_QUEUE_FRAMES: usize = 4_096;
pub const MAX_CAPTURE_QUEUE_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_SNAP_LENGTH: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OverflowPolicy {
    #[default]
    Fail,
    DropNewest,
    DropOldest,
}

impl OverflowPolicy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fail => "fail",
            Self::DropNewest => "drop-newest",
            Self::DropOldest => "drop-oldest",
        }
    }
}

impl std::fmt::Display for OverflowPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_frames: usize,
    pub max_bytes: usize,
    pub snap_length: usize,
    pub overflow_policy: OverflowPolicy,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frames: MAX_CAPTURE_QUEUE_FRAMES,
            max_bytes: MAX_CAPTURE_QUEUE_BYTES,
            snap_length: MAX_SNAP_LENGTH,
            overflow_policy: OverflowPolicy::Fail,
        }
    }
}

impl Limits {
    pub fn validate(&self) -> Result<(), Error> {
        for (field, value) in [
            ("max_frames", self.max_frames),
            ("max_bytes", self.max_bytes),
            ("snap_length", self.snap_length),
        ] {
            if value == 0 {
                return Err(Error::InvalidCaptureQueueLimit {
                    field,
                    value,
                    reason: "must be greater than zero",
                });
            }
        }
        for (field, value, maximum) in [
            ("max_frames", self.max_frames, MAX_CAPTURE_QUEUE_FRAMES),
            ("max_bytes", self.max_bytes, MAX_CAPTURE_QUEUE_BYTES),
            ("snap_length", self.snap_length, MAX_SNAP_LENGTH),
        ] {
            if value > maximum {
                return Err(Error::InvalidCaptureQueueLimit {
                    field,
                    value,
                    reason: "exceeds the stable configured maximum",
                });
            }
        }
        if self.snap_length > self.max_bytes {
            return Err(Error::InvalidCaptureQueueLimit {
                field: "snap_length",
                value: self.snap_length,
                reason: "cannot exceed max_bytes",
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rejected_field(limits: Limits) -> &'static str {
        match limits.validate() {
            Err(Error::InvalidCaptureQueueLimit { field, .. }) => field,
            other => panic!("expected InvalidCaptureQueueLimit, got {other:?}"),
        }
    }

    #[test]
    fn rejection_reports_the_offending_value_and_reason() {
        let limits = Limits {
            max_frames: MAX_CAPTURE_QUEUE_FRAMES + 7,
            ..Limits::default()
        };
        match limits.validate() {
            Err(Error::InvalidCaptureQueueLimit {
                field,
                value,
                reason,
            }) => {
                assert_eq!(field, "max_frames");
                assert_eq!(value, MAX_CAPTURE_QUEUE_FRAMES + 7);
                assert!(!reason.is_empty());
            }
            other => panic!("expected InvalidCaptureQueueLimit, got {other:?}"),
        }
        let limits = Limits {
            snap_length: 0,
            ..Limits::default()
        };
        match limits.validate() {
            Err(Error::InvalidCaptureQueueLimit { value, .. }) => assert_eq!(value, 0),
            other => panic!("expected InvalidCaptureQueueLimit, got {other:?}"),
        }
    }

    #[test]
    fn defaults_and_boundary_values_validate() {
        assert!(Limits::default().validate().is_ok());
        let boundary = Limits {
            max_frames: 1,
            max_bytes: 1,
            snap_length: 1,
            overflow_policy: OverflowPolicy::DropOldest,
        };
        assert!(boundary.validate().is_ok());
    }

    #[test]
    fn zero_and_over_maximum_fields_are_rejected_by_name() {
        let base = Limits::default();
        assert_eq!(
            rejected_field(Limits {
                max_frames: 0,
                ..base
            }),
            "max_frames"
        );
        assert_eq!(
            rejected_field(Limits {
                max_bytes: 0,
                ..base
            }),
            "max_bytes"
        );
        assert_eq!(
            rejected_field(Limits {
                snap_length: 0,
                ..base
            }),
            "snap_length"
        );
        assert_eq!(
            rejected_field(Limits {
                max_frames: MAX_CAPTURE_QUEUE_FRAMES + 1,
                ..base
            }),
            "max_frames"
        );
        assert_eq!(
            rejected_field(Limits {
                max_bytes: MAX_CAPTURE_QUEUE_BYTES + 1,
                ..base
            }),
            "max_bytes"
        );
        assert_eq!(
            rejected_field(Limits {
                snap_length: MAX_SNAP_LENGTH + 1,
                ..base
            }),
            "snap_length"
        );
    }

    #[test]
    fn snap_length_must_fit_the_aggregate_byte_ceiling() {
        let base = Limits::default();
        assert_eq!(
            rejected_field(Limits {
                max_bytes: 10,
                snap_length: 11,
                ..base
            }),
            "snap_length"
        );
        assert!(
            Limits {
                max_bytes: 10,
                snap_length: 10,
                ..base
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn overflow_policies_render_with_their_cli_names() {
        assert_eq!(OverflowPolicy::Fail.as_str(), "fail");
        assert_eq!(OverflowPolicy::DropNewest.as_str(), "drop-newest");
        assert_eq!(OverflowPolicy::DropOldest.as_str(), "drop-oldest");
        assert_eq!(OverflowPolicy::DropNewest.to_string(), "drop-newest");
    }
}
