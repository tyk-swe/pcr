// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Shared capture resource limits and overflow policy values.

use clap::{Args, ValueEnum};
use packetcraftr::{capture, net};

#[derive(Clone, Debug, Args)]
pub(in crate::cli) struct CaptureLimitArgs {
    /// Aggregate backend capture-queue frame bound.
    #[arg(long, default_value_t = net::capture::Limits::default().max_frames)]
    max_queue_frames: usize,
    /// Aggregate retained/queued capture byte bound.
    #[arg(long, default_value_t = net::capture::Limits::default().max_bytes)]
    max_captured_bytes: usize,
    /// Maximum bytes retained from any one captured frame.
    #[arg(long, default_value_t = capture::DEFAULT_SIZE_LIMIT)]
    snap_length: usize,
    /// Backend queue behavior when a configured bound is reached.
    #[arg(long, value_enum, default_value_t = CliCaptureOverflowPolicy::Fail)]
    overflow_policy: CliCaptureOverflowPolicy,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(in crate::cli) enum CliCaptureOverflowPolicy {
    #[default]
    Fail,
    DropNewest,
    DropOldest,
}

impl From<CliCaptureOverflowPolicy> for net::capture::OverflowPolicy {
    fn from(value: CliCaptureOverflowPolicy) -> Self {
        match value {
            CliCaptureOverflowPolicy::Fail => Self::Fail,
            CliCaptureOverflowPolicy::DropNewest => Self::DropNewest,
            CliCaptureOverflowPolicy::DropOldest => Self::DropOldest,
        }
    }
}

impl CaptureLimitArgs {
    pub(in crate::cli) fn into_limits(self) -> net::capture::Limits {
        net::capture::Limits {
            max_frames: self.max_queue_frames,
            max_bytes: self.max_captured_bytes,
            snap_length: self.snap_length,
            overflow_policy: self.overflow_policy.into(),
        }
    }
}
