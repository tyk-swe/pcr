// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::{Args, ValueEnum};
use packetcraftr::{analysis::pcap as capture, netio as net};

#[derive(Clone, Debug, Args)]
pub(crate) struct CaptureLimitsArgs {
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
    #[arg(long, value_enum, default_value_t = OverflowPolicy::Fail)]
    overflow_policy: OverflowPolicy,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum OverflowPolicy {
    #[default]
    Fail,
    DropNewest,
    DropOldest,
}

impl From<OverflowPolicy> for net::capture::OverflowPolicy {
    fn from(value: OverflowPolicy) -> Self {
        match value {
            OverflowPolicy::Fail => Self::Fail,
            OverflowPolicy::DropNewest => Self::DropNewest,
            OverflowPolicy::DropOldest => Self::DropOldest,
        }
    }
}

impl CaptureLimitsArgs {
    pub(crate) fn into_limits(self) -> net::capture::Limits {
        net::capture::Limits {
            max_frames: self.max_queue_frames,
            max_bytes: self.max_captured_bytes,
            snap_length: self.snap_length,
            overflow_policy: self.overflow_policy.into(),
        }
    }
}
