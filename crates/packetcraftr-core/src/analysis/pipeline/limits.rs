// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use crate::analysis::reassembly::ip::{self, Limits as IpReassemblyLimits};
use crate::analysis::reassembly::tcp::{self, Limits as TcpReassemblyLimits};
use crate::capture_file::{
    Budget as CaptureBudget, DEFAULT_MAX_STREAM_BYTES, DEFAULT_MAX_STREAM_FRAMES,
    Error as CaptureError, Limits as CaptureLimits,
};
use crate::frame::DEFAULT_MAX_SIZE;

use crate::analysis::{Constraint, Error};

const DEFAULT_MAX_ANALYSIS_FLOWS: usize = 8_192;
pub(super) const DIRECTIONS_PER_CONVERSATION: usize = 2;

const fn tcp_field(field: tcp::Field) -> &'static str {
    match field {
        tcp::Field::MaxFlows => "max_tcp_flows",
        tcp::Field::MaxBytesPerFlow => "max_tcp_bytes_per_flow",
        tcp::Field::MaxAggregateBytes => "max_tcp_reassembly_bytes",
        tcp::Field::MaxSegmentsPerFlow => "max_tcp_segments_per_flow",
        tcp::Field::IdleExpiry => "tcp_idle_expiry",
    }
}

const fn ip_field(field: ip::Field) -> &'static str {
    match field {
        ip::Field::MaxDatagrams => "max_ip_datagrams",
        ip::Field::MaxFragmentsPerDatagram => "max_ip_fragments_per_datagram",
        ip::Field::MaxBytesPerDatagram => "max_ip_bytes_per_datagram",
        ip::Field::MaxAggregateBytes => "max_ip_reassembly_bytes",
        ip::Field::MaxRetainedOutcomes => "max_ip_outcomes",
        ip::Field::IdleExpiry => "ip_idle_expiry",
    }
}

/// Frame and byte limits count all input, including filtered frames.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_provenance_bytes: usize,
    pub max_frames: u64,
    pub max_bytes: u64,
    pub max_frame_bytes: usize,
    /// Cumulative distinct conversations per transport; expiry does not release them.
    pub max_flows: usize,
    pub max_scope_bytes: usize,
    pub tcp: TcpReassemblyLimits,
    /// Its aggregate byte ceiling also covers derived cascade buffers.
    pub ip: IpReassemblyLimits,
    pub max_duration: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_provenance_bytes: 16 * 1024 * 1024,
            max_frames: DEFAULT_MAX_STREAM_FRAMES,
            max_bytes: DEFAULT_MAX_STREAM_BYTES,
            max_frame_bytes: DEFAULT_MAX_SIZE,
            max_flows: DEFAULT_MAX_ANALYSIS_FLOWS,
            max_scope_bytes: 16 * 1024 * 1024,
            tcp: TcpReassemblyLimits {
                max_flows: DEFAULT_MAX_ANALYSIS_FLOWS * DIRECTIONS_PER_CONVERSATION,
                ..TcpReassemblyLimits::default()
            },
            ip: IpReassemblyLimits::default(),
            max_duration: Duration::from_secs(3_600),
        }
    }
}

impl Limits {
    pub fn validate(&self) -> Result<(), Error> {
        for (field, value) in [
            ("max_frames", self.max_frames),
            ("max_bytes", self.max_bytes),
            ("max_frame_bytes", self.max_frame_bytes as u64),
            ("max_flows", self.max_flows as u64),
            ("max_scope_bytes", self.max_scope_bytes as u64),
            ("max_provenance_bytes", self.max_provenance_bytes as u64),
            (tcp_field(tcp::Field::MaxFlows), self.tcp.max_flows as u64),
            (
                tcp_field(tcp::Field::MaxBytesPerFlow),
                self.tcp.max_bytes_per_flow as u64,
            ),
            (
                tcp_field(tcp::Field::MaxAggregateBytes),
                self.tcp.max_aggregate_bytes as u64,
            ),
            (
                tcp_field(tcp::Field::MaxSegmentsPerFlow),
                self.tcp.max_segments_per_flow as u64,
            ),
            (
                ip_field(ip::Field::MaxDatagrams),
                self.ip.max_datagrams as u64,
            ),
            (
                ip_field(ip::Field::MaxFragmentsPerDatagram),
                self.ip.max_fragments_per_datagram as u64,
            ),
            (
                ip_field(ip::Field::MaxBytesPerDatagram),
                self.ip.max_bytes_per_datagram as u64,
            ),
            (
                ip_field(ip::Field::MaxAggregateBytes),
                self.ip.max_aggregate_bytes as u64,
            ),
            (
                ip_field(ip::Field::MaxRetainedOutcomes),
                self.ip.max_retained_outcomes as u64,
            ),
        ] {
            if value == 0 {
                return Err(Error::InvalidLimit {
                    field,
                    value,
                    reason: Constraint::NonZero,
                });
            }
        }
        for (field, expiry) in [
            (tcp_field(tcp::Field::IdleExpiry), self.tcp.idle_expiry),
            (ip_field(ip::Field::IdleExpiry), self.ip.idle_expiry),
        ] {
            if expiry.is_zero() {
                return Err(Error::InvalidLimit {
                    field,
                    value: 0,
                    reason: Constraint::NonZero,
                });
            }
        }
        if let Some((field, value, reason)) = self.tcp.violation() {
            return Err(Error::InvalidLimit {
                field: tcp_field(field),
                value,
                reason,
            });
        }
        if let Some((field, value, reason)) = self.ip.violation() {
            return Err(Error::InvalidLimit {
                field: ip_field(field),
                value,
                reason,
            });
        }
        if self.max_frame_bytes as u64 > self.max_bytes {
            return Err(Error::InvalidLimit {
                field: "max_frame_bytes",
                value: self.max_frame_bytes as u64,
                reason: Constraint::AtMostMaxBytes,
            });
        }
        if self.max_duration.is_zero() {
            return Err(Error::InvalidLimit {
                field: "max_duration",
                value: 0,
                reason: Constraint::NonZero,
            });
        }
        Ok(())
    }

    pub(super) fn capture_budget(&self) -> Result<CaptureBudget, Error> {
        CaptureBudget::new(CaptureLimits {
            max_frames: self.max_frames,
            max_bytes: self.max_bytes,
        })
        .map_err(|error| match error {
            CaptureError::InvalidLimit { field, value } => Error::InvalidLimit {
                field,
                value,
                reason: Constraint::NonZero,
            },
            source => Error::Capture { number: 0, source },
        })
    }
}
