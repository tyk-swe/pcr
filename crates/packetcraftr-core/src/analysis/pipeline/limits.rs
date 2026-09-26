// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use crate::analysis::reassembly::ip::{self, Limits as IpReassemblyLimits, OverlapPolicy};
use crate::analysis::reassembly::tcp::{self, Limits as TcpReassemblyLimits};
use crate::capture_file::{
    Budget as CaptureBudget, DEFAULT_STREAM_BYTES, DEFAULT_STREAM_FRAMES, Error as CaptureError,
    Limits as CaptureLimits,
};
use crate::filter::Filter;
use crate::frame::DEFAULT_SIZE_LIMIT;

use crate::analysis::{Constraint, Error};

const DEFAULT_MAX_ANALYSIS_FLOWS: usize = 8_192;
/// A TCP conversation occupies one reassembly flow per direction.
pub(super) const DIRECTIONS_PER_CONVERSATION: usize = 2;

/// The offline analysis name of a TCP reassembly limit.
const fn tcp_field(field: tcp::Field) -> &'static str {
    match field {
        tcp::Field::MaxFlows => "max_tcp_flows",
        tcp::Field::MaxBytesPerFlow => "max_tcp_bytes_per_flow",
        tcp::Field::MaxAggregateBytes => "max_tcp_reassembly_bytes",
        tcp::Field::MaxSegmentsPerFlow => "max_tcp_segments_per_flow",
        tcp::Field::IdleExpiry => "tcp_idle_expiry",
    }
}

/// The offline analysis name of an IP reassembly limit.
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

/// Complete per-run resource limits, including both reassembly engines. Frame
/// and byte limits count all input, including filtered frames; duration bounds
/// processing time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Physical source-set allocations, including references retained by collectors.
    pub max_provenance_bytes: usize,
    /// Physical input frames. This also bounds persistent capture-scope
    /// metadata: one frame can introduce at most three exact scope identities.
    pub max_frames: u64,
    pub max_bytes: u64,
    pub max_frame_bytes: usize,
    /// Capture-global cumulative distinct conversations per transport. Expiry
    /// releases payload state, not these indices. A TCP conversation additionally
    /// occupies one reassembly flow per direction, so the default
    /// [`tcp.max_flows`](TcpReassemblyLimits::max_flows) is twice this default.
    pub max_flows: usize,
    /// Conservative retained scope/path metadata charge, separate from payload state.
    pub max_scope_bytes: usize,
    /// The TCP reassembler's limits. Its aggregate byte ceiling is the largest
    /// single memory ceiling an analysis run has.
    pub tcp: TcpReassemblyLimits,
    /// The IP fragment reassembler's limits. Its aggregate byte ceiling also
    /// covers derived cascade buffers.
    pub ip: IpReassemblyLimits,
    pub max_duration: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_provenance_bytes: 16 * 1024 * 1024,
            max_frames: DEFAULT_STREAM_FRAMES,
            max_bytes: DEFAULT_STREAM_BYTES,
            max_frame_bytes: DEFAULT_SIZE_LIMIT,
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
    /// Rejects a zero limit, a per-frame byte limit above `max_bytes`, and
    /// any reassembly limit its engine refuses. Reassembly fields are named
    /// as the offline analysis options spell them, such as
    /// `max_tcp_bytes_per_flow`.
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

    /// The input frame and byte budget. Its limits are this struct's
    /// `max_frames` and `max_bytes`, so a refusal names those fields.
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

/// Required optional stages, independent of input accounting. The default
/// preserves full capture-global indexing and IP reconstruction semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub ip_reassembly: bool,
    pub tcp_index: bool,
    pub udp_index: bool,
}

impl Default for Plan {
    fn default() -> Self {
        Self {
            ip_reassembly: true,
            tcp_index: true,
            udp_index: true,
        }
    }
}

impl Plan {
    /// Only the conversation indexes requested by compiled filters/projections,
    /// retaining IP reconstruction when needed for canonical stream numbering.
    /// IDs include reconstructed conversations before selection. Consumers use
    /// [`super::FrameRecord::physical_context`] to select and project only
    /// physical evidence; this plan does not push filters upstream.
    pub fn physical(requirements: crate::filter::Requirements) -> Self {
        Self {
            ip_reassembly: requirements.tcp_stream || requirements.udp_stream,
            tcp_index: requirements.tcp_stream,
            udp_index: requirements.udp_stream,
        }
    }

    /// Every stage either plan requires. Indexing keeps IP reconstruction, so
    /// the union can never produce a plan that renumbers streams.
    #[must_use]
    pub fn union(self, other: Self) -> Self {
        let tcp_index = self.tcp_index || other.tcp_index;
        let udp_index = self.udp_index || other.udp_index;
        Self {
            ip_reassembly: self.ip_reassembly || other.ip_reassembly || tcp_index || udp_index,
            tcp_index,
            udp_index,
        }
    }
}

/// What one analysis run computes beyond dispatching matched frames.
#[derive(Clone, Debug, Default)]
pub struct Options<'a> {
    pub plan: Plan,
    /// Shared invocation ceiling; a local phase limit may tighten it.
    pub deadline: Option<std::sync::Arc<crate::budget::Deadline>>,
    /// Track contributing physical records through nested IP reconstruction.
    pub track_sources: bool,
    pub cancellation: Option<crate::budget::Cancellation>,
    /// Keeps only matching frames; compiled by the caller so filter mistakes
    /// surface before any input is read. Conversation indices are assigned
    /// before the filter runs, so `tcp.stream` and `udp.stream` resolve.
    /// This is input selection for TCP reassembly, not session presentation:
    /// IP reconstruction sees all input, but TCP and collectors see only matches.
    /// `tcp.stream == 7` preserves a conversation; `tls.sni == "example.test"`
    /// removes its ServerHello and segmented handshake bytes. Apply TLS status
    /// or SNI selection to completed sessions instead. Matching observations may
    /// first expose stream indices out of numerical order.
    pub filter: Option<&'a Filter>,
    /// Inclusive capture-time bounds applied with the filter. Comparison uses
    /// the timestamp's full precision and assumes nothing about ordering, so
    /// regressing clocks still select by value. Like the filter, bounds apply
    /// after IP reconstruction and stream indexing for timestamped frames,
    /// even when they are excluded. All physical frames consume read budgets.
    /// Records without timestamps are skipped when bounds are set; without
    /// bounds they still fail the run before selection.
    pub time_bounds: Option<crate::frame::TimeBounds>,
    /// Drives bounded TCP reassembly over the matched frames and delivers
    /// its events with each record. Costs memory proportional to reordering,
    /// so commands that only count leave it off.
    pub tcp_events: bool,
    /// Deterministic policy applied when IP fragments carry conflicting bytes.
    pub ip_overlap: OverlapPolicy,
    pub limits: Limits,
}
