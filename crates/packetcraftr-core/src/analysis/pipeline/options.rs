// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The per-run plan and caller-provided options a pipeline run consumes.

use crate::analysis::reassembly::ip::OverlapPolicy;
use crate::filter::Filter;

use super::limits::Limits;

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
    /// Keeps only the frames of one conversation, applied with the filter
    /// and matching exactly what `tcp.stream == N` or `udp.stream == N`
    /// matches. Indices are assigned before selection, so the plan must
    /// index the selected transport; [`Session`](crate::analysis::Session) derives
    /// such a plan from its selector.
    pub stream: Option<crate::analysis::StreamRef>,
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
