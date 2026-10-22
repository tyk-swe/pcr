// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The boundary between the scan engine and the executor that sends its
//! probes: pipelined execution, adaptive feeds, and neighbor resolution.

use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;

use super::AdaptiveAdmission;
use crate::Stats;
use crate::engine::execution::Executor;
use crate::evidence::SentPacket;
use crate::probe::{Batch, Evidence};
use crate::scan::Probe;
use crate::scan::discovery::Neighbor;
use crate::target::SelectedAddress;

#[derive(Clone, Debug)]
pub(crate) struct PipelineOptions {
    pub(crate) max_in_flight: usize,
    pub(crate) probes_per_second: Option<u32>,
    pub(crate) max_duration: Duration,
    /// Exact operation control, including inherited cancellation and ceilings.
    pub(crate) control: Deadline,
    pub(crate) max_prepared_bytes: usize,
    pub(crate) max_evidence_frames: usize,
    pub(crate) max_evidence_bytes: usize,
    /// The operation's statistics before this pipeline, which its failure
    /// reports with its own.
    pub(crate) preceding: Stats,
}

#[derive(Clone, Debug)]
pub(crate) enum PipelineEvent {
    Sent {
        index: usize,
        sent: Arc<SentPacket>,
    },
    Omitted {
        index: usize,
    },
    Completed {
        index: usize,
        execution: Evidence,
    },
    Undecoded {
        frame: packetcraftr_core::frame::Frame,
    },
    /// A correlated frame no probe outcome carries.
    Unattributed {
        frame: packetcraftr_core::frame::Frame,
        attribution: crate::scan::Attribution,
        sequence: Option<u64>,
    },
    Diagnostic(packetcraftr_core::diagnostic::Diagnostic),
    Qualification(crate::scan::Qualification),
}

/// One controller-selected attempt. The driver owns only its bounded active
/// and recent descriptors; IDs are stable for the entire stage.
pub(crate) struct PipelineBatch {
    pub(crate) index: usize,
    pub(crate) batch: Batch<Probe>,
    pub(crate) host_deadline: Option<std::time::Instant>,
}

pub(crate) struct PipelinePoll {
    pub(crate) batches: Vec<PipelineBatch>,
    pub(crate) next_ready: Option<std::time::Instant>,
    pub(crate) done: bool,
}

/// The raw controller's private substitution boundary with acquisition. It
/// selects work and consumes each settlement immediately; capture never chooses
/// a retry, endpoint, host window or inference policy on its own.
pub(crate) trait PipelineFeed {
    fn poll(
        &mut self,
        capacity: usize,
        now: std::time::Instant,
    ) -> Result<PipelinePoll, BoundaryError>;
    fn event(&mut self, event: PipelineEvent) -> Result<(), BoundaryError>;
}

pub(crate) trait Pipelined: Executor<Batch<Probe>> {
    fn execute_stream(
        &mut self,
        options: PipelineOptions,
        admission: &AdaptiveAdmission,
        attempts: usize,
        feed: &mut dyn PipelineFeed,
    ) -> Result<Stats, BoundaryError>;

    fn execute_pipeline(
        &mut self,
        batches: &[Batch<Probe>],
        options: PipelineOptions,
        emit: &mut dyn FnMut(PipelineEvent) -> Result<(), BoundaryError>,
    ) -> Result<Stats, BoundaryError>;

    /// Admits a pipelined stage's probes as [`Self::execute_pipeline`]
    /// would, sending nothing, so its preparation limit fails before any
    /// traffic.
    fn admit_pipeline(
        &mut self,
        batches: &[Batch<Probe>],
        options: &PipelineOptions,
    ) -> Result<(), BoundaryError>;

    fn admit_adaptive_pipeline(
        &mut self,
        batches: &[Batch<Probe>],
        options: &PipelineOptions,
        summary: &mut AdaptiveAdmission,
    ) -> Result<(), BoundaryError>;

    /// Sends at most one ARP or NDP request for `target` and reports what
    /// it learned with the exchange's statistics. A routed target's next hop
    /// is never sent a request.
    fn resolve_neighbor(
        &mut self,
        target: &SelectedAddress,
        timeout: Duration,
        deadline: &Deadline,
    ) -> Result<(Neighbor, Stats), BoundaryError>;

    /// Resolves the neighbor `target`'s probes send their frames to, its own
    /// or its gateway's, unless the operation already knows it, and reports
    /// the request's statistics. A stage resolves its targets before any
    /// probe arms a capture, so each probe's materialization finds the
    /// answer cached.
    fn resolve_next_hop(
        &mut self,
        target: &SelectedAddress,
        deadline: &Deadline,
    ) -> Result<NextHopResolution, BoundaryError>;

    /// Whether resolving `target`'s neighbor, explicitly as discovery does or
    /// for its probes, would send a request, so the engine waits out a pause
    /// owed by an earlier transmission only before one.
    fn requests_neighbor(
        &mut self,
        target: &SelectedAddress,
        explicit: bool,
        deadline: &Deadline,
    ) -> Result<bool, BoundaryError>;

    /// Learns whether any probe of the operation resolves a link-layer
    /// neighbor, before the first resolution or exchange. Bounds that could
    /// not hold a reply then never apply to a resolver no probe uses.
    fn resolves_neighbors(&mut self, resolves: bool);
}

/// What resolving a target's next hop found.
#[derive(Debug, Default)]
pub(crate) struct NextHopResolution {
    /// The requests it sent.
    pub(crate) stats: Stats,
    /// Why no frame can reach the target: its next hop stayed silent.
    pub(crate) silence: Option<BoundaryError>,
}
