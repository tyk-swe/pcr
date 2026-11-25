// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The boundary between the scan engine and the executor that sends its
//! probes: pipelined execution, adaptive feeds, and neighbor resolution.

use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;

use crate::Stats;
use crate::evidence::SentPacket;
use crate::probe::{Batch, Evidence};
use crate::scan::Probe;

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

/// What resolving a target's next hop found.
#[derive(Debug, Default)]
pub(crate) struct NextHopResolution {
    /// The requests it sent.
    pub(crate) stats: Stats,
    /// Why no frame can reach the target: its next hop stayed silent.
    pub(crate) silence: Option<BoundaryError>,
}
