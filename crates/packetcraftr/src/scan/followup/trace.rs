// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The optional trace stage of a scan.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use packetcraftr_core::error::BoundaryError;

use crate::clock::Clock;
use crate::evidence;
use crate::providers::{PacketProviders, TargetProviders};
use crate::scan;
use crate::target::{ScopedAddress, Target};
use crate::traceroute::hosts;
use crate::{Client, traceroute};

use super::Error;
use super::request::Trace;

/// The trace request every scanned host shares, validated before any probe.
pub(super) struct Stage {
    pub(super) template: hosts::Request,
}

/// The evidence the scan already holds against the shared budget, as scalar
/// counts: streaming keeps the counts even though its tracker strips the
/// matched response frames. Retained bytes stay authoritative on
/// `scan::Aggregate::retained_evidence_bytes`.
#[derive(Clone, Copy, Default)]
pub(super) struct Retained {
    pub(super) frames: usize,
    pub(super) undecoded: usize,
}

impl Retained {
    /// Counts the retained evidence a complete aggregate describes: the
    /// matched response frames, the undecoded frames, and the unattributed
    /// frames. A host's probe references name the same discovery evidence and
    /// are not counted again.
    #[cfg(test)]
    pub(super) fn of(scan: &scan::Aggregate) -> Self {
        Self {
            frames: scan
                .discovery
                .iter()
                .chain(scan.endpoints.iter().flat_map(|endpoint| &endpoint.probes))
                .filter(|probe| probe.response.is_some())
                .count()
                .saturating_add(scan.undecoded.len())
                .saturating_add(scan.unattributed.len()),
            undecoded: scan.undecoded.len(),
        }
    }

    /// Counts one published scan event's retained evidence: a probe's
    /// response frame, or one undecoded or unattributed frame. A metadata
    /// `reply` without a `response` frame holds none, and `Sent` and
    /// `Diagnostic` events retain nothing.
    pub(super) fn observe(&mut self, event: &scan::Event) {
        match event {
            scan::Event::Probe { probe, .. } if probe.response.is_some() => {
                self.frames = self.frames.saturating_add(1);
            }
            scan::Event::Undecoded { .. } => {
                self.frames = self.frames.saturating_add(1);
                self.undecoded = self.undecoded.saturating_add(1);
            }
            scan::Event::Unattributed { .. } => {
                self.frames = self.frames.saturating_add(1);
            }
            _ => {}
        }
    }
}

pub(super) struct Streamed {
    pub(super) report: hosts::Report,
    pub(super) last_sent: Option<Instant>,
}

impl Stage {
    pub(super) fn new(trace: &Trace, scan: &scan::Request) -> Result<Self, Error> {
        if trace
            .runtime
            .as_ref()
            .is_some_and(|runtime| runtime.capacity() == 0)
        {
            return Err(traceroute::Error::InvalidLimit {
                field: "runtime.capacity",
                value: 0,
                reason: "trace publication requires at least one worker slot".to_owned(),
            }
            .into());
        }
        let template = hosts::Request {
            targets: scan.targets.clone(),
            max_targets: scan.limits.max_targets,
            first_sequence: 0,
            resolved_targets: None,
            address_family: scan.address_family,
            strategy: trace.strategy,
            observed: Vec::new(),
            source_port: None,
            payload_size: 0,
            dont_fragment: false,
            dscp: 0,
            first_hop: trace.first_hop,
            max_hops: trace.max_hops,
            probes_per_hop: trace.attempts,
            timeout: scan.timeout,
            probes_per_second: scan.probes_per_second,
            paced_after: None,
            reuse: trace.reuse,
            limits: traceroute::Limits {
                max_probes: trace.max_probes,
                max_duration: scan.limits.max_duration,
                evidence: scan.limits.evidence,
            },
            route: scan.route.clone(),
            collection: scan.collection.clone(),
        };
        template.validate()?;
        Ok(Self { template })
    }

    /// The request for the scan's hosts: one exact declaration each, in host
    /// order, the scan's own observations, what remains of its duration at
    /// `now`, and the evidence budget the scan has not already retained.
    pub(super) fn request(
        &self,
        scan: &scan::Aggregate,
        retained: Retained,
        started: Instant,
        now: Instant,
        last_sent: Option<Instant>,
    ) -> Result<hosts::Request, Error> {
        let resolved = scan
            .hosts
            .iter()
            .map(|host| {
                Ok(match (&host.scope, host.address) {
                    (Some(scope), std::net::IpAddr::V6(address)) => {
                        Target::ScopedAddress(ScopedAddress::new(address, scope.zone.clone())?)
                    }
                    _ => Target::Address(host.address),
                })
            })
            .collect::<Result<_, Error>>()?;
        let observed = hosts::observed(scan);
        let covered: std::collections::HashSet<_> =
            observed.iter().map(|observed| observed.address).collect();
        // A host only sends trace probes when it is unscoped and an
        // observation or the fallback strategy covers it. When no host can
        // send, the trace retains nothing, so the scan's evidence stays
        // available to report the not_traced outcomes instead of erroring.
        let sends = scan.hosts.iter().any(|host| {
            host.scope.is_none()
                && (covered.contains(&host.address) || self.template.strategy.is_some())
        });
        let (limits, collection) = if sends {
            let template = self.template.limits.evidence;
            let evidence = evidence::Limits {
                max_frames: template.max_frames.saturating_sub(retained.frames),
                max_bytes: template
                    .max_bytes
                    .saturating_sub(scan.retained_evidence_bytes),
                max_undecoded: template.max_undecoded.saturating_sub(retained.undecoded),
            };
            let limits = traceroute::Limits {
                evidence: evidence::Limits {
                    max_undecoded: evidence.max_undecoded.min(evidence.max_frames),
                    ..evidence
                },
                ..self.template.limits
            };
            // The queues keep only what the shared budget leaves, never more
            // than the workflow configured.
            let mut collection = self.template.collection.clone();
            collection.capture.max_frames = collection
                .capture
                .max_frames
                .min(limits.evidence.max_frames);
            collection.capture.max_bytes =
                collection.capture.max_bytes.min(limits.evidence.max_bytes);
            collection.max_responses = collection.max_responses.min(collection.capture.max_frames);
            collection.max_unmatched_frames = collection
                .max_unmatched_frames
                .min(collection.capture.max_frames);
            (limits, collection)
        } else {
            (self.template.limits, self.template.collection.clone())
        };
        // The marker is monotonic from the sending stage: a scan that sent
        // anything marks now, so the first trace batch conservatively owes a
        // full --rate interval.
        let request = hosts::Request {
            // The bounded declaration stays the scan's original; the exact
            // hosts already resolved hand off as numeric targets.
            resolved_targets: Some(resolved),
            first_sequence: Self::next_sequence(scan)?,
            observed,
            paced_after: last_sent,
            limits: traceroute::Limits {
                max_duration: limits
                    .max_duration
                    .saturating_sub(now.saturating_duration_since(started))
                    .max(Duration::from_nanos(1)),
                ..limits
            },
            collection,
            ..self.template.clone()
        };
        request.validate()?;
        Ok(request)
    }

    /// One past the scan's last probe sequence, so the trace continues its
    /// namespace and no trace probe collides with an identifier the scan's
    /// evidence already cites.
    fn next_sequence(scan: &scan::Aggregate) -> Result<u64, Error> {
        let last = scan
            .discovery
            .iter()
            .chain(
                scan.endpoints
                    .iter()
                    .flat_map(|endpoint| endpoint.probes.iter()),
            )
            .map(|probe| probe.sequence)
            .max();
        match last {
            Some(u64::MAX) => Err(traceroute::Error::InvalidLimit {
                field: "first_sequence",
                value: u64::MAX,
                reason: "the scan's probe sequences leave none for the trace".to_owned(),
            }
            .into()),
            Some(last) => Ok(last + 1),
            None => Ok(0),
        }
    }

    pub(super) fn stream<P, K>(
        &self,
        client: &Client<P, K>,
        scan: &scan::Aggregate,
        retained: Retained,
        started: Instant,
        last_sent: Option<Instant>,
        emit: impl FnMut(hosts::Event) -> Result<(), BoundaryError> + Send + 'static,
    ) -> Result<Streamed, Error>
    where
        P: PacketProviders + TargetProviders,
        K: Clock,
    {
        let request = self.request(scan, retained, started, client.now(), last_sent)?;
        let latest = Arc::new(Mutex::new(None::<Instant>));
        let observed = Arc::clone(&latest);
        let settled = client.clock.clone();
        let mut emit = emit;
        // The trace runs in the policy allowance the scan left over, not a
        // fresh one.
        let client = client.with_remaining_budget(&scan.stats);
        let report = client.trace_hosts(request, move |event: hosts::Event| {
            // The probe's wall-clock sent_at is evidence, not a pacing
            // marker: the monotonic marker is when its event settled.
            if let hosts::Event::Probe(_) = &event {
                let mut latest = observed.lock().unwrap_or_else(PoisonError::into_inner);
                *latest = Some(settled.now());
            }
            emit(event)
        })?;
        let last_sent = *latest.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(Streamed { report, last_sent })
    }
}
