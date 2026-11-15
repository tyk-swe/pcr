// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::decode::DecodedPacket;
use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::packet::Packet;

use super::{Batch, BatchEvidence, Classifier, Evidence, Outcome, Sequenced, run_batches};
use crate::clock::SystemClock;
use crate::engine::execution::Executor;
use crate::error::{Failure, FromFailure};
use crate::evidence::{ExecutionPermit, Limits, SentPacket};
use crate::probe::Workflow;

struct Unit;

impl Sequenced for Unit {
    fn sequence(&self) -> u64 {
        0
    }
}

struct Silent;

impl Classifier for Silent {
    type Probe = Unit;
    type Observation = ();
    type Event = ();

    fn sent_matches(&self, _: &Unit, _: &Packet) -> bool {
        true
    }
    fn classify(&self, _: &Unit, _: &SentPacket, _: &DecodedPacket) -> Option<()> {
        None
    }
    fn rank(&self, _: &()) -> u8 {
        0
    }
    fn responder(&self, _: &()) -> IpAddr {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    }
    fn evidence(&mut self, _: &Unit, _: &SentPacket, _: Outcome<()>) {}
    fn undecoded(&self, _: &[Unit], _: Frame) {}
    fn diagnostic(&self, _: Diagnostic) {}
}

#[derive(Debug)]
struct Failed(Failure);

impl FromFailure for Failed {
    fn from_failure(_: u64, failure: Failure) -> Self {
        Self(failure)
    }
}

/// Answers each batch with empty evidence carrying `permit(batch)`.
struct Answering<P> {
    permit: P,
    seen: Vec<(Duration, ExecutionPermit)>,
}

impl<P: FnMut(&Batch<Unit>) -> ExecutionPermit> Executor<Batch<Unit>> for Answering<P> {
    fn execute(&mut self, batch: &Batch<Unit>) -> Result<Evidence, BoundaryError> {
        self.seen.push((batch.timeout, batch.permit()));
        Ok(Evidence {
            observation_quality: None,
            permit: (self.permit)(batch),
            sent: Vec::new(),
            responses: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: Default::default(),
        })
    }
}

fn run<P: FnMut(&Batch<Unit>) -> ExecutionPermit>(
    batches: Vec<Batch<Unit>>,
    executor: &mut Answering<P>,
) -> Result<crate::Stats, Failed> {
    let mut evidence = BatchEvidence::new_with_retention_limits(
        Workflow::Scan,
        Limits::default(),
        Limits::default(),
        Silent,
        |(), _: &Deadline| Ok::<(), Failed>(()),
    );
    run_batches(
        batches,
        None,
        &mut Deadline::new(Duration::from_secs(1)),
        &mut SystemClock,
        executor,
        &mut evidence,
    )
}

#[test]
fn executors_see_a_fresh_grant_bounded_by_the_deadline() {
    let planned = [
        Batch::new(1, Vec::new(), Duration::from_secs(60)),
        Batch::new(2, Vec::new(), Duration::from_millis(10)),
    ];
    let planned_permits = planned.each_ref().map(Batch::permit);
    let mut executor = Answering {
        permit: Batch::permit,
        seen: Vec::new(),
    };
    run(planned.into(), &mut executor).unwrap();

    let [
        (first_timeout, first_permit),
        (second_timeout, second_permit),
    ] = executor.seen.as_slice()
    else {
        panic!("expected one execution per batch: {:?}", executor.seen);
    };
    assert!(*first_timeout <= Duration::from_secs(1));
    assert_eq!(*second_timeout, Duration::from_millis(10));
    assert_ne!(first_permit, second_permit);
    assert!(!planned_permits.contains(first_permit));
    assert!(!planned_permits.contains(second_permit));
}

#[test]
fn evidence_under_another_permit_is_rejected() {
    let planned = Batch::new(1, Vec::new(), Duration::from_millis(10));
    let planned_permit = planned.permit();
    let mut executor = Answering {
        permit: |_: &Batch<Unit>| planned_permit,
        seen: Vec::new(),
    };
    let Failed(failure) = run(vec![planned], &mut executor).unwrap_err();
    assert!(
        matches!(
            failure,
            Failure::InvalidEvidence(crate::evidence::Error::PermitMismatch)
        ),
        "{failure:?}"
    );
}
