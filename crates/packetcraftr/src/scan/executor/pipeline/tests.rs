// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::super::{ClientExecutor, PipelineEvent, PipelineOptions, Pipelined};
use crate::Stats;
use crate::clock::Clock;
use crate::evidence::ExecutionPermit;
use crate::probe::{Batch, ProbeEndpoint};
use crate::scan::{Probe, Request, Stage};
use crate::test_support::{Call, fake_client};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::{BoundaryError, Classified as _};

fn request() -> Request {
    Request {
        target_sources: Vec::new(),
        max_in_flight: 4,
        targets: crate::target::Target::Address("192.0.2.2".parse().unwrap()).into(),
        udp_payload: bytes::Bytes::new(),
        udp_profiles: Default::default(),
        address_family: crate::target::Family::Any,
        endpoints: vec![ProbeEndpoint::Tcp { port: 80 }],
        discovery: Default::default(),
        attempts: 1,
        adaptive: None,
        timeout: Duration::from_millis(20),
        probes_per_second: None,
        limits: crate::scan::Limits::default(),
        route: Default::default(),
        collection: Default::default(),
    }
}

fn batch(address: u8, sequence: u64) -> Batch<Probe> {
    Batch {
        probes: vec![Probe {
            sequence,
            stage: Stage::Scan,
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, address)),
            scope: None,
            endpoint: ProbeEndpoint::Tcp { port: 80 },
            attempt: 1,
            udp_payload: bytes::Bytes::new(),
            udp_profile: None,
        }],
        timeout: Duration::from_millis(20),
        permit: ExecutionPermit::new(),
        sequence,
    }
}

fn options(host_deadlines: Vec<Option<Instant>>) -> PipelineOptions {
    PipelineOptions {
        max_in_flight: 4,
        probes_per_second: None,
        max_duration: Duration::from_secs(60),
        max_prepared_bytes: 1 << 20,
        max_evidence_frames: 64,
        max_evidence_bytes: 1 << 20,
        host_deadlines,
        preceding: Stats::default(),
    }
}

#[derive(Clone)]
struct StepClock {
    state: Arc<Mutex<(Option<Instant>, Duration)>>,
}

impl StepClock {
    fn stepping(step: Duration) -> Self {
        Self {
            state: Arc::new(Mutex::new((None, step))),
        }
    }
}

impl Clock for StepClock {
    type Error = Infallible;

    fn now(&self) -> Instant {
        let mut state = self.state.lock().expect("step clock");
        let instant = *state.0.get_or_insert_with(Instant::now);
        state.0 = instant.checked_add(state.1);
        instant
    }

    fn sleep(&self, delay: Duration, _: &Deadline) -> Result<(), Self::Error> {
        let mut state = self.state.lock().expect("step clock");
        let now = *state.0.get_or_insert_with(Instant::now);
        state.0 = now.checked_add(delay);
        Ok(())
    }
}

#[test]
fn a_spent_host_deadline_omits_without_traffic_or_evidence() {
    let (client, providers) = fake_client();
    let batches = [batch(2, 0), batch(3, 1)];
    let spent = Instant::now() - Duration::from_millis(1);
    let mut events = Vec::new();
    let mut executor = ClientExecutor::new(&client, &request());
    let stats = executor
        .execute_pipeline(
            &batches,
            options(vec![Some(spent), Some(spent)]),
            &mut |event| {
                events.push(event);
                Ok::<(), BoundaryError>(())
            },
        )
        .expect("omitted entries settle");
    assert_eq!(stats.packets_attempted, 0);
    assert!(
        matches!(
            events.as_slice(),
            [
                PipelineEvent::Omitted { index: 0 },
                PipelineEvent::Omitted { index: 1 }
            ]
        ),
        "expected two omissions, got {events:?}"
    );
    assert!(
        !providers
            .calls()
            .iter()
            .any(|call| matches!(call, Call::Transmit(_))),
        "an omitted entry transmits nothing"
    );
}

#[test]
fn a_mismatched_host_deadline_vector_fails_before_any_provider_call() {
    let (client, providers) = fake_client();
    let batches = [batch(2, 0), batch(3, 1)];
    let mut executor = ClientExecutor::new(&client, &request());
    let error = executor
        .execute_pipeline(
            &batches,
            options(vec![Some(Instant::now() + Duration::from_secs(60))]),
            &mut |_| Ok::<(), BoundaryError>(()),
        )
        .expect_err("deadline metadata must cover every batch");
    assert_eq!(error.classification().code, "policy.scan_pipeline_limit",);
    assert!(providers.calls().is_empty());
}

#[test]
fn a_deadline_spent_before_transmit_omits_that_entry() {
    const STEP: Duration = Duration::from_millis(1);
    let request = request();
    let clock = StepClock::stepping(STEP);
    let client = fake_client().0.with_clock(clock.clone());
    let batches = [batch(2, 0)];
    let mut sent_marker = None;
    let mut executor = ClientExecutor::new(&client, &request);
    executor
        .execute_pipeline(&batches, options(vec![None]), &mut |event| {
            if matches!(event, PipelineEvent::Sent { .. }) {
                sent_marker = Some(clock.now());
            }
            Ok::<(), BoundaryError>(())
        })
        .expect("the control wave sends its entry");
    let sent_marker = sent_marker.expect("the control wave emitted a send");

    let clock = StepClock::stepping(STEP);
    let (client, providers) = fake_client();
    let client = client.with_clock(clock);
    let mut events = Vec::new();
    let mut executor = ClientExecutor::new(&client, &request);
    let stats = executor
        .execute_pipeline(
            &batches,
            options(vec![Some(sent_marker - STEP)]),
            &mut |event| {
                events.push(event);
                Ok::<(), BoundaryError>(())
            },
        )
        .expect("omitted entries settle");
    assert_eq!(stats.packets_attempted, 0);
    assert!(
        matches!(events.as_slice(), [PipelineEvent::Omitted { index: 0 }]),
        "expected the pre-transmit check to omit, got {events:?}"
    );
    assert!(
        !providers
            .calls()
            .iter()
            .any(|call| matches!(call, Call::Transmit(_))),
        "an entry omitted at transmit sent nothing"
    );
}

#[test]
fn a_completed_adaptive_wave_reports_its_sends() {
    let (client, providers) = fake_client();
    let batches = [batch(2, 0)];
    let far = Instant::now() + Duration::from_secs(60);
    let mut events = Vec::new();
    let mut executor = ClientExecutor::new(&client, &request());
    let stats = executor
        .execute_pipeline(&batches, options(vec![Some(far)]), &mut |event| {
            events.push(event);
            Ok::<(), BoundaryError>(())
        })
        .expect("a wave inside its deadline sends");
    assert_eq!(stats.packets_attempted, 1);
    assert_eq!(stats.packets_completed, 1);
    assert!(
        matches!(events[0], PipelineEvent::Sent { index: 0, .. }),
        "the sent entry reports its receipt, got {events:?}"
    );
    assert!(
        providers
            .calls()
            .iter()
            .any(|call| matches!(call, Call::Transmit(_)))
    );
}

#[test]
fn the_adaptive_summary_charges_the_worst_live_wave_bound() {
    let mut options = options(Vec::new());
    let admission = super::AdaptiveAdmission {
        interfaces: Vec::new(),
        track_interfaces: false,
        max_description_bytes: 400,
        max_route_bytes: 2_100,
        max_probe_bytes: 10_000,
    };
    options.max_prepared_bytes = 50_000;
    admission
        .check(16, 32, &options)
        .expect("16*400 + min(16,32)*2100 + 10000 == 50_000");
    options.max_prepared_bytes = 49_999;
    let error = admission
        .check(16, 32, &options)
        .expect_err("one byte under the conservative bound rejects");
    assert_eq!(error.classification().code, "policy.scan_pipeline_limit");
    options.max_prepared_bytes = 18_500;
    admission
        .check(16, 1, &options)
        .expect("16*400 + min(16,1)*2100 + 10000 == 18_500");
    options.max_prepared_bytes = 18_499;
    assert!(admission.check(16, 1, &options).is_err());
}
