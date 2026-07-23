use std::net::Ipv4Addr;
use std::result::Result;

use super::super::*;
use super::support::{FixedAuthorizer, MixedHopExecutor, NoopClock, udp_traceroute_request};
use crate::protocol::builtin::registry as default_registry;

#[test]
fn slow_executor_expires_before_the_next_traceroute_hop() {
    struct SlowExecutor {
        calls: usize,
    }

    impl TracerouteExecutor for SlowExecutor {
        fn execute(
            &mut self,
            batch: &TracerouteBatch,
        ) -> Result<TracerouteBatchExecution, BoundaryError> {
            self.calls += 1;
            std::thread::sleep(Duration::from_millis(20));
            MixedHopExecutor.execute(batch)
        }
    }

    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let mut request = udp_traceroute_request(Target::Address(destination));
    request.probes_per_hop = 1;
    request.timeout = Duration::from_millis(1);
    request.limits.max_duration = Duration::from_millis(5);
    let mut executor = SlowExecutor { calls: 0 };

    let error = traceroute(
        &request,
        &mut FixedAuthorizer {
            address: destination,
            operations: Vec::new(),
        },
        &default_registry().unwrap(),
        &mut executor,
        &mut NoopClock::default(),
    )
    .unwrap_err();

    assert!(matches!(error, TracerouteError::DurationLimit { .. }));
    assert_eq!(executor.calls, 1);
}

#[test]
fn candidate_heavy_hop_expires_before_the_next_traceroute_execution() {
    struct CandidateHeavyExecutor {
        calls: usize,
    }

    impl TracerouteExecutor for CandidateHeavyExecutor {
        fn execute(
            &mut self,
            batch: &TracerouteBatch,
        ) -> Result<TracerouteBatchExecution, BoundaryError> {
            self.calls += 1;
            let mut execution = MixedHopExecutor.execute(batch)?;
            let candidate = execution.unsolicited.pop().unwrap();
            execution.unsolicited = vec![candidate; DEFAULT_CAPTURE_QUEUE_FRAMES];
            execution.stats.elapsed = Duration::ZERO;
            Ok(execution)
        }
    }

    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let mut request = udp_traceroute_request(Target::Address(destination));
    request.probes_per_hop = 1;
    request.timeout = Duration::from_nanos(1);
    request.limits.max_duration = Duration::from_millis(5);
    let mut executor = CandidateHeavyExecutor { calls: 0 };

    let error = traceroute(
        &request,
        &mut FixedAuthorizer {
            address: destination,
            operations: Vec::new(),
        },
        &default_registry().unwrap(),
        &mut executor,
        &mut NoopClock::default(),
    )
    .unwrap_err();

    assert!(matches!(error, TracerouteError::DurationLimit { .. }));
    assert_eq!(executor.calls, 1);
}

#[test]
fn unsolicited_hop_response_after_the_deadline_cannot_finish_the_trace() {
    struct LateHopExecutor;

    impl TracerouteExecutor for LateHopExecutor {
        fn execute(
            &mut self,
            batch: &TracerouteBatch,
        ) -> Result<TracerouteBatchExecution, BoundaryError> {
            let mut execution = MixedHopExecutor.execute(batch)?;
            for response in &mut execution.unsolicited {
                response.frame.timestamp += Duration::from_secs(1);
            }
            Ok(execution)
        }
    }

    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let operation = udp_traceroute_request(Target::Address(destination));
    let result = traceroute(
        &operation,
        &mut FixedAuthorizer {
            address: destination,
            operations: Vec::new(),
        },
        &default_registry().unwrap(),
        &mut LateHopExecutor,
        &mut NoopClock::default(),
    )
    .unwrap();

    assert_eq!(result.completion, TracerouteCompletion::Timeout);
    assert!(
        result
            .hops
            .iter()
            .flat_map(|hop| &hop.probes)
            .all(|probe| { probe.status == TracerouteProbeStatus::Timeout })
    );
}

#[test]
fn matched_response_deadline_uses_monotonic_latency_despite_wall_clock_skew() {
    struct PreSendMatchedExecutor;

    impl TracerouteExecutor for PreSendMatchedExecutor {
        fn execute(
            &mut self,
            batch: &TracerouteBatch,
        ) -> Result<TracerouteBatchExecution, BoundaryError> {
            let mut execution = MixedHopExecutor.execute(batch)?;
            let mut response = execution.unsolicited.remove(0);
            response.frame.timestamp = execution.sent_evidence[0]
                .timestamp
                .checked_sub(Duration::from_millis(1))
                .unwrap();
            execution.responses.push(TracerouteMatchedResponse {
                request_index: 0,
                response,
                latency: Duration::from_millis(1),
            });
            Ok(execution)
        }
    }

    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let result = traceroute(
        &udp_traceroute_request(Target::Address(destination)),
        &mut FixedAuthorizer {
            address: destination,
            operations: Vec::new(),
        },
        &default_registry().unwrap(),
        &mut PreSendMatchedExecutor,
        &mut NoopClock::default(),
    )
    .unwrap();

    let evidence = &result.hops[0].probes[0];
    assert_eq!(evidence.status, TracerouteProbeStatus::Response);
    assert!(evidence.received_at.unwrap() < evidence.sent_at);
}
