// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::scan::{adaptive, inference};

#[test]
fn local_deadline_is_unavailable_for_both_control_and_port_inference() {
    let mut probe = ProbeEvidence {
        sequence: 7,
        stage: Stage::Scan,
        endpoint: "192.0.2.1:80".parse().unwrap(),
        scope: None,
        attempt: 1,
        attempted: true,
        connect_succeeded: None,
        outcome: Outcome::DeadlineExpired,
        scheduled_at: SystemTime::UNIX_EPOCH,
        finished_at: None,
        elapsed: Duration::from_secs(1),
        local: None,
        error: None,
    };
    for outcome in [Outcome::DeadlineExpired, Outcome::LocalError] {
        probe.outcome = outcome;
        assert!(matches!(
            connect_outcome(&probe),
            adaptive::Outcome::Aborted
        ));
        let inference = inference::connect([(probe.sequence, outcome)]);
        assert!(inference.state.is_none());
        assert_eq!(inference.failed, [7]);
        assert!(inference.supporting.is_empty());
    }
    probe.outcome = Outcome::TimedOut;
    assert!(matches!(connect_outcome(&probe), adaptive::Outcome::Silent));
    let silent = inference::connect([(7, probe.outcome)]);
    assert_eq!(silent.rule, inference::Rule::ConnectTimedOut);
    assert_eq!(silent.state, Some(inference::State::Filtered));
    assert_eq!(silent.supporting, [7]);
    assert!(silent.failed.is_empty());
    for (outcome, state, rule) in [
        (
            Outcome::Connected,
            inference::State::Open,
            inference::Rule::ConnectConnected,
        ),
        (
            Outcome::Refused,
            inference::State::Closed,
            inference::Rule::ConnectRefused,
        ),
    ] {
        probe.outcome = outcome;
        let adaptive::Outcome::Reply {
            latency,
            responder,
            control,
        } = connect_outcome(&probe)
        else {
            panic!("a completed connection response remains reply evidence");
        };
        assert_eq!(latency, probe.elapsed);
        assert_eq!(responder, probe.endpoint.ip());
        assert!(!control);
        let evidence = inference::connect([(7, outcome)]);
        assert_eq!(evidence.rule, rule);
        assert_eq!(evidence.state, Some(state));
        assert_eq!(evidence.supporting, [7]);
        assert!(evidence.failed.is_empty());
    }
    probe.attempted = false;
    assert!(matches!(
        connect_outcome(&probe),
        adaptive::Outcome::Omitted
    ));
}
