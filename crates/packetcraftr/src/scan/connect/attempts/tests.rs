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
        scheduled_at: SystemTime::now(),
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
    assert_eq!(
        inference::connect([(7, probe.outcome)]).rule,
        inference::Rule::ConnectTimedOut
    );
    probe.attempted = false;
    assert!(matches!(
        connect_outcome(&probe),
        adaptive::Outcome::Omitted
    ));
}
