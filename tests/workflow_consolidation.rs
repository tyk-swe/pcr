// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{error, workflow};
use serde_json::json;

#[test]
fn boundary_error_preserves_its_public_error_contract() {
    let classification = error::Classification::new("test.boundary", error::Kind::Io, None);
    let boundary = workflow::BoundaryError::new(
        "boundary failed",
        classification,
        vec!["underlying failure".to_owned()],
    );

    assert_eq!(boundary.to_string(), "boundary failed");
    assert_eq!(error::Classified::classification(&boundary), classification);
    assert_eq!(error::Classified::causes(&boundary), ["underlying failure"]);
    assert!(std::error::Error::source(&boundary).is_none());
    assert_eq!(
        serde_json::to_value(packetcraftr::output::envelope::Error::classified(&boundary)).unwrap(),
        json!({
            "code": "test.boundary",
            "kind": "io",
            "message": "boundary failed",
            "causes": ["underlying failure"]
        })
    );
    let _: &dyn std::error::Error = &boundary;
}

#[test]
fn workflow_stats_preserve_their_public_contract() {
    let stats = workflow::Stats {
        packets_attempted: 2,
        packets_completed: 1,
        bytes: 64,
        ..workflow::Stats::default()
    };

    assert_eq!(stats.packets_attempted, 2);
    assert_eq!(stats.packets_completed, 1);
    assert_eq!(stats.bytes, 64);
}
