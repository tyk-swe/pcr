// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{client, error, workflow};

#[test]
fn boundary_errors_keep_domain_paths() {
    let classification = error::Classification::new("test.boundary", error::Kind::Io, None);
    let boundary = workflow::BoundaryError::new(
        "boundary failed",
        classification,
        vec!["underlying failure".to_owned()],
    );

    assert_eq!(boundary.to_string(), "boundary failed");
    assert_eq!(error::Classified::classification(&boundary), classification);
    assert_eq!(error::Classified::causes(&boundary), ["underlying failure"]);
    let _: &dyn std::error::Error = &boundary;

    let _: workflow::scan::ExecutionError = boundary.clone();
    let _: workflow::dns::ExecutionError = boundary.clone();
    let _: workflow::traceroute::ExecutionError = boundary.clone();
    let _: workflow::fuzz::AuthorizationError = boundary.clone();
    let _: workflow::fuzz::ExecutionError = boundary.clone();
    let _: workflow::replay::AuthorizationError = boundary.clone();
    let _: workflow::target::AuthorizationError = boundary;
}

#[test]
fn execution_stats_keep_domain_paths() {
    let client_stats = client::Stats::default();
    let workflow_stats: workflow::Stats = client_stats;
    let _: workflow::fuzz::ExecutionStats = workflow_stats;
}
