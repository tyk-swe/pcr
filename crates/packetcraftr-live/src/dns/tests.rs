// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, Instant};

use crate::probe::evidence::response_within_deadline;

#[test]
fn dns_freshness_requires_the_provider_ingress_marker() {
    let sent = Instant::now();
    assert!(!response_within_deadline(
        Some(Duration::from_millis(1)),
        None,
        sent,
        Duration::from_secs(1),
    ));
}
