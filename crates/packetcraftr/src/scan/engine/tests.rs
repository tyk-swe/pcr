// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use super::*;
use crate::scan::adaptive::Adaptive;
use crate::target::SelectedAddress;

fn adaptive_scheduler(host_timeout: Duration) -> Scheduler {
    let config = Adaptive {
        min_timeout: Duration::from_millis(1),
        max_timeout: Duration::from_secs(1),
        min_window: 1,
        initial_window: 1,
        host_timeout,
        retry_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(1),
    };
    Scheduler::Adaptive(Box::new(AdaptiveScheduler {
        controller: Controller::new(config, Duration::from_millis(1), 1),
        reservation: 0,
        admissions: [AdaptiveAdmission::new(0), AdaptiveAdmission::new(0)],
    }))
}

fn target() -> SelectedAddress {
    SelectedAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
}

#[test]
fn host_expiry_during_neighbor_discovery_marks_it_incomplete() {
    let now = Instant::now();
    let target = target();
    let mut scheduler = adaptive_scheduler(Duration::from_secs(1));
    let host = scheduler.host_index(&target);
    scheduler.host_started(host, now);
    assert!(!scheduler.host_expired(host, now));
    assert!(scheduler.host_expired(host, now + Duration::from_secs(1)));
    let scheduling = scheduler.finish(0);
    assert_eq!(scheduling.incomplete.len(), 1);
    assert_eq!(scheduling.incomplete[0].address, target.address);
}

#[test]
fn fixed_scheduler_has_no_host_deadline() {
    let now = Instant::now();
    let mut scheduler = Scheduler::Fixed { peak: 0 };
    let host = scheduler.host_index(&target());
    assert_eq!(host, None);
    scheduler.host_started(host, now);
    assert!(!scheduler.host_expired(host, now));
    assert_eq!(scheduler.host_remaining(host, now), None);
}
