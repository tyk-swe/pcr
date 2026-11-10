// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime};

use super::*;
use crate::scan::adaptive::{Adaptive, Controller};

fn targets(count: usize) -> Vec<SelectedAddress> {
    (0..count)
        .map(|index| SelectedAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, index as u8 + 1))))
        .collect()
}

fn controller(targets: &[SelectedAddress]) -> Controller {
    let config = Adaptive {
        min_timeout: Duration::from_millis(1),
        max_timeout: Duration::from_secs(1),
        min_window: 1,
        initial_window: 1,
        host_timeout: Duration::from_secs(1),
        retry_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(1),
    };
    let mut controller = Controller::new(config, Duration::from_millis(1), 1);
    for target in targets {
        controller.host_index(target);
    }
    controller
}

fn response(target: &SelectedAddress, sequence: u64) -> Observation {
    Observation {
        sequence,
        address: target.address,
        interface: None,
        response: Some((ReasonKind::Connected, target.address)),
        observed_at: SystemTime::UNIX_EPOCH,
    }
}

#[test]
fn discovery_incomplete_and_unresponsive_skip_control_scan_targets() {
    let targets = targets(3);
    let mut controller = controller(&targets);
    controller.mark_incomplete(2);
    let mut sweep = Sweep::new(&targets, Mode::Before, Unresponsive::Skip);
    sweep.observe_all([response(&targets[0], 7)]).unwrap();
    let discovered = sweep.finish_discovery(Some(&controller));
    let scan_targets = discovered.scan_targets();
    let hosts = discovered.finish_scan(None);

    assert_eq!(
        hosts.iter().map(|host| host.state).collect::<Vec<_>>(),
        vec![State::Responded, State::NoResponse, State::NoResponse]
    );
    assert_eq!(
        hosts.iter().map(|host| host.scan).collect::<Vec<_>>(),
        vec![Scan::Scanned, Scan::Skipped, Scan::Incomplete]
    );
    assert_eq!(scan_targets, vec![targets[0].clone()]);
}

#[test]
fn unresponsive_scan_and_incomplete_scan_set_final_dispositions() {
    let targets = targets(2);
    let mut sweep = Sweep::new(&targets, Mode::Before, Unresponsive::Scan);
    sweep.observe_all([response(&targets[1], 9)]).unwrap();
    let discovered = sweep.finish_discovery(None);
    assert_eq!(discovered.scan_targets(), targets);

    let mut controller = controller(&targets);
    controller.mark_incomplete(0);
    let hosts = discovered.finish_scan(Some(&controller));

    assert_eq!(
        hosts.iter().map(|host| host.scan).collect::<Vec<_>>(),
        vec![Scan::Incomplete, Scan::Scanned]
    );
}
