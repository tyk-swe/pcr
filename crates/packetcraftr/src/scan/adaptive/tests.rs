// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Instant;

use crate::target::SelectedAddress;

use super::*;

fn config() -> Adaptive {
    Adaptive {
        min_timeout: Duration::from_millis(1),
        max_timeout: Duration::from_secs(1),
        min_window: 1,
        initial_window: 4,
        host_timeout: Duration::from_secs(10),
        retry_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_millis(100),
    }
}

fn targets(count: usize) -> Vec<SelectedAddress> {
    (0..count)
        .map(|host| {
            SelectedAddress::new(IpAddr::V4(std::net::Ipv4Addr::new(
                192,
                0,
                2,
                host as u8 + 1,
            )))
        })
        .collect()
}

fn identities(selections: &[Selection]) -> Vec<(usize, usize, u32, u64)> {
    selections
        .iter()
        .map(|selection| {
            (
                selection.slot,
                selection.endpoint,
                selection.attempt,
                selection.sequence,
            )
        })
        .collect()
}

fn reply(responder: IpAddr) -> Outcome {
    Outcome::Reply {
        latency: Duration::from_millis(1),
        responder,
        control: false,
    }
}

fn send_and_settle(
    controller: &mut Controller,
    work: &mut Work,
    selection: Selection,
    outcome: Outcome,
    now: Instant,
) {
    controller.admitted(work, selection);
    controller.confirm_send(work, selection, now);
    controller.settle(work, selection, outcome, now);
}

#[test]
fn every_host_endpoint_is_selected_once_and_completed() {
    for hosts in [1, 4, 32] {
        for endpoints in [32, 128, 512] {
            let now = Instant::now();
            let mut controller = Controller::new(config(), Duration::from_millis(100), 4);
            let mut work = controller.open_stage(&targets(hosts), endpoints, 1, 100, now);
            let mut sequences = std::collections::BTreeSet::new();
            for _ in 0..hosts * endpoints {
                let wave = controller.select(&mut work, now, now + Duration::from_secs(20), 1);
                assert_eq!(wave.selections.len(), 1);
                let selection = wave.selections[0];
                assert_eq!(
                    selection.sequence,
                    100 + (selection.endpoint * hosts + selection.slot) as u64
                );
                controller.admitted(&mut work, selection);
                controller.confirm_send(&mut work, selection, now);
                controller.settle(
                    &mut work,
                    selection,
                    reply(targets(hosts)[selection.slot].address),
                    now,
                );
                assert!(sequences.insert(selection.sequence));
            }
            assert!(work.done());
            assert_eq!(sequences, (100..100 + (hosts * endpoints) as u64).collect());
            assert!(
                controller
                    .select(&mut work, now, now + Duration::from_secs(20), 1)
                    .selections
                    .is_empty()
            );
        }
    }
}

#[test]
fn unadmitted_selections_remain_eligible_and_retry_identity_is_stable() {
    let now = Instant::now();
    let mut controller = Controller::new(config(), Duration::from_millis(100), 4);
    let mut work = controller.open_stage(&targets(2), 2, 2, 17, now);
    let initial = controller.select(&mut work, now, now + Duration::from_secs(20), 4);
    assert_eq!(
        initial
            .selections
            .iter()
            .map(|s| (s.slot, s.endpoint))
            .collect::<Vec<_>>(),
        vec![(0, 0), (1, 0), (0, 1), (1, 1)]
    );
    // A caller can stop admission after any selection because of pacing or
    // finite native capacity. Selection itself must not consume the rest.
    let first = initial.selections[0];
    controller.admitted(&mut work, first);
    controller.confirm_send(&mut work, first, now);
    controller.settle(&mut work, first, Outcome::Silent, now);
    let next = controller.select(&mut work, now, now + Duration::from_secs(20), 4);
    assert_eq!(
        next.selections
            .iter()
            .map(|s| (s.slot, s.endpoint))
            .collect::<Vec<_>>(),
        vec![(0, 1), (1, 0), (1, 1)]
    );
    for selection in next.selections {
        controller.admitted(&mut work, selection);
        controller.confirm_send(&mut work, selection, now);
        controller.settle(&mut work, selection, Outcome::Aborted, now);
    }
    let waiting = controller.select(&mut work, now, now + Duration::from_secs(20), 4);
    assert!(waiting.selections.is_empty());
    assert_eq!(waiting.next_ready, Some(now + config().retry_backoff));
    let retried = controller.select(
        &mut work,
        now + config().retry_backoff,
        now + Duration::from_secs(20),
        4,
    );
    assert_eq!(retried.selections.len(), 1);
    let retry = retried.selections[0];
    assert_eq!(
        (retry.slot, retry.endpoint, retry.attempt, retry.sequence),
        (0, 0, 2, 21)
    );
    controller.admitted(&mut work, retry);
    controller.confirm_send(&mut work, retry, now + config().retry_backoff);
    controller.settle(
        &mut work,
        retry,
        Outcome::Silent,
        now + config().retry_backoff,
    );
    assert!(work.done());
    assert_eq!(controller.take_canceled_responses(&mut work), 3);
}

#[test]
fn expiry_counts_unsent_attempts_once_and_pending_settlement_remains_valid() {
    let now = Instant::now();
    let mut controller = Controller::new(config(), Duration::from_millis(100), 4);
    let mut work = controller.open_stage(&targets(1), 3, 2, 0, now);
    let selection = controller
        .select(&mut work, now, now + Duration::from_secs(20), 1)
        .selections[0];
    controller.admitted(&mut work, selection);
    controller.confirm_send(&mut work, selection, now);
    let expired = controller.select(
        &mut work,
        now + config().host_timeout,
        now + Duration::from_secs(20),
        4,
    );
    assert!(expired.done);
    assert_eq!(controller.take_canceled_responses(&mut work), 5);
    controller.settle(
        &mut work,
        selection,
        Outcome::Reply {
            latency: config().host_timeout,
            responder: targets(1)[0].address,
            control: false,
        },
        now + config().host_timeout,
    );
    assert!(work.done());
    assert_eq!(controller.take_canceled_responses(&mut work), 0);
    let report = controller.finish(Ceilings::default());
    assert_eq!(
        report
            .incomplete
            .iter()
            .map(|host| (host.address, host.scope.clone()))
            .collect::<Vec<_>>(),
        [(targets(1)[0].address, None)]
    );
}

#[test]
fn selection_timeline_preserves_pacing_retries_discarded_offers_and_expiry() {
    let start = Instant::now();
    let mut settings = config();
    settings.host_timeout = Duration::from_millis(300);
    let mut controller = Controller::new(settings, Duration::from_millis(100), 8);
    let targets = targets(3);
    let mut work = controller.open_stage(&targets, 3, 2, 100, start);
    let paced = controller.host_index(&targets[0]);
    controller.hosts[paced].min_gap = Duration::from_millis(10);
    let end = start + Duration::from_secs(2);
    let at = |millis| start + Duration::from_millis(millis);

    let initial = controller.select(&mut work, start, end, 4);
    assert_eq!(
        identities(&initial.selections),
        [
            (0, 0, 1, 100),
            (1, 0, 1, 101),
            (2, 0, 1, 102),
            (1, 1, 1, 104)
        ]
    );
    for selection in initial.selections.iter().take(3) {
        controller.admitted(&mut work, *selection);
        controller.confirm_send(&mut work, *selection, start);
    }
    controller.settle(&mut work, initial.selections[0], Outcome::Silent, start);
    controller.settle(
        &mut work,
        initial.selections[1],
        Outcome::Reply {
            latency: Duration::from_millis(5),
            responder: targets[1].address,
            control: false,
        },
        at(5),
    );
    controller.settle(&mut work, initial.selections[2], Outcome::Aborted, at(5));

    let next = controller.select(&mut work, at(5), end, 3);
    assert_eq!(
        identities(&next.selections),
        [(2, 1, 1, 105), (1, 1, 1, 104), (2, 2, 1, 108)]
    );
    send_and_settle(
        &mut controller,
        &mut work,
        next.selections[0],
        reply(targets[2].address),
        at(5),
    );
    send_and_settle(
        &mut controller,
        &mut work,
        next.selections[1],
        Outcome::Silent,
        at(5),
    );
    controller.settle(&mut work, next.selections[2], Outcome::Omitted, at(5));

    let refill = controller.select(&mut work, at(9), end, 4);
    assert_eq!(identities(&refill.selections), [(1, 2, 1, 107)]);
    for selection in refill.selections {
        send_and_settle(
            &mut controller,
            &mut work,
            selection,
            reply(targets[selection.slot].address),
            at(9),
        );
    }

    let retry = controller.select(&mut work, at(10), end, 4);
    assert_eq!(identities(&retry.selections), [(0, 0, 2, 109)]);
    send_and_settle(
        &mut controller,
        &mut work,
        retry.selections[0],
        reply(targets[0].address),
        at(10),
    );
    let waiting = controller.select(&mut work, at(14), end, 4);
    assert!(waiting.selections.is_empty());
    assert_eq!(waiting.next_ready, Some(at(15)));
    let retry = controller.select(&mut work, at(15), end, 4);
    assert_eq!(identities(&retry.selections), [(1, 1, 2, 113)]);
    send_and_settle(
        &mut controller,
        &mut work,
        retry.selections[0],
        reply(targets[1].address),
        at(15),
    );

    let waiting = controller.select(&mut work, at(19), end, 4);
    assert!(waiting.selections.is_empty());
    assert_eq!(waiting.next_ready, Some(at(20)));
    let pending = controller.select(&mut work, at(20), end, 4);
    assert_eq!(identities(&pending.selections), [(0, 1, 1, 103)]);
    controller.admitted(&mut work, pending.selections[0]);
    controller.confirm_send(&mut work, pending.selections[0], at(20));
    let discarded = controller.select(&mut work, at(30), end, 4);
    assert_eq!(identities(&discarded.selections), [(0, 2, 1, 106)]);
    let last_chance = controller.select(&mut work, at(299), end, 4);
    assert_eq!(identities(&last_chance.selections), [(0, 2, 1, 106)]);
    assert_eq!(last_chance.selections[0].timeout, Duration::from_millis(1));
    assert_eq!(last_chance.selections[0].host_deadline, at(300));
    assert!(last_chance.selections[0].host_limited);

    let expired = controller.select(&mut work, at(300), end, 4);
    assert!(expired.done);
    assert!(expired.selections.is_empty());
    assert_eq!(controller.take_canceled_responses(&mut work), 6);
    controller.settle(
        &mut work,
        pending.selections[0],
        Outcome::Reply {
            latency: Duration::from_millis(290),
            responder: targets[0].address,
            control: false,
        },
        at(310),
    );
    assert!(work.done());
    assert_eq!(controller.take_canceled_responses(&mut work), 0);
    let report = controller.finish(Ceilings::default());
    assert_eq!(report.retries_started, 2);
    assert_eq!(
        report
            .incomplete
            .iter()
            .map(|host| (&host.address, &host.scope))
            .collect::<Vec<_>>(),
        [(&targets[0].address, &targets[0].scope)]
    );
}

#[test]
fn paced_host_cannot_queue_again_before_its_admission_commits_or_is_omitted() {
    for omit in [false, true] {
        let now = Instant::now();
        let end = now + Duration::from_secs(5);
        let gap = Duration::from_millis(10);
        let mut controller = Controller::new(config(), Duration::from_millis(100), 4);
        let targets = targets(1);
        let mut work = controller.open_stage(&targets, 3, 1, 0, now);
        let host = controller.host_index(&targets[0]);
        controller.hosts[host].min_gap = gap;
        let initial = controller.select(&mut work, now, end, 4);
        assert_eq!(identities(&initial.selections), [(0, 0, 1, 0)]);
        let first = initial.selections[0];
        controller.admitted(&mut work, first);
        assert!(
            controller
                .select(&mut work, now, end, 4)
                .selections
                .is_empty()
        );
        let second_at = if omit {
            controller.settle(&mut work, first, Outcome::Omitted, now);
            now
        } else {
            controller.confirm_send(&mut work, first, now);
            assert!(
                controller
                    .select(&mut work, now, end, 4)
                    .selections
                    .is_empty()
            );
            controller.settle(&mut work, first, reply(targets[0].address), now);
            now + gap
        };
        let second = controller.select(&mut work, second_at, end, 4);
        assert_eq!(identities(&second.selections), [(0, 1, 1, 1)]);
        send_and_settle(
            &mut controller,
            &mut work,
            second.selections[0],
            reply(targets[0].address),
            second_at,
        );
        let third_at = second_at + gap;
        let waiting = controller.select(&mut work, third_at - Duration::from_nanos(1), end, 4);
        assert!(waiting.selections.is_empty());
        assert_eq!(waiting.next_ready, Some(third_at));
        let third = controller.select(&mut work, third_at, end, 4);
        assert_eq!(identities(&third.selections), [(0, 2, 1, 2)]);
        send_and_settle(
            &mut controller,
            &mut work,
            third.selections[0],
            reply(targets[0].address),
            third_at,
        );
        assert!(work.done());
        assert!(
            controller
                .select(&mut work, third_at, end, 4)
                .selections
                .is_empty()
        );
        assert_eq!(
            controller.take_canceled_responses(&mut work),
            usize::from(omit)
        );
    }
}

#[test]
fn paced_hosts_keep_independent_admission_and_ready_times() {
    let now = Instant::now();
    let end = now + Duration::from_secs(5);
    let mut controller = Controller::new(config(), Duration::from_millis(100), 4);
    let targets = targets(2);
    let mut work = controller.open_stage(&targets, 2, 1, 0, now);
    for (target, milliseconds) in targets.iter().zip([10, 20]) {
        let host = controller.host_index(target);
        controller.hosts[host].min_gap = Duration::from_millis(milliseconds);
    }
    let initial = controller.select(&mut work, now, end, 4);
    assert_eq!(
        identities(&initial.selections),
        [(0, 0, 1, 0), (1, 0, 1, 1)]
    );
    for selection in initial.selections {
        send_and_settle(
            &mut controller,
            &mut work,
            selection,
            reply(targets[selection.slot].address),
            now,
        );
    }
    for (slot, milliseconds, sequence) in [(0, 10, 2), (1, 20, 3)] {
        let ready = now + Duration::from_millis(milliseconds);
        let waiting = controller.select(&mut work, ready - Duration::from_nanos(1), end, 4);
        assert!(waiting.selections.is_empty());
        assert_eq!(waiting.next_ready, Some(ready));
        let selected = controller.select(&mut work, ready, end, 4);
        assert_eq!(identities(&selected.selections), [(slot, 1, 1, sequence)]);
        send_and_settle(
            &mut controller,
            &mut work,
            selected.selections[0],
            reply(targets[slot].address),
            ready,
        );
    }
    assert!(work.done());
}

#[test]
fn provisional_silence_retries_neutrally_and_only_final_clean_quality_promotes_losses() {
    for (coverage, expected_window, incomplete) in [
        (crate::scan::Coverage::NoReportedLoss, 2, false),
        (crate::scan::Coverage::Incomplete, 4, true),
        (crate::scan::Coverage::Unknown, 4, true),
    ] {
        let now = Instant::now();
        let retry_at = now + config().retry_backoff;
        let mut controller = Controller::new(config(), Duration::from_millis(100), 4);
        controller.begin_observation_stage();
        let target = targets(1);
        let mut work = controller.open_stage(&target, 2, 2, 0, now);
        let first = controller.select(
            &mut work,
            now,
            now + Duration::from_secs(5),
            controller.window(),
        );
        assert_eq!(identities(&first.selections), [(0, 0, 1, 0), (0, 1, 1, 1)]);
        for selection in first.selections {
            send_and_settle(
                &mut controller,
                &mut work,
                selection,
                Outcome::UnqualifiedSilence,
                now,
            );
        }
        let waiting = controller.select(
            &mut work,
            retry_at - Duration::from_nanos(1),
            now + Duration::from_secs(5),
            controller.window(),
        );
        assert!(waiting.selections.is_empty());
        assert_eq!(waiting.next_ready, Some(retry_at));
        let retry = controller.select(
            &mut work,
            retry_at,
            now + Duration::from_secs(5),
            controller.window(),
        );
        assert_eq!(identities(&retry.selections), [(0, 0, 2, 2), (0, 1, 2, 3)]);
        for selection in retry.selections {
            send_and_settle(
                &mut controller,
                &mut work,
                selection,
                Outcome::UnqualifiedSilence,
                retry_at,
            );
        }
        assert!(work.done());

        let responder: IpAddr = "198.51.100.7".parse().unwrap();
        let mut controls = controller.open_stage(&target, 4, 1, 10, retry_at);
        let replies = controller.select(
            &mut controls,
            retry_at,
            now + Duration::from_secs(5),
            controller.window(),
        );
        assert_eq!(
            identities(&replies.selections),
            [(0, 0, 1, 10), (0, 1, 1, 11), (0, 2, 1, 12), (0, 3, 1, 13)]
        );
        for selection in &replies.selections {
            controller.admitted(&mut controls, *selection);
            controller.confirm_send(&mut controls, *selection, retry_at);
        }
        for selection in replies.selections {
            controller.settle(
                &mut controls,
                selection,
                Outcome::Reply {
                    latency: Duration::from_millis(1),
                    responder,
                    control: true,
                },
                retry_at,
            );
        }
        assert!(controls.done());

        controller.qualify_pending(coverage);
        let following = SelectedAddress::new("192.0.2.2".parse().unwrap());
        let mut followup = controller.open_stage(&[following], 4, 1, 100, retry_at);
        let offered = controller.select(
            &mut followup,
            retry_at,
            now + Duration::from_secs(5),
            controller.window(),
        );
        let expected = [
            (0, 0, 1, 101),
            (0, 1, 1, 103),
            (0, 2, 1, 105),
            (0, 3, 1, 107),
        ];
        assert_eq!(identities(&offered.selections), expected[..expected_window]);
        controller.qualify_pending(crate::scan::Coverage::NoReportedLoss);
        let repeated = controller.select(
            &mut followup,
            retry_at,
            now + Duration::from_secs(5),
            controller.window(),
        );
        assert_eq!(
            identities(&repeated.selections),
            expected[..expected_window]
        );

        let report = controller.finish(Ceilings::default());
        assert_eq!(report.retries_started, 2);
        let expected_incomplete = if incomplete {
            vec![(target[0].address, target[0].scope.clone())]
        } else {
            vec![]
        };
        assert_eq!(
            report
                .incomplete
                .iter()
                .map(|host| (host.address, host.scope.clone()))
                .collect::<Vec<_>>(),
            expected_incomplete
        );
        if incomplete {
            assert!(report.conditions.is_empty());
            continue;
        }
        assert_eq!(report.conditions.len(), 1);
        let condition = &report.conditions[0];
        assert_eq!(condition.kind, ConditionKind::SuspectedResponseRateLimit);
        assert_eq!(condition.host.address, target[0].address);
        assert_eq!(condition.host.scope, target[0].scope);
        assert_eq!(condition.control_responder, responder);
        assert_eq!(
            (condition.completed, condition.replies, condition.losses),
            (8, 4, 4)
        );
        assert_eq!(condition.control_sequences, [10, 11, 12, 13]);
        assert_eq!(condition.loss_sequences, [0, 1, 2, 3]);
    }
}

#[test]
fn deferred_interface_admission_preserves_host_pacing_across_refill_polls() {
    let now = Instant::now();
    let mut controller = Controller::new(config(), Duration::from_millis(100), 3);
    let targets = targets(2);
    let mut work = controller.open_stage(&targets, 3, 1, 0, now);
    let deferred = controller.host_index(&targets[1]);
    controller.hosts[deferred].min_gap = Duration::from_millis(10);
    let initial = controller.select(&mut work, now, now + Duration::from_secs(5), 3);
    assert_eq!(
        initial
            .selections
            .iter()
            .map(|s| (s.slot, s.endpoint))
            .collect::<Vec<_>>(),
        vec![(0, 0), (1, 0), (0, 1)]
    );
    let straggler = initial.selections[0];
    let unarmed = initial.selections[1];
    let quick = initial.selections[2];
    for selection in &initial.selections {
        controller.admitted(&mut work, *selection);
        if selection.slot == 0 {
            controller.confirm_send(&mut work, *selection, now);
        }
    }
    controller.settle(&mut work, quick, reply(targets[0].address), now);
    // The first host's armed source can refill while the second host's offered
    // attempt waits for a drained capture epoch. A second offer for that paced
    // host must not sneak into the queue on this independent select call.
    let refill = controller.select(&mut work, now, now + Duration::from_secs(5), 1);
    assert_eq!(
        refill
            .selections
            .iter()
            .map(|s| (s.slot, s.endpoint))
            .collect::<Vec<_>>(),
        vec![(0, 2)]
    );
    let last_armed = refill.selections[0];
    controller.admitted(&mut work, last_armed);
    controller.confirm_send(&mut work, last_armed, now);
    controller.settle(&mut work, last_armed, Outcome::Aborted, now);
    assert!(
        controller
            .select(&mut work, now, now + Duration::from_secs(5), 1)
            .selections
            .is_empty()
    );
    controller.settle(&mut work, straggler, Outcome::Aborted, now);
    let rotated = now + Duration::from_millis(200);
    controller.confirm_send(&mut work, unarmed, rotated);
    let paced = controller.select(&mut work, rotated, rotated + Duration::from_secs(5), 3);
    assert!(paced.selections.is_empty());
    assert_eq!(paced.next_ready, Some(rotated + Duration::from_millis(10)));
    let next = controller.select(
        &mut work,
        rotated + Duration::from_millis(10),
        rotated + Duration::from_secs(5),
        3,
    );
    assert_eq!(
        next.selections
            .iter()
            .map(|s| (s.slot, s.endpoint))
            .collect::<Vec<_>>(),
        vec![(1, 1)]
    );
    controller.admitted(&mut work, next.selections[0]);
    assert!(
        controller
            .select(
                &mut work,
                rotated + Duration::from_millis(10),
                rotated + Duration::from_secs(5),
                3
            )
            .selections
            .is_empty()
    );
    let committed = rotated + Duration::from_millis(10);
    controller.confirm_send(&mut work, next.selections[0], committed);
    controller.settle(
        &mut work,
        next.selections[0],
        reply(targets[1].address),
        committed,
    );
    controller.settle(&mut work, unarmed, reply(targets[1].address), committed);
    let ready = committed + Duration::from_millis(10);
    let last = controller.select(&mut work, ready, ready + Duration::from_secs(5), 3);
    assert_eq!(identities(&last.selections), [(1, 2, 1, 5)]);
    send_and_settle(
        &mut controller,
        &mut work,
        last.selections[0],
        reply(targets[1].address),
        ready,
    );
    assert!(work.done());
}
