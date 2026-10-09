// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use super::*;

fn config() -> Adaptive {
    Adaptive {
        min_timeout: Duration::from_millis(10),
        max_timeout: Duration::from_millis(2_000),
        min_window: 1,
        initial_window: 1,
        host_timeout: Duration::from_millis(5_000),
        retry_backoff: Duration::from_millis(100),
        max_backoff: Duration::from_millis(1_000),
    }
}

fn request_timeout() -> Duration {
    Duration::from_millis(1_000)
}

fn host(address: u8) -> SelectedAddress {
    SelectedAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, address)))
}

fn reply(latency: Duration) -> Outcome {
    Outcome::Reply {
        latency,
        responder: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
        control: false,
    }
}

fn control_reply(latency: Duration, responder: IpAddr) -> Outcome {
    Outcome::Reply {
        latency,
        responder,
        control: true,
    }
}

fn send(controller: &mut Controller, work: &mut Work, selection: Selection, now: Instant) {
    controller.admitted(work, selection);
    controller.confirm_send(work, selection, now);
}

#[test]
fn the_first_sample_sets_srtt_and_rttvar_so_rto_is_three_samples() {
    let mut estimator = Estimator::default();
    estimator.sample(Duration::from_millis(100));
    assert_eq!(
        estimator.rto(config().min_timeout, config().max_timeout),
        Some(Duration::from_millis(300)),
    );
}

#[test]
fn repeated_stable_samples_converge_on_the_sample() {
    let mut estimator = Estimator::default();
    for _ in 0..8 {
        estimator.sample(Duration::from_millis(100));
    }
    assert_eq!(
        estimator.rto(config().min_timeout, config().max_timeout),
        Some(Duration::from_nanos(126_696_772)),
    );
}

#[test]
fn the_estimator_clamps_between_the_configured_bounds() {
    let mut estimator = Estimator::default();
    estimator.sample(Duration::from_nanos(1));
    assert_eq!(
        estimator.rto(config().min_timeout, config().max_timeout),
        Some(config().min_timeout),
    );
    let mut estimator = Estimator::default();
    estimator.sample(Duration::from_secs(60));
    assert_eq!(
        estimator.rto(config().min_timeout, config().max_timeout),
        Some(config().max_timeout),
    );
}

#[test]
fn near_duration_samples_stay_finite_and_ordered() {
    let mut estimator = Estimator::default();
    estimator.sample(Duration::from_nanos(u64::MAX - 1));
    estimator.sample(Duration::from_nanos(1));
    let rto = estimator
        .rto(config().min_timeout, config().max_timeout)
        .expect("a saturated estimate still yields an RTO");
    assert_eq!(rto, config().max_timeout);
}

#[test]
fn an_unsampled_host_never_drops_below_the_initial_timeout_floor() {
    for (operation_sample, expected) in [
        (Duration::from_millis(100), request_timeout()),
        (Duration::from_millis(500), Duration::from_millis(1500)),
    ] {
        let mut controller = Controller::new(config(), request_timeout(), 8);
        let h1 = controller.host_index(&host(1));
        controller.operation.sample(operation_sample);
        assert_eq!(
            controller.rto(h1),
            expected,
            "operation sample {operation_sample:?}"
        );
    }
    let mut controller = Controller::new(config(), request_timeout(), 8);
    let h1 = controller.host_index(&host(1));
    controller.hosts[h1]
        .estimator
        .sample(Duration::from_millis(100));
    assert_eq!(controller.rto(h1), Duration::from_millis(300));
}

#[test]
fn the_round_robin_interleaves_hosts_in_selection_order() {
    let mut controller = Controller::new(config(), request_timeout(), 8);
    let targets = [host(1), host(2)];
    let mut work = controller.open_stage(&targets, 3, 1, 0, Instant::now());
    let start = Instant::now();
    let end = start + Duration::from_secs(60);
    let mut order = Vec::new();
    loop {
        let wave = controller.select(&mut work, start, end, controller.window());
        if wave.done {
            break;
        }
        for selection in &wave.selections {
            order.push((selection.slot, selection.endpoint));
            send(&mut controller, &mut work, *selection, start);
            controller.settle(
                &mut work,
                *selection,
                reply(Duration::from_millis(10)),
                start,
            );
        }
    }
    assert_eq!(
        order,
        [(0, 0), (1, 0), (0, 1), (1, 1), (0, 2), (1, 2)],
        "h1p1, h2p1, h1p2, h2p2, h1p3, h2p3"
    );
}

#[test]
fn sequences_reserve_every_potential_attempts_position() {
    let mut controller = Controller::new(config(), request_timeout(), 8);
    let targets = [host(1), host(2)];
    let mut work = controller.open_stage(&targets, 2, 3, 7, Instant::now());
    let start = Instant::now();
    let end = start + Duration::from_secs(60);
    let wave = controller.select(&mut work, start, end, 4);
    let sequences: Vec<u64> = wave.selections.iter().map(|sel| sel.sequence).collect();
    assert_eq!(sequences, [7, 8, 9, 10]);
    for selection in &wave.selections {
        send(&mut controller, &mut work, *selection, start);
        controller.settle(&mut work, *selection, Outcome::Silent, start);
    }
    let now = start + config().retry_backoff;
    let wave = controller.select(&mut work, now, end, 4);
    let sequences: Vec<u64> = wave.selections.iter().map(|sel| sel.sequence).collect();
    assert_eq!(sequences, [11, 12, 13, 14]);
}

#[test]
fn an_answered_endpoint_never_spends_its_retry_quota() {
    let mut controller = Controller::new(config(), request_timeout(), 8);
    let targets = [host(1)];
    let mut work = controller.open_stage(&targets, 1, 3, 0, Instant::now());
    let start = Instant::now();
    let end = start + Duration::from_secs(60);
    let wave = controller.select(&mut work, start, end, 1);
    send(&mut controller, &mut work, wave.selections[0], start);
    controller.settle(
        &mut work,
        wave.selections[0],
        reply(Duration::from_millis(10)),
        start,
    );
    assert_eq!(controller.retries_started, 0);
    assert!(work.done());
}

#[test]
fn a_silent_endpoint_retries_with_growing_bounded_backoffs() {
    let mut controller = Controller::new(config(), request_timeout(), 8);
    let targets = [host(1)];
    let mut work = controller.open_stage(&targets, 1, 3, 0, Instant::now());
    let start = Instant::now();
    let end = start + Duration::from_secs(60);
    let mut now = start;
    let mut sent = Vec::new();
    while !work.done() {
        let wave = controller.select(&mut work, now, end, 1);
        if wave.selections.is_empty() {
            now = wave.next_ready.expect("unfinished work waits for a time");
            continue;
        }
        let selection = wave.selections[0];
        sent.push((selection.attempt, now));
        send(&mut controller, &mut work, selection, now);
        controller.settle(&mut work, selection, Outcome::Silent, now);
    }
    let attempts: Vec<u32> = sent.iter().map(|(attempt, _)| *attempt).collect();
    assert_eq!(attempts, [1, 2, 3]);
    assert!(sent[1].1 - sent[0].1 >= Duration::from_millis(100));
    assert!(sent[2].1 - sent[1].1 >= Duration::from_millis(200));
}

#[test]
fn a_waiting_retry_never_starves_a_ready_host() {
    let mut controller = Controller::new(config(), request_timeout(), 8);
    let targets = [host(1), host(2)];
    let mut work = controller.open_stage(&targets, 1, 3, 0, Instant::now());
    let start = Instant::now();
    let end = start + Duration::from_secs(60);
    let wave = controller.select(&mut work, start, end, 1);
    send(&mut controller, &mut work, wave.selections[0], start);
    controller.settle(&mut work, wave.selections[0], Outcome::Silent, start);
    let wave = controller.select(&mut work, start, end, 1);
    assert_eq!(wave.selections[0].host, 1);
}

#[test]
fn a_host_deadline_marks_it_incomplete_and_omits_unsent_endpoints() {
    let mut config = config();
    config.host_timeout = Duration::from_millis(50);
    let mut controller = Controller::new(config, Duration::from_millis(40), 8);
    let targets = [host(1), host(2)];
    let mut work = controller.open_stage(&targets, 2, 1, 0, Instant::now());
    let start = Instant::now();
    let end = start + Duration::from_secs(60);
    let wave = controller.select(&mut work, start, end, 1);
    assert_eq!(wave.selections.len(), 1);
    send(&mut controller, &mut work, wave.selections[0], start);
    controller.settle(&mut work, wave.selections[0], Outcome::Silent, start);
    let later = start + Duration::from_millis(60);
    loop {
        let wave = controller.select(&mut work, later, end, 1);
        if wave.done {
            break;
        }
        assert_eq!(wave.selections.len(), 1);
        assert_eq!(wave.selections[0].slot, 1);
        send(&mut controller, &mut work, wave.selections[0], later);
        controller.settle(
            &mut work,
            wave.selections[0],
            reply(Duration::from_millis(5)),
            later,
        );
    }
    let wave = controller.select(&mut work, later, end, 1);
    assert!(
        wave.done,
        "h1's endpoints closed as incomplete, not timeouts"
    );
    let report = controller.finish((None, None));
    assert_eq!(report.incomplete.len(), 1);
    assert_eq!(
        report.incomplete[0].address,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
    );
}

#[test]
fn a_truncated_silent_window_marks_the_host_incomplete() {
    let mut config = config();
    config.host_timeout = Duration::from_millis(100);
    config.min_timeout = Duration::from_millis(500);
    config.max_timeout = Duration::from_millis(1_000);
    let mut controller = Controller::new(config, Duration::from_millis(800), 8);
    let targets = [host(1)];
    let mut work = controller.open_stage(&targets, 1, 2, 0, Instant::now());
    let start = Instant::now();
    let wave = controller.select(&mut work, start, start + Duration::from_secs(60), 1);
    assert_eq!(wave.selections.len(), 1);
    assert_eq!(wave.selections[0].timeout, Duration::from_millis(100));
    assert!(wave.selections[0].host_limited);
    assert!(!controller.is_incomplete(0));
    send(&mut controller, &mut work, wave.selections[0], start);
    controller.settle(&mut work, wave.selections[0], Outcome::Silent, start);
    assert!(controller.is_incomplete(0));
}

#[test]
fn a_definitive_reply_inside_a_truncated_window_completes_the_host() {
    let mut config = config();
    config.host_timeout = Duration::from_millis(10);
    config.min_timeout = Duration::from_millis(20);
    config.max_timeout = Duration::from_millis(1_000);
    let mut controller = Controller::new(config, Duration::from_millis(500), 8);
    let targets = [host(1)];
    let mut work = controller.open_stage(&targets, 1, 3, 0, Instant::now());
    let start = Instant::now();
    let wave = controller.select(&mut work, start, start + Duration::from_secs(60), 1);
    assert_eq!(wave.selections.len(), 1);
    assert!(wave.selections[0].host_limited);
    send(&mut controller, &mut work, wave.selections[0], start);
    controller.settle(
        &mut work,
        wave.selections[0],
        reply(Duration::from_millis(1)),
        start + Duration::from_millis(1),
    );
    assert!(!controller.is_incomplete(0));
    assert!(work.done());
}

#[test]
fn the_aimd_window_grows_after_a_windows_successes_and_floors_on_loss() {
    let mut config = config();
    config.initial_window = 2;
    config.min_window = 1;
    let mut controller = Controller::new(config, request_timeout(), 4);
    let targets = [host(1)];
    let mut work = controller.open_stage(&targets, 8, 1, 0, Instant::now());
    let start = Instant::now();
    let end = start + Duration::from_secs(60);
    for _ in 0..5 {
        let wave = controller.select(&mut work, start, end, controller.window());
        for selection in &wave.selections {
            send(&mut controller, &mut work, *selection, start);
            controller.settle(
                &mut work,
                *selection,
                reply(Duration::from_millis(5)),
                start,
            );
        }
    }
    assert_eq!(controller.window(), 4);
    work = controller.open_stage(&targets, 8, 1, 0, Instant::now());
    let now = Instant::now();
    for _ in 0..2 {
        let wave = controller.select(&mut work, now, end, controller.window());
        for selection in &wave.selections {
            send(&mut controller, &mut work, *selection, now);
        }
        for selection in &wave.selections {
            controller.settle(&mut work, *selection, Outcome::Silent, now);
        }
    }
    assert_eq!(controller.window(), 1);
}

#[test]
fn losses_in_one_cohort_halve_only_once() {
    let mut config = config();
    config.initial_window = 4;
    let mut controller = Controller::new(config, request_timeout(), 8);
    let targets = [host(1), host(2)];
    let mut work = controller.open_stage(&targets, 2, 2, 0, Instant::now());
    let start = Instant::now();
    let end = start + Duration::from_secs(60);
    let wave = controller.select(&mut work, start, end, 4);
    assert_eq!(wave.selections.len(), 4);
    for selection in &wave.selections {
        send(&mut controller, &mut work, *selection, start);
    }
    for selection in &wave.selections {
        controller.settle(&mut work, *selection, Outcome::Silent, start);
    }
    assert_eq!(
        controller.window(),
        2,
        "four losses in one cohort halve once"
    );
}

#[test]
fn rate_limit_inference_needs_enough_controls_losses_and_one_responder() {
    let mut controller = Controller::new(config(), request_timeout(), 8);
    let targets = [host(1)];
    let mut work = controller.open_stage(&targets, 12, 1, 0, Instant::now());
    let start = Instant::now();
    let end = start + Duration::from_secs(60);
    let responder = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
    let mut index = 0;
    while index < 8 {
        let wave = controller.select(&mut work, start, end, 4);
        for selection in &wave.selections {
            send(&mut controller, &mut work, *selection, start);
            let outcome = match index {
                0 | 1 => control_reply(Duration::from_millis(5), responder),
                _ => Outcome::Silent,
            };
            controller.settle(&mut work, *selection, outcome, start);
            index += 1;
        }
        if index >= 8 {
            break;
        }
    }
    let report = controller.finish((None, None));
    assert_eq!(report.conditions.len(), 1);
    let condition = &report.conditions[0];
    assert_eq!(condition.kind, ConditionKind::SuspectedResponseRateLimit);
    assert_eq!(condition.control_responder, responder);
    assert_eq!(condition.completed, 8);
    assert!(condition.losses >= 4);
    assert_eq!(condition.control_sequences.len(), 2);
    assert_eq!(condition.loss_sequences.len(), 6);
}

#[test]
fn all_silent_or_distinct_responders_infer_no_condition() {
    for controls_from_one_responder in [0usize, 1] {
        let mut controller = Controller::new(config(), request_timeout(), 8);
        let targets = [host(1)];
        let mut work = controller.open_stage(&targets, 12, 1, 0, Instant::now());
        let start = Instant::now();
        let end = start + Duration::from_secs(60);
        let mut index = 0;
        while index < 8 {
            let wave = controller.select(&mut work, start, end, 4);
            for selection in &wave.selections {
                send(&mut controller, &mut work, *selection, start);
                let outcome = match index {
                    i if i < controls_from_one_responder => control_reply(
                        Duration::from_millis(5),
                        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10 + i as u8)),
                    ),
                    _ => Outcome::Silent,
                };
                controller.settle(&mut work, *selection, outcome, start);
                index += 1;
            }
            if index >= 8 {
                break;
            }
        }
        let report = controller.finish((None, None));
        assert!(report.conditions.is_empty());
    }
}

#[test]
fn retry_rtt_samples_never_update_the_estimators() {
    let mut controller = Controller::new(config(), request_timeout(), 8);
    let targets = [host(1)];
    let mut work = controller.open_stage(&targets, 1, 3, 0, Instant::now());
    let start = Instant::now();
    let end = start + Duration::from_secs(60);
    let wave = controller.select(&mut work, start, end, 1);
    let first = wave.selections[0];
    send(&mut controller, &mut work, first, start);
    controller.settle(&mut work, first, Outcome::Silent, start);
    let wave = controller.select(&mut work, start + config().retry_backoff, end, 1);
    let retry = wave.selections[0];
    assert_eq!(retry.attempt, 2);
    send(
        &mut controller,
        &mut work,
        retry,
        start + config().retry_backoff,
    );
    controller.settle(
        &mut work,
        retry,
        reply(Duration::from_millis(500)),
        start + config().retry_backoff,
    );
    assert_eq!(controller.hosts[0].estimator.srtt_ns, None);
    assert_eq!(controller.operation.srtt_ns, None);
    assert!(work.done());
}

#[test]
fn a_pending_endpoint_is_never_selected_twice() {
    let mut config = config();
    config.initial_window = 2;
    let mut controller = Controller::new(config, request_timeout(), 8);
    let targets = [host(1)];
    let mut work = controller.open_stage(&targets, 2, 1, 0, Instant::now());
    let start = Instant::now();
    let end = start + Duration::from_secs(60);
    let wave = controller.select(&mut work, start, end, 2);
    assert_eq!(wave.selections.len(), 2);
    send(&mut controller, &mut work, wave.selections[0], start);
    send(&mut controller, &mut work, wave.selections[1], start);
    controller.settle(
        &mut work,
        wave.selections[0],
        reply(Duration::from_millis(5)),
        start,
    );
    let pending_endpoint = wave.selections[1].endpoint;
    let wave = controller.select(&mut work, start, end, 2);
    assert!(
        wave.selections.is_empty(),
        "a pending endpoint admits no second selection inside the attempt ceiling"
    );
    let _ = pending_endpoint;
}

#[test]
fn an_expired_pending_endpoint_settles_once() {
    let mut config = config();
    config.host_timeout = Duration::from_millis(10);
    let mut controller = Controller::new(config, request_timeout(), 8);
    let targets = [host(1)];
    let mut work = controller.open_stage(&targets, 2, 1, 0, Instant::now());
    let start = Instant::now();
    let wave = controller.select(&mut work, start, start + Duration::from_secs(60), 2);
    assert_eq!(wave.selections.len(), 2);
    send(&mut controller, &mut work, wave.selections[0], start);
    send(&mut controller, &mut work, wave.selections[1], start);
    let expired = controller.select(
        &mut work,
        start + Duration::from_millis(11),
        start + Duration::from_secs(60),
        2,
    );
    assert!(expired.done);
    assert_eq!(work.unfinished, 0);
    controller.settle(
        &mut work,
        wave.selections[0],
        reply(Duration::from_millis(11)),
        start + Duration::from_millis(12),
    );
    controller.settle(
        &mut work,
        wave.selections[1],
        Outcome::Silent,
        start + Duration::from_millis(12),
    );
    assert_eq!(
        work.unfinished, 0,
        "a late settlement settles no endpoint twice"
    );
}

#[test]
fn interleaved_cohorts_each_halve_once() {
    let mut config = config();
    config.initial_window = 4;
    let mut controller = Controller::new(config, request_timeout(), 8);
    let targets = [host(1)];
    let mut work = controller.open_stage(&targets, 4, 1, 0, Instant::now());
    let start = Instant::now();
    let end = start + Duration::from_secs(60);
    let first = controller.select(&mut work, start, end, 2);
    assert_eq!(first.selections.len(), 2);
    send(&mut controller, &mut work, first.selections[0], start);
    send(&mut controller, &mut work, first.selections[1], start);
    let second = controller.select(&mut work, start, end, 2);
    assert_eq!(second.selections.len(), 2);
    send(&mut controller, &mut work, second.selections[0], start);
    send(&mut controller, &mut work, second.selections[1], start);
    controller.settle(&mut work, first.selections[0], Outcome::Silent, start);
    assert_eq!(controller.window(), 2);
    controller.settle(&mut work, second.selections[0], Outcome::Silent, start);
    assert_eq!(controller.window(), 1);
    controller.settle(&mut work, first.selections[1], Outcome::Silent, start);
    assert_eq!(controller.window(), 1);
    controller.settle(&mut work, second.selections[1], Outcome::Silent, start);
    assert_eq!(controller.window(), 1);
}

#[test]
fn conditions_choose_the_lowest_responder_past_the_cite_cap() {
    let mut controller = Controller::new(config(), request_timeout(), 8);
    let targets = [host(1)];
    let mut work = controller.open_stage(&targets, 14, 1, 0, Instant::now());
    let start = Instant::now();
    let end = start + Duration::from_secs(60);
    let mut selected = 0u8;
    while !work.done() {
        let wave = controller.select(&mut work, start, end, 14);
        for selection in &wave.selections {
            send(&mut controller, &mut work, *selection, start);
            let outcome = if selected < 10 {
                let responder = if selected < 8 {
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 201 + selected))
                } else {
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 250))
                };
                control_reply(Duration::from_millis(5), responder)
            } else {
                Outcome::Silent
            };
            controller.settle(&mut work, *selection, outcome, start);
            selected += 1;
        }
    }
    let report = controller.finish((None, None));
    let [condition] = report.conditions.as_slice() else {
        panic!("one condition: {:?}", report.conditions);
    };
    assert_eq!(
        condition.control_responder,
        "192.0.2.250".parse::<IpAddr>().unwrap()
    );
    assert_eq!(condition.control_sequences, vec![8, 9]);
    assert_eq!(condition.loss_sequences, vec![10, 11, 12, 13]);
    assert_eq!(condition.completed, 14);
}

#[test]
fn the_same_responder_keeps_counting_while_its_citations_cap() {
    let mut controller = Controller::new(config(), request_timeout(), 8);
    let targets = [host(1)];
    let mut work = controller.open_stage(&targets, 13, 1, 0, Instant::now());
    let start = Instant::now();
    let end = start + Duration::from_secs(60);
    let responder = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 250));
    let mut selected = 0;
    while !work.done() {
        let wave = controller.select(&mut work, start, end, 13);
        for selection in &wave.selections {
            send(&mut controller, &mut work, *selection, start);
            let outcome = if selected < 9 {
                control_reply(Duration::from_millis(5), responder)
            } else {
                Outcome::Silent
            };
            controller.settle(&mut work, *selection, outcome, start);
            selected += 1;
        }
    }
    let entry = &controller.hosts[0].control[&responder];
    assert_eq!(entry.count, 9);
    assert_eq!(entry.sequences.len(), CITED_SEQUENCES);
    let report = controller.finish((None, None));
    assert_eq!(report.conditions.len(), 1);
    assert_eq!(
        report.conditions[0].control_sequences.len(),
        CITED_SEQUENCES
    );
}

#[test]
fn the_host_deadline_anchors_at_selection_not_later_admission() {
    let mut config = config();
    config.host_timeout = Duration::from_millis(100);
    let mut controller = Controller::new(config, request_timeout(), 8);
    let targets = [host(1)];
    let mut work = controller.open_stage(&targets, 2, 1, 0, Instant::now());
    let t0 = Instant::now();
    let end = t0 + Duration::from_secs(60);
    let wave = controller.select(&mut work, t0, end, 1);
    let first = wave.selections[0];
    let t40 = t0 + Duration::from_millis(40);
    controller.admitted(&mut work, first);
    assert_eq!(
        controller.host_remaining(first.host, t40),
        Duration::from_millis(60)
    );
    controller.commit_attempt(&mut work, first, t40);
    controller.note_attempted(first);
    controller.settle(
        &mut work,
        first,
        reply(Duration::from_millis(5)),
        t40 + Duration::from_millis(5),
    );
    let t60 = t0 + Duration::from_millis(60);
    let wave = controller.select(&mut work, t60, end, 1);
    let second = wave.selections[0];
    assert_eq!(second.host_deadline, t0 + Duration::from_millis(100));
    let t100 = t0 + Duration::from_millis(100);
    let wave = controller.select(&mut work, t100, end, 1);
    assert!(wave.done);
    assert!(controller.is_incomplete(second.host));
}

#[test]
fn canceled_endpoints_release_their_unstarted_attempt_slots() {
    let mut config = config();
    config.host_timeout = Duration::from_millis(100);
    let mut controller = Controller::new(config, request_timeout(), 8);
    let targets = [host(1)];
    let start = Instant::now();
    let end = start + Duration::from_secs(60);

    let mut work = controller.open_stage(&targets, 1, 3, 0, start);
    let wave = controller.select(&mut work, start, end, 1);
    let selection = wave.selections[0];
    controller.admitted(&mut work, selection);
    controller.settle(&mut work, selection, Outcome::Omitted, start);
    assert_eq!(controller.take_canceled_responses(&mut work), 3);

    let mut work = controller.open_stage(&targets, 1, 3, 0, start);
    let wave = controller.select(&mut work, start, end, 1);
    let selection = wave.selections[0];
    send(&mut controller, &mut work, selection, start);
    controller.settle(&mut work, selection, Outcome::Silent, start);
    assert_eq!(controller.take_canceled_responses(&mut work), 0);
    let expired = start + config.host_timeout;
    controller.select(&mut work, expired, end, 1);
    assert_eq!(controller.take_canceled_responses(&mut work), 2);
    controller.select(&mut work, expired + Duration::from_millis(1), end, 1);
    assert_eq!(controller.take_canceled_responses(&mut work), 0);
}

#[test]
fn sequence_ordinals_follow_the_seeded_host_index_not_the_subset_slot() {
    let mut controller = Controller::new(config(), request_timeout(), 8);
    let targets = [host(1), host(2)];
    for target in &targets {
        controller.host_index(target);
    }
    let start = Instant::now();
    let mut work = controller.open_stage(&targets[1..], 1, 1, 4, start);
    let wave = controller.select(&mut work, start, start + Duration::from_secs(60), 4);
    assert_eq!(wave.selections[0].sequence, 5);
}
