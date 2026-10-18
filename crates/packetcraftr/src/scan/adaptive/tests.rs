// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Instant;

use crate::target::SelectedAddress;

use super::work::Endpoint;
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

#[test]
fn completed_prefix_discovery_is_linear() {
    for hosts in [1, 4, 32] {
        for endpoints in [32, 128, 512] {
            let now = Instant::now();
            let mut controller = Controller::new(config(), Duration::from_millis(100), 4);
            let mut work = controller.open_stage(&targets(hosts), endpoints, 1, 100, now);
            let mut completed = 0;
            while !work.done() {
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
                    Outcome::Reply {
                        latency: Duration::from_millis(1),
                        responder: targets(hosts)[selection.slot].address,
                        control: false,
                    },
                    now,
                );
                completed += 1;
            }
            assert_eq!(completed, hosts * endpoints);
            assert!(work.operations.ready <= 16 * completed + hosts);
            assert!(work.operations.time <= 16 * completed + 2 * hosts);
            if hosts == 1 {
                eprintln!(
                    "N={endpoints}: endpoint visits={}, ready-index mutations={}, time-index mutations={}",
                    work.operations.discovery, work.operations.ready, work.operations.time
                );
            }
            assert!(
                work.operations.discovery <= 3 * completed,
                "{hosts} hosts x {endpoints}: {} endpoint visits",
                work.operations.discovery
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
    assert_eq!(controller.finish(Ceilings::default()).incomplete.len(), 1);
}

struct ConservativeWork {
    endpoints: Vec<Vec<Endpoint>>,
    cursor: usize,
    canceled: usize,
}

impl ConservativeWork {
    fn select(
        &mut self,
        controller: &Controller,
        work: &Work,
        now: Instant,
        end: Instant,
        capacity: usize,
    ) -> Vec<(usize, usize, u32)> {
        for (index, slot) in work.slots.iter().enumerate() {
            if controller.host_expired(slot.host, now) {
                for endpoint in &mut self.endpoints[index] {
                    if !endpoint.finished {
                        self.canceled += work.max_attempts.saturating_sub(endpoint.sent) as usize;
                        endpoint.finished = true;
                    }
                }
            }
        }
        let mut picked = std::collections::HashSet::new();
        let mut gapped = std::collections::HashSet::new();
        let mut selected = Vec::new();
        let mut misses = 0;
        while selected.len() < capacity && misses < work.slots.len() {
            let index = self.cursor;
            self.cursor = (self.cursor + 1) % work.slots.len();
            let host = work.slots[index].host;
            if controller.host_expired(host, now)
                || controller.hosts[host].min_gap > Duration::ZERO && gapped.contains(&index)
                || !controller.host_gap_ready(host, now)
            {
                misses += 1;
                continue;
            }
            let endpoint =
                self.endpoints[index]
                    .iter()
                    .enumerate()
                    .find_map(|(endpoint, state)| {
                        (!state.finished
                            && !state.pending
                            && state.sent < work.max_attempts
                            && state.ready_at <= now
                            && !picked.contains(&(index, endpoint)))
                        .then_some(endpoint)
                    });
            let Some(endpoint) = endpoint else {
                misses += 1;
                continue;
            };
            picked.insert((index, endpoint));
            gapped.insert(index);
            let deadline = controller.hosts[host]
                .first_admission
                .map_or(now + controller.config.host_timeout, |started| {
                    started + controller.config.host_timeout
                })
                .min(end);
            if now >= deadline {
                misses += 1;
                continue;
            }
            selected.push((index, endpoint, self.endpoints[index][endpoint].sent + 1));
            misses = 0;
        }
        selected
    }

    fn admitted(&mut self, selection: Selection) {
        let endpoint = &mut self.endpoints[selection.slot][selection.endpoint];
        endpoint.pending = true;
        endpoint.sent = selection.attempt;
    }

    fn settle(
        &mut self,
        selection: Selection,
        outcome: Outcome,
        controller: &Controller,
        max_attempts: u32,
        now: Instant,
    ) {
        let endpoint = &mut self.endpoints[selection.slot][selection.endpoint];
        endpoint.pending = false;
        match outcome {
            Outcome::Silent | Outcome::UnqualifiedSilence if selection.attempt < max_attempts => {
                endpoint.ready_at = now + controller.config.retry_delay(selection.attempt + 1);
            }
            Outcome::Reply { .. } | Outcome::Silent | Outcome::UnqualifiedSilence => {
                endpoint.finished = true;
            }
            Outcome::Aborted | Outcome::Omitted => {
                if !endpoint.finished {
                    self.canceled += max_attempts.saturating_sub(endpoint.sent) as usize;
                }
                endpoint.finished = true;
            }
        }
    }
}

#[test]
fn indexed_readiness_matches_conservative_transitions_with_pacing_retries_and_expiry() {
    for hosts in [1, 3, 8] {
        let start = Instant::now();
        let mut settings = config();
        settings.host_timeout = Duration::from_millis(300);
        let mut controller = Controller::new(settings, Duration::from_millis(100), 8);
        let targets = targets(hosts);
        for (index, target) in targets.iter().enumerate() {
            let host = controller.host_index(target);
            if index % 2 == 0 {
                controller.hosts[host].min_gap = Duration::from_millis(15);
            }
        }
        let mut work = controller.open_stage(&targets, 32, 3, 0, start);
        let mut conservative = ConservativeWork {
            endpoints: work
                .slots
                .iter()
                .map(|slot| slot.endpoints.clone())
                .collect(),
            cursor: 0,
            canceled: 0,
        };
        let mut active = Vec::<(Instant, Selection)>::new();
        let mut accounted_canceled = 0;
        for tick in 0..1000 {
            let now = start + Duration::from_millis(tick * 5);
            let mut index = 0;
            while index < active.len() {
                if active[index].0 > now {
                    index += 1;
                    continue;
                }
                let (_, selection) = active.remove(index);
                let outcome = match selection.sequence % 5 {
                    0 => Outcome::Silent,
                    1 => Outcome::Aborted,
                    _ => Outcome::Reply {
                        latency: Duration::from_millis(5),
                        responder: targets[selection.slot].address,
                        control: false,
                    },
                };
                conservative.settle(selection, outcome, &controller, work.max_attempts, now);
                controller.settle(&mut work, selection, outcome, now);
            }
            let capacity = 8usize.saturating_sub(active.len());
            let expected = conservative.select(
                &controller,
                &work,
                now,
                start + Duration::from_secs(2),
                capacity,
            );
            let wave = controller.select(&mut work, now, start + Duration::from_secs(2), capacity);
            assert_eq!(
                wave.selections
                    .iter()
                    .map(|s| (s.slot, s.endpoint, s.attempt))
                    .collect::<Vec<_>>(),
                expected,
                "hosts={hosts}, tick={tick}"
            );
            accounted_canceled += controller.take_canceled_responses(&mut work);
            assert_eq!(accounted_canceled, conservative.canceled);
            // Exercise a discarded suffix after pacing or admission refusal.
            let prefix = if tick % 3 == 0 {
                1
            } else {
                wave.selections.len()
            };
            for selection in wave.selections.into_iter().take(prefix) {
                if selection.sequence % 11 == 0 {
                    conservative.settle(
                        selection,
                        Outcome::Omitted,
                        &controller,
                        work.max_attempts,
                        now,
                    );
                    controller.settle(&mut work, selection, Outcome::Omitted, now);
                } else {
                    conservative.admitted(selection);
                    controller.admitted(&mut work, selection);
                    controller.confirm_send(&mut work, selection, now);
                    active.push((
                        now + Duration::from_millis(5 + selection.sequence % 7 * 5),
                        selection,
                    ));
                }
            }
            assert!(work.wakes.len() <= hosts);
            assert!(work.expirations.len() <= hosts);
            assert!(work.runnable.len() <= hosts);
            assert!(
                work.slots
                    .iter()
                    .all(|slot| slot.ready.len() + slot.delayed.len() <= slot.endpoints.len())
            );
            if work.done() && active.is_empty() {
                accounted_canceled += controller.take_canceled_responses(&mut work);
                assert_eq!(accounted_canceled, conservative.canceled);
                break;
            }
            assert!(tick < 999, "scheduler must finish");
        }
    }
}

#[test]
fn paced_host_cannot_queue_again_before_its_admission_commits_or_is_omitted() {
    for omit in [false, true] {
        let now = Instant::now();
        let mut controller = Controller::new(config(), Duration::from_millis(100), 4);
        let targets = targets(1);
        let host = controller.host_index(&targets[0]);
        controller.hosts[host].min_gap = Duration::from_millis(10);
        let mut work = controller.open_stage(&targets, 3, 1, 0, now);
        let first = controller
            .select(&mut work, now, now + Duration::from_secs(5), 4)
            .selections[0];
        controller.admitted(&mut work, first);
        assert!(
            controller
                .select(&mut work, now, now + Duration::from_secs(5), 4)
                .selections
                .is_empty()
        );
        if omit {
            controller.settle(&mut work, first, Outcome::Omitted, now);
            assert_eq!(
                controller
                    .select(&mut work, now, now + Duration::from_secs(5), 4)
                    .selections
                    .len(),
                1
            );
        } else {
            controller.confirm_send(&mut work, first, now);
            assert!(
                controller
                    .select(&mut work, now, now + Duration::from_secs(5), 4)
                    .selections
                    .is_empty()
            );
            assert_eq!(
                controller
                    .select(
                        &mut work,
                        now + Duration::from_millis(10),
                        now + Duration::from_secs(5),
                        4
                    )
                    .selections
                    .len(),
                1
            );
        }
        assert_eq!(controller.hosts[host].uncommitted, 0);
    }
}

#[test]
fn provisional_silence_retries_neutrally_and_only_final_clean_quality_promotes_losses() {
    for coverage in [
        crate::scan::Coverage::NoReportedLoss,
        crate::scan::Coverage::Incomplete,
        crate::scan::Coverage::Unknown,
    ] {
        let now = Instant::now();
        let mut controller = Controller::new(config(), Duration::from_millis(100), 4);
        controller.begin_observation_stage();
        let mut work = controller.open_stage(&targets(1), 1, 2, 0, now);
        let first = controller
            .select(&mut work, now, now + Duration::from_secs(5), 4)
            .selections[0];
        controller.admitted(&mut work, first);
        controller.confirm_send(&mut work, first, now);
        controller.settle(&mut work, first, Outcome::UnqualifiedSilence, now);
        assert_eq!(controller.window(), 4);
        assert_eq!(controller.hosts[0].losses, 0);
        let retry = controller
            .select(
                &mut work,
                now + config().retry_backoff,
                now + Duration::from_secs(5),
                4,
            )
            .selections[0];
        controller.admitted(&mut work, retry);
        controller.confirm_send(&mut work, retry, now + config().retry_backoff);
        controller.settle(
            &mut work,
            retry,
            Outcome::UnqualifiedSilence,
            now + config().retry_backoff,
        );
        assert!(work.done());
        assert_eq!(controller.window(), 4);
        assert_eq!(controller.hosts[0].pending_losses, 2);
        controller.qualify_pending(coverage);
        assert_eq!(
            controller.hosts[0].losses,
            if coverage.permits_silence() { 2 } else { 0 }
        );
        assert_eq!(controller.is_incomplete(0), !coverage.permits_silence());
        assert_eq!(
            controller.window(),
            if coverage.permits_silence() { 2 } else { 4 }
        );
        assert_eq!(controller.hosts[0].pending_losses, 0);
        assert!(controller.hosts[0].pending_loss_sequences.is_empty());
        assert!(controller.cohort_members.is_empty());
        assert!(controller.halved.is_empty());
    }
}

#[test]
fn deferred_interface_admission_preserves_host_pacing_across_refill_polls() {
    let now = Instant::now();
    let mut controller = Controller::new(config(), Duration::from_millis(100), 3);
    let targets = targets(2);
    let deferred = controller.host_index(&targets[1]);
    controller.hosts[deferred].min_gap = Duration::from_millis(10);
    let mut work = controller.open_stage(&targets, 3, 1, 0, now);
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
    controller.settle(
        &mut work,
        quick,
        Outcome::Reply {
            latency: Duration::from_millis(1),
            responder: targets[0].address,
            control: false,
        },
        now,
    );
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
}
