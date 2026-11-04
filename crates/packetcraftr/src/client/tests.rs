// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use std::convert::Infallible;
use std::time::{Duration, Instant, SystemTime};

#[derive(Clone)]
struct FixedClock {
    now: Instant,
    wall: SystemTime,
}

impl Clock for FixedClock {
    type Error = Infallible;

    fn now(&self) -> Instant {
        self.now
    }

    fn wall_now(&self) -> SystemTime {
        self.wall
    }

    fn sleep(&self, _delay: Duration, _deadline: &Deadline) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn composed() -> Client<u32> {
    Client::new(
        Arc::new(Registry::default()),
        Policy {
            max_packets_per_operation: 7,
            ..Policy::default()
        },
        42,
    )
}

#[test]
fn accessors_return_the_composed_parts() {
    let registry = Arc::new(Registry::default());
    let client = Client::new(
        registry.clone(),
        Policy {
            max_packets_per_operation: 7,
            ..Policy::default()
        },
        42,
    )
    .with_runtime(Runtime::new(3).unwrap());
    assert!(Arc::ptr_eq(client.registry(), &registry));
    assert_eq!(client.policy().max_packets_per_operation, 7);
    assert_eq!(client.providers(), &42);
    assert_eq!(client.runtime().capacity(), 3);
}

#[test]
fn injected_clock_drives_both_times() {
    let now = Instant::now();
    let wall = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let client = composed().with_clock(FixedClock { now, wall });
    assert_eq!(client.now(), now);
    assert_eq!(client.wall_now(), wall);
    assert_eq!(client.policy().max_packets_per_operation, 7);
}

#[test]
fn check_cancelled_follows_the_composed_signal() {
    let signal = Cancellation::default();
    let client = composed().with_cancellation(signal.clone());
    assert!(client.check_cancelled().is_ok());
    signal.cancel();
    assert!(client.check_cancelled().is_err());
    assert!(composed().check_cancelled().is_ok());
}

#[test]
fn deadline_ceiling_cannot_be_extended() {
    let now = Instant::now();
    let clock = FixedClock {
        now,
        wall: SystemTime::UNIX_EPOCH,
    };
    let at = move |limit: Duration| Deadline::with_time_source(limit, move || now);
    let client = composed()
        .with_clock(clock)
        .with_deadline(at(Duration::from_millis(50)))
        .with_deadline(at(Duration::from_secs(60)));
    assert_eq!(
        client.deadline(Duration::from_secs(60)).remaining(),
        Ok(Duration::from_millis(50))
    );
}

#[test]
fn neighbor_options_validate_before_replacement() {
    let client = composed()
        .with_neighbor_options(neighbor::Options::default())
        .unwrap();
    assert!(client.check_cancelled().is_ok());
    let invalid = composed().with_neighbor_options(neighbor::Options {
        max_attempts: 0,
        ..neighbor::Options::default()
    });
    assert!(invalid.is_err());
}
