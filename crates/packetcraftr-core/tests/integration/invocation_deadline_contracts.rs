// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

use std::io::{self, Cursor, Read};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use packetcraftr_core::budget::Deadline;

fn clock(limit_ms: u64) -> (Arc<Deadline>, Arc<AtomicU64>) {
    let ticks = Arc::new(AtomicU64::new(0));
    let observed = ticks.clone();
    let start = Instant::now();
    (
        Arc::new(Deadline::with_time_source(
            Duration::from_millis(limit_ms),
            move || start + Duration::from_millis(observed.load(Ordering::SeqCst)),
        )),
        ticks,
    )
}

struct Ticking {
    source: Cursor<Vec<u8>>,
    ticks: Arc<AtomicU64>,
}
impl Read for Ticking {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.ticks.fetch_add(1, Ordering::SeqCst);
        self.source.read(buffer)
    }
}

#[test]
fn multiple_parents_keep_tightest_ceiling() {
    let (tight, ticks) = clock(5);
    let child = Deadline::new(Duration::from_secs(60))
        .with_parent(Some(tight))
        .with_parent(Some(Arc::new(Deadline::new(Duration::from_secs(120)))));
    ticks.store(6, Ordering::SeqCst);
    assert!(child.enforce().is_err());
    assert!(child.remaining().is_err());
}
