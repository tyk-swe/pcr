// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic operation clocks; no sleeps or wall-time thresholds.
mod common;

use std::io::{self, Cursor, Read};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::Classified;
use packetcraftr_core::{analysis, capture_file};

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

#[test]
fn starting_a_second_analysis_does_not_restart_the_invocation() {
    let (deadline, ticks) = clock(5);
    let frames = [common::udp_frame(
        &common::registry(),
        std::time::UNIX_EPOCH + Duration::from_secs(1),
        common::CLIENT,
        common::SERVER,
        40000,
        9000,
        b"hello",
    )];
    let options = analysis::Options {
        deadline: Some(deadline),
        ..Default::default()
    };
    ticks.store(3, Ordering::SeqCst);
    analysis::run(
        &mut common::reader(&frames),
        common::registry(),
        &options,
        |_| Ok(()),
    )
    .unwrap();
    ticks.store(6, Ordering::SeqCst);
    let error = analysis::run(
        &mut common::reader(&frames),
        common::registry(),
        &options,
        |_| Ok(()),
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.duration_limit");
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
fn metadata_and_eof_share_the_packet_analysis_clock() {
    let (deadline, ticks) = clock(5);
    let mut bytes = Vec::new();
    // PCAPNG section, followed by valid opaque 12-byte blocks.
    bytes.extend_from_slice(&0x0a0d0d0au32.to_le_bytes());
    bytes.extend_from_slice(&28u32.to_le_bytes());
    bytes.extend_from_slice(&0x1a2b3c4du32.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&u64::MAX.to_le_bytes());
    bytes.extend_from_slice(&28u32.to_le_bytes());
    for _ in 0..128 {
        bytes.extend_from_slice(&0x12345678u32.to_le_bytes());
        bytes.extend_from_slice(&12u32.to_le_bytes());
        bytes.extend_from_slice(&12u32.to_le_bytes());
    }
    let mut reader = capture_file::Reader::new(Ticking {
        source: Cursor::new(bytes),
        ticks: ticks.clone(),
    })
    .unwrap();
    ticks.store(0, Ordering::SeqCst);
    let options = analysis::Options {
        deadline: Some(deadline),
        ..Default::default()
    };
    let error = analysis::run(&mut reader, common::registry(), &options, |_| Ok(())).unwrap_err();
    assert_eq!(error.classification().code, "policy.duration_limit");
    assert!(
        ticks.load(Ordering::SeqCst) < 128,
        "stopped before consuming all metadata"
    );
}

#[test]
fn multiple_parents_preserve_the_tightest_existing_ceiling() {
    let (tight, ticks) = clock(5);
    let child = Deadline::new(Duration::from_secs(60))
        .with_parent(Some(tight))
        .with_parent(Some(Arc::new(Deadline::new(Duration::from_secs(120)))));
    ticks.store(6, Ordering::SeqCst);
    assert!(child.enforce().is_err());
    assert!(child.remaining().is_err());
}

#[test]
fn a_panicking_sink_does_not_leave_its_phase_clock_on_the_reader() {
    let (parent, parent_ticks) = clock(60);
    let (phase, phase_ticks) = clock(5);
    let frames = [common::udp_frame(
        &common::registry(),
        std::time::UNIX_EPOCH + Duration::from_secs(1),
        common::CLIENT,
        common::SERVER,
        40000,
        9000,
        b"fixture",
    )];
    let mut reader = common::reader(&frames).with_deadline(parent);
    let options = analysis::Options {
        deadline: Some(phase),
        ..Default::default()
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = analysis::run(&mut reader, common::registry(), &options, |_| {
            panic!("adversarial sink");
        });
    }));
    assert!(result.is_err());
    phase_ticks.store(6, Ordering::SeqCst);
    parent_ticks.store(6, Ordering::SeqCst);
    // Only the original 60ms parent remains; the failed run's 5ms parent is gone.
    reader.rewind().unwrap();
    assert!(reader.next_frame().unwrap().is_some());
}
