// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use packetcraftr_core::{
    analysis::{self, pcap::Reader, stats::Collector},
    protocol::builtin,
};
use std::{io::Cursor, time::Duration};

#[test]
fn downstream_offline_collector_preserves_capture_clock_evidence() {
    let data = include_bytes!("../../examples/captures/clock-regression.pcap");
    let mut reader = Reader::new(Cursor::new(data)).unwrap();
    let mut collector = Collector::new(Duration::from_secs(1)).unwrap();
    let summary = analysis::run(
        &mut reader,
        builtin::registry(),
        &analysis::Options::default(),
        |record| {
            collector.observe(&record);
            Ok(())
        },
    )
    .unwrap();
    let report = collector.finish(&summary);
    assert_eq!(summary.frames_read, 3);
    assert_eq!(report.frames, 3);
    assert_eq!(report.clock.regressions, 1);
}
