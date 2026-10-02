// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]
mod composed_support;
mod http2_support;

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::{analysis, capture_file, error::BoundaryError, protocol::builtin};
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(64 * 1024)];
    let Ok(mut reader) = capture_file::Reader::with_limits(
        Cursor::new(data),
        capture_file::ReaderLimits {
            max_size: 64 * 1024,
            max_total_interfaces: 32,
            ..capture_file::ReaderLimits::default()
        },
    ) else {
        return;
    };
    let mut options = composed_support::options();
    options.tcp_events = true;
    options.track_sources = true;
    let mut collector = http2_support::collector();
    let Ok(summary) = analysis::run(&mut reader, builtin::registry(), &options, |record| {
        let _ = collector
            .observe(&record)
            .map_err(BoundaryError::from_error)?;
        Ok(())
    }) else {
        return;
    };
    if let Ok((_, summary)) = collector.finish(&summary) {
        assert!(summary.messages <= 32);
        assert!(summary.connections <= 32);
    }
});
