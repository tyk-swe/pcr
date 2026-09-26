// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]
mod composed_support;

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::{
    analysis,
    capture_file::{self, compression},
    protocol::builtin,
};
use std::io::{self, Cursor, Read};

// Short reads exercise adapter composition rather than only a Cursor fast path.
struct Short<R> {
    inner: R,
    chunk: usize,
}
impl<R: Read> Read for Short<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let size = bytes.len().min(self.chunk);
        self.inner.read(&mut bytes[..size])
    }
}

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(64 * 1024)];
    let chunk = usize::from(data.first().copied().unwrap_or(0)) + 1;
    let source = Short {
        inner: Cursor::new(data),
        chunk,
    };
    let Ok(input) = compression::Input::new(
        source,
        compression::Limits {
            max_encoded_bytes: 64 * 1024,
            max_decoded_bytes: 128 * 1024,
            max_window_log: 16,
        },
    ) else {
        return;
    };
    let Ok(mut reader) = capture_file::Reader::with_options(
        input,
        capture_file::ReaderOptions {
            max_size: 64 * 1024,
            max_total_interfaces: 32,
            ..capture_file::ReaderOptions::default()
        },
    ) else {
        return;
    };
    let mut options = composed_support::options();
    options.plan = analysis::Plan::physical(Default::default());
    if let Ok(summary) = analysis::run(&mut reader, builtin::registry(), &options, |_| Ok(())) {
        assert!(summary.frames_read <= options.limits.max_frames);
    }
});
