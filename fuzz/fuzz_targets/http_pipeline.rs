// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]
mod composed_support;

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::{
    analysis::{self, application, expert, http},
    capture_file,
    diagnostic::Severity,
    error::{BoundaryError, Classification, Kind},
    protocol::builtin,
};
use std::io::Cursor;

/// A bounded [`http::BodySink`] that counts delivered entity bytes and refuses
/// the next span once `fail_at` bytes have accumulated. The collector must
/// propagate the refusal as an analysis failure, never a message status.
struct CountingSink {
    bytes: u64,
    fail_at: u64,
}

impl http::BodySink for CountingSink {
    fn write(&mut self, bytes: &[u8]) -> Result<(), BoundaryError> {
        if self.bytes >= self.fail_at {
            return Err(BoundaryError::new(
                "bounded fuzz sink refusal",
                Classification::new("fuzz.body_sink", Kind::Io, None),
                Vec::new(),
            ));
        }
        self.bytes = self.bytes.saturating_add(bytes.len() as u64);
        Ok(())
    }
}

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
    let mut sink = CountingSink {
        bytes: 0,
        fail_at: u64::from(data.get(1).copied().unwrap_or(255)),
    };
    // One input byte selects the message whose body spans reach the sink,
    // exercising `consume_with` through the collector over arbitrary input.
    let selected = 1 + u64::from(data.first().copied().unwrap_or(0)) % 4;
    let mut collector = http::Collector::new(
        application::Limits {
            max_messages: 32,
            max_streams: 16,
            max_buffer_bytes: 65536,
            max_retained_bytes: 1024 * 1024,
            max_source_spans: 1024,
        },
        [80, 8080],
        65536,
    )
    .unwrap()
    .with_transactions()
    .expect("pre-observe transaction configuration")
    .with_body_sink(selected, &mut sink)
    .expect("pre-observe body selection");
    // The gate counts every finding of the same completed run, including the
    // trailing events only `finish` emits; its verdict truth table is checked.
    let mut findings = expert::Collector::new();
    let mut gate = expert::gate::Gate::new(expert::gate::Options {
        min_severity: [Severity::Info, Severity::Warning, Severity::Error]
            [usize::from(data.get(2).copied().unwrap_or(0)) % 3],
        allow_findings: u64::from(data.get(3).copied().unwrap_or(0)),
        minimum_frames: 1 + u64::from(data.get(4).copied().unwrap_or(0)),
    })
    .expect("positive minimum frame coverage");
    let mut events = Vec::new();
    let Ok(summary) = analysis::run(&mut reader, builtin::registry(), &options, |record| {
        events.extend(
            collector
                .observe(&record)
                .map_err(BoundaryError::from_error)?,
        );
        for finding in findings.observe(&record) {
            gate.observe(&finding).map_err(BoundaryError::from_error)?;
        }
        Ok(())
    }) else {
        return;
    };
    let (tail, _) = findings.finish(&summary);
    for finding in &tail {
        let _ = gate.observe(finding);
    }
    let report = gate.finish(summary.frames_matched);
    assert!(report.triggering_findings <= report.findings_observed);
    let expected = if report.triggering_findings > report.allow_findings {
        expert::gate::Verdict::Fail
    } else if report.frames_matched < report.minimum_frames {
        expert::gate::Verdict::Inconclusive
    } else {
        expert::gate::Verdict::Pass
    };
    assert_eq!(report.verdict, expected);
    assert_eq!(report.frames_matched, summary.frames_matched);
    if let Ok((tail, summary)) = collector.finish(&summary) {
        events.extend(tail);
        assert!(summary.messages <= 32);
        assert!(sink.bytes <= 65536);
        // Every entity span of a completed selected message reached the sink,
        // so a successful run leaves the delivered count equal to body_bytes.
        let completed = events.iter().any(|event| {
            matches!(
                event,
                http::Event::Message(message)
                    if message.index == selected && message.status == http::Status::Complete
            )
        });
        if completed {
            let body_bytes = events
                .iter()
                .find_map(|event| match event {
                    http::Event::Message(message) if message.index == selected => {
                        Some(message.body_bytes)
                    }
                    _ => None,
                })
                .expect("the completed selected message is present");
            assert_eq!(sink.bytes, body_bytes);
        }
    }
});
