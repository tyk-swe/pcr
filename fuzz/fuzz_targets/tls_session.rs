#![no_main]

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::analysis::Options;
use packetcraftr_core::analysis::pcap::{Reader, ReaderOptions};
use packetcraftr_core::analysis::tls::{Collector, Limits};
use packetcraftr_core::protocol::builtin;
use std::io::Cursor;

// Runs a capture through the analysis pipeline with TCP reassembly on and
// folds every frame into the TLS session collector, the same path the `tls`
// command takes. The collector, not the parsers, is under test here: the
// record and handshake parsers have their own target.
fuzz_target!(|data: &[u8]| {
    let mut reader_options = ReaderOptions::default();
    reader_options.max_size = 64 * 1024;
    reader_options.max_total_interfaces = 16;
    let Ok(mut reader) = Reader::with_options(Cursor::new(data), reader_options) else {
        return;
    };

    let registry = builtin::registry();
    let mut collector = Collector::new(Limits {
        max_sessions: 64,
        max_buffered_bytes: 1024 * 1024,
    });
    let mut sessions = Vec::new();
    let options = Options {
        tcp_events: true,
        ..Options::default()
    };
    let Ok(summary) = packetcraftr_core::analysis::run(&mut reader, registry, &options, |record| {
        sessions.extend(collector.observe(&record));
        Ok(())
    }) else {
        return;
    };
    let (trailing, tls_summary) = collector.finish(&summary);
    sessions.extend(trailing);

    for event in &sessions {
        // Serialization is what the CLI does with every session; a session
        // that assembled must also render.
        let _ = serde_json::to_string(&event.session);
    }
    assert!(
        tls_summary.evicted_sessions <= tls_summary.sessions,
        "more sessions evicted than were ever tracked"
    );
});
