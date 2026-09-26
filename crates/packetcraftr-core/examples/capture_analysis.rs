// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Records a small classic-PCAP fixture in memory, then runs the shared
//! analysis pipeline with the stats collector over it — the same pipeline the
//! CLI's `stats`/`expert`/`follow` commands drive for files. Fully offline;
//! no native features required.
//!
//!     cargo run -p packetcraftr-core --example capture_analysis

use std::io::Cursor;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr_core::analysis::{self, stats};
use packetcraftr_core::build::{Builder, Options as BuildOptions};
use packetcraftr_core::capture_file::{Format, Reader, Writer};
use packetcraftr_core::codec::Context as BuildContext;
use packetcraftr_core::expression;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::builtin;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let registry = builtin::registry();

    // Materialize two datagrams between documentation (TEST-NET-1) addresses
    // and record them as a classic-PCAP fixture held entirely in memory.
    let mut capture = Vec::new();
    {
        let mut writer = Writer::new(&mut capture, Format::Pcap, LinkType::IPV4)?;
        for (dport, seconds) in [(9_u16, 0_u64), (80, 1)] {
            let packet = expression::parse(
                &format!(
                    "ipv4(src=192.0.2.1,dst=192.0.2.2)/udp(sport=12345,dport={dport})/raw(text=fixture)"
                ),
                &registry,
                expression::Options::default(),
            )?;
            let built = Builder::new(Arc::clone(&registry)).build(
                packet,
                BuildContext::default(),
                BuildOptions::default(),
            )?;
            writer.write_frame(&Frame::new(
                UNIX_EPOCH + Duration::from_secs(seconds),
                LinkType::IPV4,
                built.bytes,
            )?)?;
        }
    }

    // Run the analysis loop and fold matched frames into the stats tables.
    let mut reader = Reader::new(Cursor::new(&capture))?;
    let mut collector = stats::Collector::new(Duration::from_secs(1))?;
    let options = analysis::Options::default();
    let summary = analysis::run(&mut reader, registry, &options, |record| {
        collector.observe(&record);
        Ok(())
    })?;
    let report = collector.finish(&summary);

    println!(
        "read {} frame(s), matched {}; captured {} byte(s)",
        summary.frames_read, summary.frames_matched, report.bytes
    );
    if let Some(duration) = report.duration() {
        println!("matched span duration: {duration:?}");
    }
    for interface in &report.interfaces {
        println!("interface {interface:?}");
    }
    for protocol in &report.protocols {
        println!(
            "protocol {}: {} frame(s)",
            protocol.protocol, protocol.frames
        );
    }
    for endpoint in &report.endpoints {
        println!("endpoint {}", endpoint.address);
    }
    Ok(())
}
