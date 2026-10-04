// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use packetcraftr_core::{
    analysis::{self, Collector, CollectorNeeds, FrameRecord, Session},
    capture_file::{PcapOptions, Reader},
    error::BoundaryError,
    protocol::{builtin, transport::Udp},
    transform::{FragmentOptions, fragment},
};
use std::io::Cursor;
struct Physical;
impl Collector for Physical {
    type Event = ();
    type Summary = ();
    fn needs(&self) -> CollectorNeeds {
        CollectorNeeds::default()
    }
    fn observe(&mut self, _: &FrameRecord<'_>) -> Result<Vec<()>, BoundaryError> {
        Ok(vec![])
    }
    fn finish(self, _: &analysis::Summary) -> Result<(Vec<()>, ()), BoundaryError> {
        Ok((vec![], ()))
    }
}
#[test]
fn physical_collector_preserves_requested_ip_lifecycle_evidence() {
    let frame = common::packets::transport_frame(
        false,
        true,
        Udp {
            source_port: 40000,
            destination_port: 40001,
            ..Default::default()
        },
        &[42; 100],
    );
    let fragments = fragment(
        &frame,
        FragmentOptions {
            mtu: 60,
            ..Default::default()
        },
    )
    .unwrap();
    let bytes = common::pcap::pcap_bytes(PcapOptions::default(), &fragments);
    let mut reader = Reader::new(Cursor::new(bytes)).unwrap();
    let mut events = 0;
    Session::new(
        builtin::registry(),
        analysis::Options::default(),
        Physical,
        None,
    )
    .run(
        &mut reader,
        |_| {
            events += 1;
            Ok(())
        },
        |_| Ok(()),
    )
    .unwrap();
    assert!(events > 0, "explicit default plan must retain IP events");
}
