// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common;
use packetcraftr::scan::{Event, Qualification, Stage};
use packetcraftr_cli::output::{
    self, contract::Command, envelope::Published, stream::StreamEncoder,
};
use packetcraftr_netio::capture::ObservationQuality as Quality;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);
impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn qualification_adapter_uses_current_family_and_rejects_unsettled_coverage() {
    for coverage in [
        Quality::Unknown,
        Quality::NoReportedLoss,
        Quality::Incomplete,
    ] {
        let writer = Buffer::default();
        let stream = StreamEncoder::new(Command::Scan, writer.clone());
        let event =
            Event::Qualification(Qualification::new(Stage::Scan, 7, 100, coverage).unwrap());
        stream
            .emit_published(Published::<output::scan::Event>::try_from(event).unwrap())
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&writer.0.lock().unwrap()).unwrap();
        assert_eq!(value["schema"], "packetcraftr.output/v18");
        assert_eq!(value["event"], "observation_quality");
        assert_eq!(value["sequence"], 0);
        assert!(common::schema_validator().is_valid(&value));
        let mut invalid = value;
        invalid["result"]["qualification"]["coverage"] = "pending".into();
        assert!(!common::schema_validator().is_valid(&invalid));
    }
}
