// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The capture driver against scripted native sessions.

use super::*;
use crate::test_support::stream;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_netio::{self as net, capture as native, interface::Id};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, UNIX_EPOCH},
};
struct Session {
    metadata: native::Metadata,
    frames: VecDeque<native::Captured>,
    stopped: Arc<AtomicUsize>,
    failed: bool,
}
impl native::Session for Session {
    fn metadata(&self) -> &native::Metadata {
        &self.metadata
    }
    fn wait_ready(&mut self, _deadline: &Deadline) -> Result<(), net::Error> {
        Ok(())
    }
    fn next_captured_frame(
        &mut self,
        _deadline: &Deadline,
    ) -> Result<Option<native::Captured>, net::Error> {
        if let Some(frame) = self.frames.pop_front() {
            return Ok(Some(frame));
        }
        if self.failed {
            return Err(net::Error::Capture {
                message: "fixture receive failure".to_owned(),
                source: None,
            });
        }
        Ok(None)
    }
    fn shutdown(&mut self) -> Result<(), net::Error> {
        self.stopped.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn stats(&self) -> native::Stats {
        native::Stats {
            received_frames: 1,
            received_bytes: 4,
            ..Default::default()
        }
    }
}
struct Provider {
    captures: Mutex<VecDeque<Session>>,
}
impl native::Provider for Provider {
    type Capture = Session;
    fn arm_capture(
        &self,
        _: &native::Request,
        _deadline: &Deadline,
    ) -> Result<Session, net::Error> {
        Ok(self.captures.lock().unwrap().pop_front().unwrap())
    }
}
fn fixture(fail: bool) -> (Provider, GroupRequest, Vec<Arc<AtomicUsize>>) {
    let interfaces: Vec<_> = (0..2)
        .map(|index| Id {
            index: index + 7,
            name: format!("fixture{index}"),
        })
        .collect();
    let mut captures = VecDeque::new();
    let mut stopped = Vec::new();
    for (index, interface) in interfaces.iter().enumerate() {
        let counter = Arc::new(AtomicUsize::new(0));
        stopped.push(counter.clone());
        let link_type = if index == 0 {
            LinkType::RAW
        } else {
            LinkType::ETHERNET
        };
        let frame = Frame::new(UNIX_EPOCH, link_type, vec![index as u8; 4]).unwrap();
        captures.push_back(Session {
            metadata: native::Metadata {
                interface: interface.clone(),
                link_type,
                snap_length: 64,
                native: Default::default(),
            },
            frames: VecDeque::from([native::Captured::without_ingress_time(frame)]),
            stopped: counter,
            failed: fail && index == 0,
        });
    }
    (
        Provider {
            captures: Mutex::new(captures),
        },
        GroupRequest {
            interfaces,
            limits: native::Limits {
                max_frames: 8,
                max_bytes: 128,
                snap_length: 64,
                ..Default::default()
            },
            filter: None,
            promiscuous: false,
            native: Default::default(),
        },
        stopped,
    )
}
fn options(count: u64) -> workflow::Options {
    workflow::Options {
        window: Duration::from_secs(1),
        budget: packetcraftr::policy::CaptureBudget::new(&packetcraftr::policy::Policy {
            max_packets_per_operation: count,
            max_bytes_per_operation: 1024,
            ..Default::default()
        }),
        cancellation: None,
    }
}
#[test]
fn mixed_interfaces_share_output_ids_and_completion_statistics() {
    let (provider, request, stopped) = fixture(false);
    let (publisher, buffer) = stream(Command::Capture);
    drive(
        &provider,
        &request,
        options(2),
        Output {
            format: CaptureFormat::Ndjson,
            compression: Compression::None,
            selector: None,
            decoding: None,
            projector: None,
            files: None,
            stream: &publisher,
        },
    )
    .unwrap();
    let records = buffer.records();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0]["result"]["frame"]["interface"], 0);
    assert_eq!(records[1]["result"]["frame"]["interface"], 1);
    assert_eq!(records[2]["result"]["sources"].as_array().unwrap().len(), 2);
    assert_eq!(records[2]["stats"]["packets_attempted"], 2);
    assert!(
        stopped
            .iter()
            .all(|count| count.load(Ordering::SeqCst) == 1)
    );
    let validator = crate::test_support::schema_validator();
    for record in records {
        assert!(validator.is_valid(&record), "{record}");
    }
}
#[test]
fn runtime_failure_finalizes_saved_capture_and_retains_partial_evidence() {
    let (provider, request, stopped) = fixture(true);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("partial.pcapng.gz");
    let files = Files::new(
        super::files::Options {
            path: path.clone(),
            compression: Compression::Gzip,
            rotate_bytes: None,
            rotate_after: None,
            max_files: 1,
            retention: output::capture::Retention::Stop,
        },
        capture_file::Limits {
            max_frames: 10,
            max_bytes: 1024,
        },
    )
    .unwrap();
    let (publisher, buffer) = stream(Command::Capture);
    let error = drive(
        &provider,
        &request,
        options(10),
        Output {
            format: CaptureFormat::Ndjson,
            compression: Compression::None,
            selector: None,
            decoding: None,
            projector: None,
            files: Some(files),
            stream: &publisher,
        },
    )
    .unwrap_err();
    assert_eq!(
        error.message,
        "capture source 0 (fixture0) failed during receive"
    );
    assert_eq!(error.causes, ["capture failed: fixture receive failure"]);
    assert!(
        stopped
            .iter()
            .all(|count| count.load(Ordering::SeqCst) == 1)
    );
    let value = serde_json::to_value(error.output_error()).unwrap();
    assert_eq!(
        value["capture"]["summary"]["files"]["files"][0]["finalized"],
        true
    );
    assert_eq!(value["capture"]["summary"]["files"]["frames_written"], 2);
    assert_eq!(buffer.records().len(), 2);
    let input =
        compression::Input::new(std::fs::File::open(path).unwrap(), Default::default()).unwrap();
    let mut reader = capture_file::Reader::new(input).unwrap();
    assert_eq!(reader.next_frame().unwrap().unwrap().interface, Some(0));
    assert_eq!(reader.next_frame().unwrap().unwrap().interface, Some(1));
    assert!(reader.next_frame().unwrap().is_none());
}

fn single_session(
    link_type: LinkType,
    frames: Vec<Vec<u8>>,
) -> (Provider, GroupRequest, Vec<Arc<AtomicUsize>>) {
    let interface = Id {
        index: 7,
        name: "fixture0".to_owned(),
    };
    let counter = Arc::new(AtomicUsize::new(0));
    let session = Session {
        metadata: native::Metadata {
            interface: interface.clone(),
            link_type,
            snap_length: 256,
            native: Default::default(),
        },
        frames: frames
            .into_iter()
            .map(|bytes| {
                native::Captured::without_ingress_time(
                    Frame::new(UNIX_EPOCH, link_type, bytes).unwrap(),
                )
            })
            .collect(),
        stopped: counter.clone(),
        failed: false,
    };
    (
        Provider {
            captures: Mutex::new(VecDeque::from([session])),
        },
        GroupRequest {
            interfaces: vec![interface],
            limits: native::Limits {
                max_frames: 8,
                max_bytes: 4096,
                snap_length: 256,
                ..Default::default()
            },
            filter: None,
            promiscuous: false,
            native: Default::default(),
        },
        vec![counter],
    )
}

/// Ethernet/IPv4/UDP with a verified header checksum and four payload bytes.
fn ipv4_udp_frame() -> Vec<u8> {
    vec![
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0xf6, 0xc8, 0xc0, 0x00, 0x02, 0x01,
        0xc0, 0x00, 0x02, 0x02, 0xd4, 0x31, 0x30, 0x39, 0x00, 0x0c, 0x00, 0x00, 0xde, 0xad, 0xbe,
        0xef,
    ]
}

fn registry() -> Arc<packetcraftr_core::registry::Registry> {
    packetcraftr_core::protocol::builtin::registry()
}

fn dissecting() -> Option<Decoding> {
    Decoding::prepare(true, false, None, &registry(), 256).unwrap()
}

#[test]
fn dissected_frames_retain_bytes_metadata_and_diagnostics() {
    let mut bytes = ipv4_udp_frame();
    let truncated: Vec<u8> = bytes[..26].to_vec();
    // An unknown ethertype keeps a valid Ethernet header over raw payload.
    bytes[12] = 0x88;
    bytes[13] = 0xb5;
    let (provider, request, stopped) =
        single_session(LinkType::ETHERNET, vec![ipv4_udp_frame(), truncated, bytes]);
    let (publisher, buffer) = stream(Command::Capture);
    drive(
        &provider,
        &request,
        options(3),
        Output {
            format: CaptureFormat::Ndjson,
            compression: Compression::None,
            selector: None,
            decoding: dissecting(),
            projector: None,
            files: None,
            stream: &publisher,
        },
    )
    .unwrap();
    let records = buffer.records();
    assert_eq!(records.len(), 4);
    let validator = crate::test_support::schema_validator();
    for record in &records {
        assert!(validator.is_valid(record), "{record}");
    }
    let valid = &records[0]["result"];
    let layers: Vec<_> = valid["decoded"]["packet"]["layers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|layer| layer["protocol"].as_str().unwrap())
        .collect();
    assert_eq!(layers, ["ethernet", "ipv4", "udp", "raw"]);
    // Captured bytes and interface metadata survive beside the dissection.
    assert_eq!(
        valid["frame"]["bytes_hex"].as_str().unwrap(),
        "aabbccddeeff112233445566080045000020000100004011f6c8c0000201c0000202d4313039000c0000deadbeef"
    );
    assert_eq!(valid["frame"]["interface"], 0);
    assert!(
        valid["decoded"]["diagnostics"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    // Truncation surfaces as decode diagnostics, not a dropped frame.
    let truncated = &records[1]["result"];
    assert!(
        !truncated["decoded"]["diagnostics"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(truncated["frame"]["captured_length"], 26);
    // Unknown protocol payloads still dissect to their known layers.
    let unknown = &records[2]["result"];
    let layers: Vec<_> = unknown["decoded"]["packet"]["layers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|layer| layer["protocol"].as_str().unwrap())
        .collect();
    assert_eq!(layers.first(), Some(&"ethernet"));
    assert!(
        stopped
            .iter()
            .all(|count| count.load(Ordering::SeqCst) == 1)
    );
}

#[test]
fn projection_streams_bounded_fields_records() {
    let (provider, request, stopped) = single_session(LinkType::ETHERNET, vec![ipv4_udp_frame()]);
    let (publisher, buffer) = stream(Command::Capture);
    let projector = crate::commands::projection::Projector::prepare(
        &["frame.len".to_owned(), "ipv4.destination".to_owned()],
        4096,
        &registry(),
        Command::Capture,
        CaptureFormat::Ndjson.as_format(),
    )
    .unwrap();
    drive(
        &provider,
        &request,
        options(1),
        Output {
            format: CaptureFormat::Ndjson,
            compression: Compression::None,
            selector: None,
            decoding: Decoding::prepare(false, true, None, &registry(), 256).unwrap(),
            projector,
            files: None,
            stream: &publisher,
        },
    )
    .unwrap();
    let records = buffer.records();
    assert_eq!(records.len(), 2);
    let row = &records[0];
    assert_eq!(row["event"], "fields");
    assert_eq!(row["result"]["source_frame"], 1);
    assert_eq!(
        row["result"]["columns"],
        serde_json::json!(["frame.len", "ipv4.destination"])
    );
    assert_eq!(
        row["result"]["values"],
        serde_json::json!([46, "192.0.2.2"])
    );
    assert_eq!(records[1]["event"], "complete");
    assert_eq!(records[1]["result"]["frames_delivered"], 1);
    let validator = crate::test_support::schema_validator();
    for record in &records {
        assert!(validator.is_valid(record), "{record}");
    }
    assert!(
        stopped
            .iter()
            .all(|count| count.load(Ordering::SeqCst) == 1)
    );
}

#[test]
fn projection_exhaustion_stops_capture_and_retains_evidence() {
    let (provider, request, stopped) =
        single_session(LinkType::ETHERNET, vec![ipv4_udp_frame(), ipv4_udp_frame()]);
    let (publisher, buffer) = stream(Command::Capture);
    let projector = crate::commands::projection::Projector::prepare(
        &["frame.len".to_owned(), "ipv4.destination".to_owned()],
        16,
        &registry(),
        Command::Capture,
        CaptureFormat::Ndjson.as_format(),
    )
    .unwrap();
    let error = drive(
        &provider,
        &request,
        options(2),
        Output {
            format: CaptureFormat::Ndjson,
            compression: Compression::None,
            selector: None,
            decoding: Decoding::prepare(false, true, None, &registry(), 256).unwrap(),
            projector,
            files: None,
            stream: &publisher,
        },
    )
    .unwrap_err();
    assert_eq!(error.classification.code, "policy.projection_limit");
    let value = serde_json::to_value(error.output_error()).unwrap();
    assert_eq!(value["capture"]["summary"]["frames_delivered"], 1);
    assert!(
        stopped
            .iter()
            .all(|count| count.load(Ordering::SeqCst) == 1)
    );
    drop(buffer);
}

#[test]
fn sink_failure_stops_capture_and_shuts_sources_down() {
    struct Broken;
    impl io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("fixture sink failure"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let (provider, request, stopped) = single_session(LinkType::ETHERNET, vec![ipv4_udp_frame()]);
    let publisher = StreamEncoder::new(Command::Capture, Broken);
    let error = drive(
        &provider,
        &request,
        options(1),
        Output {
            format: CaptureFormat::Ndjson,
            compression: Compression::None,
            selector: None,
            decoding: dissecting(),
            projector: None,
            files: None,
            stream: &publisher,
        },
    )
    .unwrap_err();
    assert_eq!(error.classification.code, "io.stdout");
    let value = serde_json::to_value(error.output_error()).unwrap();
    assert_eq!(value["capture"]["summary"]["frames_delivered"], 1);
    assert!(
        stopped
            .iter()
            .all(|count| count.load(Ordering::SeqCst) == 1)
    );
}

#[test]
fn filtered_decoding_parks_one_dissection_per_emission() {
    let (provider, request, stopped) =
        single_session(LinkType::ETHERNET, vec![ipv4_udp_frame(), vec![0u8; 8]]);
    let (publisher, buffer) = stream(Command::Capture);
    let decoding = Decoding::prepare(
        true,
        false,
        Some("ipv4.destination == 192.0.2.2"),
        &registry(),
        256,
    )
    .unwrap();
    drive(
        &provider,
        &request,
        options(2),
        Output {
            format: CaptureFormat::Ndjson,
            compression: Compression::None,
            selector: None,
            decoding,
            projector: None,
            files: None,
            stream: &publisher,
        },
    )
    .unwrap();
    let records = buffer.records();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["result"]["source_frame"], 1);
    assert_eq!(
        records[0]["result"]["decoded"]["packet"]["layers"][1]["protocol"],
        "ipv4"
    );
    assert_eq!(records[1]["result"]["sources"][0]["matched_frames"], 1);
    assert!(
        stopped
            .iter()
            .all(|count| count.load(Ordering::SeqCst) == 1)
    );
}
