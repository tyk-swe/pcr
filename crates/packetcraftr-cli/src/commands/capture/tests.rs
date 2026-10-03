// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::test_support::stream;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_netio::{
    self as net,
    capture::{self as native, GroupRequest},
    interface::Id,
};
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
fn client(
    provider: Provider,
    count: u64,
) -> packetcraftr::Client<impl packetcraftr::CaptureProviders> {
    crate::commands::test_support::capturing(
        registry(),
        packetcraftr::policy::Policy {
            max_packets_per_operation: count,
            max_bytes_per_operation: 1024,
            ..Default::default()
        },
        provider,
    )
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

#[test]
fn projection_streams_bounded_fields_records() {
    let (provider, request, stopped) = single_session(LinkType::ETHERNET, vec![ipv4_udp_frame()]);
    let (publisher, buffer) = stream(Command::Capture);
    let projector = crate::rendering::Projector::prepare(
        &["frame.len".to_owned(), "ipv4.destination".to_owned()],
        4096,
        &registry(),
        Command::Capture,
        CaptureFormat::Ndjson.as_format(),
    )
    .unwrap();
    drive(
        &client(provider, 1),
        workflow::Request::new(request, Duration::from_secs(1)),
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
