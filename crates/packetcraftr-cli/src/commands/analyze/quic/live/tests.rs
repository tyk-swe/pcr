use super::*;
use clap::Parser;
use packetcraftr_core::{
    budget::{Cancellation, Deadline},
    frame::Frame,
    protocol::builtin,
};
use std::{
    io::{Cursor, Write},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

struct Backend {
    frames: Vec<Frame>,
    keys: PathBuf,
    shutdowns: Arc<AtomicUsize>,
    cancel: Option<Cancellation>,
    fail_cleanup: bool,
    drops: u64,
}
impl net::interface::Provider for Backend {
    fn interfaces(&self, _: &Deadline) -> Result<Vec<net::interface::Info>, net::interface::Error> {
        Ok(Vec::new())
    }
}
impl packetcraftr::CaptureProviders for Backend {
    type Interface = Self;
    type Capture = Self;
    fn interface(&self) -> &Self {
        self
    }
    fn capture(&self) -> &Self {
        self
    }
}
struct Session {
    frames: std::vec::IntoIter<Frame>,
    metadata: net::capture::Metadata,
    keys: PathBuf,
    shutdowns: Arc<AtomicUsize>,
    cancel: Option<Cancellation>,
    fail_cleanup: bool,
    stats: net::capture::Stats,
}
impl net::capture::Provider for Backend {
    type Capture = Session;
    fn arm_capture(
        &self,
        request: &net::capture::Request,
        _: &Deadline,
    ) -> Result<Session, net::Error> {
        Ok(Session {
            frames: self.frames.clone().into_iter(),
            metadata: net::capture::Metadata {
                interface: request.interface.clone(),
                link_type: self.frames[0].link_type,
                snap_length: request.limits.snap_length,
                native: net::capture::RealizedSettings::default(),
            },
            keys: self.keys.clone(),
            shutdowns: Arc::clone(&self.shutdowns),
            cancel: self.cancel.clone(),
            fail_cleanup: self.fail_cleanup,
            stats: net::capture::Stats {
                dropped_frames: self.drops,
                ..net::capture::Stats::default()
            },
        })
    }
}
impl net::capture::Session for Session {
    fn metadata(&self) -> &net::capture::Metadata {
        &self.metadata
    }
    fn wait_ready(&mut self, _: &Deadline) -> Result<(), net::Error> {
        Ok(())
    }
    fn next_captured_frame(
        &mut self,
        _: &Deadline,
    ) -> Result<Option<net::capture::Captured>, net::Error> {
        let keys = include_bytes!("../../../../../../../examples/captures/quic-demo.keys");
        let split = keys.len() / 2;
        let appended = match self.stats.received_frames {
            4 => &keys[..split],
            6 => &keys[split..],
            _ => &[],
        };
        if !appended.is_empty() {
            std::fs::OpenOptions::new()
                .append(true)
                .open(&self.keys)
                .unwrap()
                .write_all(appended)
                .unwrap();
        }
        if self.stats.received_frames == 2
            && let Some(cancel) = &self.cancel
        {
            cancel.cancel();
        }
        let Some(frame) = self.frames.next() else {
            return Ok(None);
        };
        self.stats.received_frames += 1;
        self.stats.received_bytes += frame.bytes().len() as u64;
        Ok(Some(net::capture::Captured::new(
            frame,
            Some(Instant::now()),
        )))
    }
    fn shutdown(&mut self) -> Result<(), net::Error> {
        self.shutdowns.fetch_add(1, Ordering::Relaxed);
        if self.fail_cleanup {
            return Err(net::Unsupported::new(
                net::NativeCapability::Capture,
                "synthetic cleanup failure",
            )
            .into());
        }
        Ok(())
    }
    fn stats(&self) -> net::capture::Stats {
        self.stats
    }
}
#[derive(Parser)]
struct Command {
    #[command(flatten)]
    args: Args,
}
fn capture(
    cancel: bool,
    fail_cleanup: bool,
    drops: u64,
    max_output_bytes: Option<usize>,
) -> (Result<Outcome, CliError>, usize, Args, Invocation) {
    let directory = tempfile::tempdir().unwrap();
    let keys = directory.path().join("session.keys");
    std::fs::write(&keys, []).unwrap();
    let mut args = Command::parse_from([
        "quic",
        "--interface",
        "mock",
        "--keylog",
        keys.to_str().unwrap(),
    ])
    .args;
    args.max_application_output_bytes =
        max_output_bytes.unwrap_or(args.max_application_output_bytes);
    let cancellation = Cancellation::default();
    let invocation = Invocation::new(
        crate::output::contract::Format::Json,
        crate::invocation::StreamEncoder::new(
            crate::output::contract::Command::Quic,
            std::io::sink(),
        ),
        Some(Duration::from_secs(30)),
        cancellation.clone(),
        None,
    );
    let bytes = include_bytes!("../../../../../../../examples/captures/quic-demo-v1.pcap");
    let mut reader = capture_file::Reader::with_limits(
        Cursor::new(bytes),
        capture_file::ReaderLimits::default(),
    )
    .unwrap();
    let mut frames = Vec::new();
    while let Some(frame) = reader.next_frame().unwrap() {
        frames.push(frame);
    }
    let setup =
        crate::commands::offline_analysis::prepare(args.limits, None, &args.decode).unwrap();
    let mut options = setup.options(&invocation);
    options.track_sources = true;
    let context = Context {
        pipeline: analysis::FramePipeline::new(builtin::registry(), options).unwrap(),
        collector: quic::Collector::new(quic::Limits::default()).unwrap(),
        secrets: keylog::Input::open(Some(&keys)).unwrap(),
        state: State::new(&args).unwrap(),
        interfaces: Vec::new(),
    };
    let shutdowns = Arc::new(AtomicUsize::new(0));
    let policy = packetcraftr::policy::Policy {
        max_packets_per_operation: frames.len() as u64,
        ..packetcraftr::policy::Policy::default()
    };
    let backend = Backend {
        frames,
        keys,
        shutdowns: Arc::clone(&shutdowns),
        cancel: cancel.then_some(cancellation.clone()),
        fail_cleanup,
        drops,
    };
    let client = packetcraftr::Client::new(builtin::registry(), policy, backend)
        .with_cancellation(cancellation);
    let request = packetcraftr::capture::Request::new(
        net::capture::GroupRequest {
            interfaces: vec![net::interface::Id {
                name: "mock".into(),
                index: 1,
            }],
            limits: net::capture::Limits {
                overflow_policy: net::capture::OverflowPolicy::DropNewest,
                ..net::capture::Limits::default()
            },
            filter: None,
            promiscuous: false,
            native: net::capture::NativeSettings::default(),
        },
        Duration::from_secs(30),
    );
    let result = drive(&client, request, context, &args, &invocation);
    (result, shutdowns.load(Ordering::Relaxed), args, invocation)
}
#[test]
fn live_quic_follows_appended_secrets_and_preserves_capture_loss() {
    let (outcome, shutdowns, _, _) = capture(false, false, 1, None);
    let outcome = outcome.unwrap_or_else(|e| panic!("{}", e.message));
    assert_eq!(shutdowns, 1);
    assert_eq!(
        outcome.capture.summary.sources[0].statistics.dropped_frames,
        1
    );
    assert_eq!(outcome.run.frames_read, 9);
    let mut connections = Vec::new();
    let summary = outcome
        .collector
        .finish(&Deadline::new(Duration::from_secs(30)), |event| {
            connections.push(event);
            Ok(())
        })
        .unwrap();
    assert_eq!(summary.decrypted_packets, 10);
    let quic::Event::Connection { connection } = &connections[0];
    assert_eq!(connection.pending_packets, 0);
    assert_eq!(connection.metrics.key_updates, 1);
    let client = connection
        .streams
        .iter()
        .find(|s| s.id == 0 && s.direction == quic::Direction::Client)
        .unwrap();
    assert!(client.complete);
    assert_eq!(&client.ranges[0].data[..], b"hello world");
}
#[test]
fn live_quic_cancellation_and_cleanup_failure_preserve_partial_evidence() {
    for (cancel, fail_cleanup) in [(true, false), (false, true)] {
        let (outcome, shutdowns, _, _) = capture(cancel, fail_cleanup, 0, None);
        let error = outcome.err().expect("capture must fail");
        assert!(shutdowns >= 1);
        let snapshot = error
            .output_error()
            .capture
            .expect("partial capture report");
        assert!(!snapshot.summary.sources.is_empty());
        if cancel {
            assert!(snapshot.summary.frames_delivered < 9);
        }
        if fail_cleanup {
            assert!(!snapshot.summary.capture_statistics_complete);
        }
    }
}

#[test]
fn live_quic_finalization_failure_retains_capture_statistics() {
    let (outcome, shutdowns, args, invocation) = capture(false, false, 7, Some(1));
    let outcome = outcome.unwrap_or_else(|error| panic!("{}", error.message));
    assert_eq!(shutdowns, 1);
    let error = super::super::finish(
        &args,
        &invocation,
        outcome.run,
        Some(outcome.capture),
        outcome.collector,
        outcome.secrets,
        outcome.state,
    )
    .unwrap_err();
    let snapshot = error
        .output_error()
        .capture
        .expect("capture evidence after finalization failure");
    assert_eq!(snapshot.summary.sources[0].statistics.dropped_frames, 7);
    assert_eq!(snapshot.summary.frames_delivered, 9);
}
