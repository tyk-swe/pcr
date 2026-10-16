// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::output::{
    self,
    contract::{Command, Format},
};
use packetcraftr::{
    Client, ProviderSet,
    policy::{DestinationConstraint, Policy},
    runtime::Runtime,
    scan,
};
use packetcraftr_core::{
    budget::{Cancellation, Deadline},
    protocol::builtin,
};
use std::{
    io::{self, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

#[derive(Clone, Default)]
struct Writer {
    writes: Arc<AtomicUsize>,
    flushes: Arc<AtomicUsize>,
    threads: Arc<Mutex<Vec<std::thread::ThreadId>>>,
}
impl Write for Writer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.threads
            .lock()
            .unwrap()
            .push(std::thread::current().id());
        self.writes.fetch_add(1, Ordering::Relaxed);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
struct Refused;
impl packetcraftr_netio::tcp::Provider for Refused {
    type Stream = packetcraftr_netio::tcp::SystemStream;
    fn connect(
        &self,
        _: std::net::SocketAddr,
        _: &Deadline,
    ) -> Result<Self::Stream, packetcraftr_netio::tcp::Error> {
        Err(io::Error::from(io::ErrorKind::ConnectionRefused).into())
    }
}

fn request() -> scan::Request {
    scan::Request {
        tcp_scan: Default::default(),
        sctp_scan: Default::default(),
        target_sources: Vec::new(),
        max_in_flight: 1,
        targets: "192.0.2.11"
            .parse::<packetcraftr::target::Target>()
            .unwrap()
            .into(),
        udp_payload: Default::default(),
        udp_profiles: Default::default(),
        address_family: packetcraftr::target::Family::Any,
        endpoints: vec![packetcraftr::probe::Endpoint::Tcp { port: 80 }],
        discovery: Default::default(),
        attempts: 1,
        adaptive: None,
        timeout: Duration::from_secs(2),
        probes_per_second: None,
        limits: scan::Limits {
            max_duration: Duration::from_secs(5),
            ..Default::default()
        },
        route: Default::default(),
        collection: Default::default(),
    }
}

struct Counted<T> {
    value: T,
    count: Arc<AtomicUsize>,
}
impl<T: serde::Serialize> serde::Serialize for Counted<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.value.serialize(serializer)
    }
}
impl<T: output::stream::StreamRecord> output::stream::StreamRecord for Counted<T> {
    fn event_name(&self) -> &'static str {
        self.value.event_name()
    }
}

#[test]
fn bounded_ndjson_followup_sink_uses_no_workflow_handoff_and_flushes_each_record() {
    let writer = Writer::default();
    let writer_runtime = Runtime::new(1).unwrap();
    let workflow_runtime = Runtime::new(0).unwrap();
    let stream = output::stream::StreamEncoder::new_bounded(
        Command::Scan,
        writer.clone(),
        &writer_runtime,
        Duration::from_secs(5),
    )
    .unwrap();
    let invocation = Invocation::new(
        Format::Ndjson,
        stream.into(),
        None,
        Cancellation::default(),
        None,
    );
    let callbacks = Arc::new(Mutex::new(Vec::new()));
    let callback_threads = Arc::clone(&callbacks);
    let serializations = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&serializations);
    let sink = emitter(&invocation, move |event: scan::connect::Event, stream| {
        callback_threads
            .lock()
            .unwrap()
            .push(std::thread::current().id());
        let scan::connect::Event::Probe(probe) = event;
        let value =
            output::scan::connect::ProbeEvent::try_from(probe).map_err(CliError::classified)?;
        stream
            .emit_data(
                Counted {
                    value,
                    count: Arc::clone(&counted),
                },
                Vec::new(),
            )
            .map_err(CliError::from)
    });
    assert_eq!(sink.delivery(), Delivery::Cooperative);
    let providers = ProviderSet::packet(
        packetcraftr_netio::route::SystemProvider,
        packetcraftr_netio::interface::SystemProvider,
        packetcraftr_netio::capture::SystemProvider,
        packetcraftr_netio::transmit::SystemProvider,
    )
    .with_tcp(Refused)
    .with_resolver(packetcraftr::target::SystemResolver);
    let client = Client::new(
        builtin::registry(),
        Policy {
            allowed_destinations: vec![DestinationConstraint::Exact("192.0.2.11".parse().unwrap())],
            ..Default::default()
        },
        providers,
    )
    .with_runtime(workflow_runtime.clone());
    client
        .scan_connect_with_followups(
            scan::followup::ConnectRequest {
                scan: request(),
                reverse_dns: None,
            },
            sink,
        )
        .unwrap();
    assert_eq!(workflow_runtime.snapshot().active, 0);
    assert_eq!(workflow_runtime.snapshot().rejected_admissions, 0);
    assert_eq!(
        callbacks.lock().unwrap().as_slice(),
        &[std::thread::current().id()]
    );
    assert_eq!(serializations.load(Ordering::Relaxed), 1);
    assert_eq!(writer.writes.load(Ordering::Relaxed), 1);
    assert_eq!(writer.flushes.load(Ordering::Relaxed), 1);
    assert!(
        writer
            .threads
            .lock()
            .unwrap()
            .iter()
            .all(|id| *id != std::thread::current().id())
    );
    invocation
        .output
        .complete(serde_json::json!({"done": true}), Vec::new())
        .unwrap();
    assert_eq!(writer.writes.load(Ordering::Relaxed), 2);
    assert_eq!(writer.flushes.load(Ordering::Relaxed), 2);
}

#[test]
fn text_and_unisolated_writers_keep_the_isolated_callback_default() {
    for format in [Format::Text, Format::Ndjson] {
        let invocation = Invocation::new(
            format,
            StreamEncoder::new(Command::Scan, Writer::default()),
            None,
            Cancellation::default(),
            None,
        );
        let sink = emitter(&invocation, |_: (), _| Ok(()));
        assert_eq!(sink.delivery(), Delivery::Isolated);
    }
}

struct GateWriter {
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
}
impl Write for GateWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.entered.send(()).unwrap();
        self.release.recv().unwrap();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn cooperative_followup_publication_retains_parent_control_inside_the_writer_wait() {
    for frozen in [false, true] {
        let writer_runtime = Runtime::new(1).unwrap();
        let workflow_runtime = Runtime::new(0).unwrap();
        let (entered, writing) = mpsc::channel();
        let (release, held) = mpsc::channel();
        let stream = output::stream::StreamEncoder::new_bounded(
            Command::Scan,
            GateWriter {
                entered,
                release: held,
            },
            &writer_runtime,
            Duration::from_secs(30),
        )
        .unwrap();
        let invocation = Invocation::new(
            Format::Ndjson,
            stream.into(),
            None,
            Cancellation::default(),
            None,
        );
        let sink = emitter(&invocation, move |event: scan::connect::Event, stream| {
            let scan::connect::Event::Probe(probe) = event;
            stream
                .emit_data(
                    output::scan::connect::ProbeEvent::try_from(probe)
                        .map_err(CliError::classified)?,
                    Vec::new(),
                )
                .map_err(CliError::from)
        });
        let cancellation = Cancellation::default();
        let parent = if frozen {
            let now = Instant::now();
            Deadline::with_time_source(Duration::from_millis(200), move || now)
        } else {
            Deadline::new(Duration::from_secs(30)).with_cancellation(Some(cancellation.clone()))
        };
        let providers = ProviderSet::packet(
            packetcraftr_netio::route::SystemProvider,
            packetcraftr_netio::interface::SystemProvider,
            packetcraftr_netio::capture::SystemProvider,
            packetcraftr_netio::transmit::SystemProvider,
        )
        .with_tcp(Refused)
        .with_resolver(packetcraftr::target::SystemResolver);
        let client = Client::new(
            builtin::registry(),
            Policy {
                allowed_destinations: vec![DestinationConstraint::Exact(
                    "192.0.2.11".parse().unwrap(),
                )],
                ..Default::default()
            },
            providers,
        )
        .with_runtime(workflow_runtime.clone())
        .with_deadline(parent);
        let (returned, result) = mpsc::channel();
        let caller = std::thread::spawn(move || {
            returned
                .send(client.scan_connect_with_followups(
                    scan::followup::ConnectRequest {
                        scan: request(),
                        reverse_dns: None,
                    },
                    sink,
                ))
                .unwrap();
        });
        writing.recv_timeout(Duration::from_secs(5)).unwrap();
        if !frozen {
            cancellation.cancel();
        }
        let returned_under_control = result.recv_timeout(Duration::from_secs(5));
        let still_charged = writer_runtime.snapshot();
        release.send(()).unwrap();
        caller.join().unwrap();
        assert!(returned_under_control.unwrap().is_err());
        assert_eq!(still_charged.active, 1);
        assert_eq!(still_charged.timed_out_retaining_capacity, 1);
        assert!(!invocation.output.is_complete());
        assert!(!invocation.output.is_open());
        assert_eq!(workflow_runtime.snapshot().rejected_admissions, 0);
        drop(invocation);
        let guard = Instant::now() + Duration::from_secs(5);
        while writer_runtime.snapshot().active != 0 {
            assert!(Instant::now() < guard);
            std::thread::yield_now();
        }
    }
}

#[test]
fn invocation_without_duration_applies_cancellation_to_initial_and_replacement_outputs() {
    for replace in [false, true] {
        let runtime = Runtime::new(1).unwrap();
        let (entered, writing) = mpsc::channel();
        let (release, held) = mpsc::channel();
        let output = output::stream::StreamEncoder::new_bounded(
            Command::Scan,
            GateWriter {
                entered,
                release: held,
            },
            &runtime,
            Duration::from_secs(30),
        )
        .unwrap();
        let cancellation = Cancellation::default();
        let invocation = if replace {
            Invocation::new(
                Format::Ndjson,
                StreamEncoder::new(Command::Scan, Writer::default()),
                None,
                cancellation.clone(),
                None,
            )
            .with_output(output.into())
        } else {
            Invocation::new(
                Format::Ndjson,
                output.into(),
                None,
                cancellation.clone(),
                None,
            )
        };
        let publishing = invocation.output.clone();
        let (returned, result) = mpsc::channel();
        let caller = std::thread::spawn(move || {
            returned.send(publishing.complete((), Vec::new())).unwrap();
        });
        writing.recv_timeout(Duration::from_secs(5)).unwrap();
        cancellation.cancel();
        let returned_under_control = result.recv_timeout(Duration::from_secs(5));
        let still_charged = runtime.snapshot();
        release.send(()).unwrap();
        caller.join().unwrap();
        assert!(returned_under_control.unwrap().is_err());
        assert_eq!(still_charged.active, 1);
        assert!(!invocation.output.is_complete());
        drop(invocation);
        let guard = Instant::now() + Duration::from_secs(5);
        while runtime.snapshot().active != 0 {
            assert!(Instant::now() < guard);
            std::thread::yield_now();
        }
    }
}
