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
    runtime::{Runtime, Worker},
    scan,
};
use packetcraftr_core::{
    budget::{Cancellation, Deadline},
    protocol::builtin,
};
use std::{
    io::{self, Write},
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

#[derive(Clone, Default)]
struct Writer {
    bytes: Arc<Mutex<Vec<u8>>>,
    visible: Arc<Mutex<Vec<u8>>>,
    threads: Arc<Mutex<Vec<std::thread::ThreadId>>>,
}
impl Write for Writer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.threads
            .lock()
            .unwrap()
            .push(std::thread::current().id());
        self.bytes.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        *self.visible.lock().unwrap() = self.bytes.lock().unwrap().clone();
        Ok(())
    }
}
struct Refused;
impl packetcraftr_netio::route::Provider for Refused {
    type Error = packetcraftr_netio::route::Error;
    fn lookup_with_preferences(
        &self,
        _: std::net::IpAddr,
        _: Option<&packetcraftr_netio::interface::Id>,
        _: Option<std::net::IpAddr>,
        _: &Deadline,
    ) -> Result<packetcraftr_netio::route::Decision, Self::Error> {
        panic!("a controlled socket scan must not query routes")
    }
}
impl packetcraftr_netio::interface::Provider for Refused {
    fn interfaces(
        &self,
        _: &Deadline,
    ) -> Result<Vec<packetcraftr_netio::interface::Info>, packetcraftr_netio::interface::Error>
    {
        panic!("a controlled socket scan must not enumerate interfaces")
    }
}
impl packetcraftr_netio::capture::Provider for Refused {
    type Capture = packetcraftr_netio::capture::SystemSession;
    fn arm_capture(
        &self,
        _: &packetcraftr_netio::capture::Request,
        _: &Deadline,
    ) -> Result<Self::Capture, packetcraftr_netio::Error> {
        panic!("a controlled socket scan must not start capture")
    }
}
impl packetcraftr_netio::transmit::Provider for Refused {
    fn send(
        &self,
        _: packetcraftr_netio::transmit::Outbound<'_>,
    ) -> Result<packetcraftr_netio::transmit::Report, packetcraftr_netio::Error> {
        panic!("a controlled socket scan must not transmit packets")
    }
}
impl packetcraftr::target::Resolver for Refused {
    fn resolve(
        &self,
        _: &packetcraftr::target::Hostname,
        _: usize,
    ) -> Result<Vec<std::net::IpAddr>, packetcraftr::target::Error> {
        panic!("a numeric socket scan must not resolve hostnames")
    }
}
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

fn providers()
-> impl packetcraftr::PacketProviders + packetcraftr::TargetProviders + packetcraftr::TcpProviders {
    ProviderSet::packet(Refused, Refused, Refused, Refused)
        .with_tcp(Refused)
        .with_resolver(Refused)
}

fn recovered_worker(runtime: &Runtime) -> Worker<usize, usize> {
    let guard = Instant::now() + Duration::from_secs(5);
    loop {
        match Worker::new_in(runtime, |event| Ok(event + 1)) {
            Ok(worker) => return worker,
            Err(_) => {
                assert!(Instant::now() < guard, "output admission did not recover");
                std::thread::yield_now();
            }
        }
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
    let sink = emitter(&invocation, move |event: scan::connect::Event, stream| {
        callback_threads
            .lock()
            .unwrap()
            .push(std::thread::current().id());
        let scan::connect::Event::Probe(probe) = event;
        let value =
            output::scan::connect::ProbeEvent::try_from(probe).map_err(CliError::classified)?;
        stream.emit_data(value, Vec::new()).map_err(CliError::from)
    });
    assert_eq!(sink.delivery(), Delivery::Cooperative);
    let providers = providers();
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
    assert_eq!(
        callbacks.lock().unwrap().as_slice(),
        &[std::thread::current().id()]
    );
    let record: serde_json::Value =
        serde_json::from_slice(&writer.visible.lock().unwrap()).unwrap();
    assert_eq!(record["event"], "connect_probe");
    assert_eq!(record["sequence"], 0);
    assert_eq!(record["result"]["address"], "192.0.2.11");
    assert_eq!(record["result"]["port"], 80);
    assert_eq!(record["result"]["attempt"], 1);
    assert_eq!(record["result"]["attempted"], true);
    assert_eq!(record["result"]["outcome"], "refused");
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
    let visible = writer.visible.lock().unwrap();
    let records: Vec<serde_json::Value> = visible
        .split_inclusive(|byte| *byte == b'\n')
        .map(|line| {
            assert_eq!(line.last(), Some(&b'\n'));
            serde_json::from_slice(line).unwrap()
        })
        .collect();
    assert_eq!(records.len(), 2);
    assert_eq!(records[1]["event"], "complete");
    assert_eq!(records[1]["sequence"], 1);
    assert_eq!(records[1]["result"], serde_json::json!({"done": true}));
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
        self.release.recv_timeout(Duration::from_secs(10)).unwrap();
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
        let providers = providers();
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
        assert!(Worker::new_in(&writer_runtime, |_: ()| Ok(())).is_err());
        release.send(()).unwrap();
        caller.join().unwrap();
        assert!(returned_under_control.unwrap().is_err());
        assert!(!invocation.output.is_complete());
        assert!(!invocation.output.is_open());
        drop(invocation);
        let worker = recovered_worker(&writer_runtime);
        assert_eq!(
            worker
                .emit(7, &Deadline::new(Duration::from_secs(5)))
                .unwrap(),
            8
        );
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
        assert!(Worker::new_in(&runtime, |_: ()| Ok(())).is_err());
        release.send(()).unwrap();
        caller.join().unwrap();
        assert!(returned_under_control.unwrap().is_err());
        assert!(!invocation.output.is_complete());
        drop(invocation);
        let worker = recovered_worker(&runtime);
        assert_eq!(
            worker
                .emit(9, &Deadline::new(Duration::from_secs(5)))
                .unwrap(),
            10
        );
    }
}
