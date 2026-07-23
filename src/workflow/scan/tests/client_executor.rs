// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[derive(Clone)]
struct FixedRoute(RouteDecision);

impl RouteProvider for FixedRoute {
    type Error = Infallible;

    fn lookup(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
    ) -> Result<RouteDecision, Self::Error> {
        Ok(self.0.clone())
    }
}

#[derive(Clone)]
struct CountingRoute {
    decision: RouteDecision,
    calls: Arc<AtomicUsize>,
}

impl RouteProvider for CountingRoute {
    type Error = Infallible;

    fn lookup(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
    ) -> Result<RouteDecision, Self::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.decision.clone())
    }
}

#[derive(Clone)]
struct LifecycleIo {
    events: Arc<Mutex<Vec<&'static str>>>,
    fail_send: bool,
}

impl PacketIo for LifecycleIo {
    fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
        let mut events = self.events.lock().unwrap();
        assert!(events.as_slice().starts_with(&["arm", "ready"]));
        assert!(events[2..].iter().all(|event| *event == "send"));
        events.push("send");
        if self.fail_send {
            return Err(LiveIoError::Send {
                message: "scripted failure".to_owned(),
            });
        }
        Ok(IoSendReport {
            bytes_sent: frame.bytes().len(),
            wire_bytes: Some(frame.bytes().clone()),
        })
    }
}

struct LifecycleCapture(Arc<Mutex<Vec<&'static str>>>);

impl CaptureSession for LifecycleCapture {
    fn supports_monotonic_ingress_time(&self) -> bool {
        true
    }

    fn wait_ready(&mut self, _timeout: Duration) -> Result<(), LiveIoError> {
        self.0.lock().unwrap().push("ready");
        Ok(())
    }

    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame>, LiveIoError> {
        Ok(None)
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        self.0.lock().unwrap().push("shutdown");
        Ok(())
    }

    fn statistics(&self) -> CaptureStatistics {
        CaptureStatistics::default()
    }
}

impl CaptureProvider for LifecycleIo {
    type Capture = LifecycleCapture;

    fn arm_capture(
        &self,
        _route: &PlannedRoute,
        _limits: CaptureQueueLimits,
    ) -> Result<Self::Capture, LiveIoError> {
        self.events.lock().unwrap().push("arm");
        Ok(LifecycleCapture(Arc::clone(&self.events)))
    }
}

fn lifecycle_route() -> RouteDecision {
    RouteDecision {
        interface: InterfaceId {
            name: "test0".to_owned(),
            index: 7,
        },
        source_mac: None,
        selected_address: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        preferred_source: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        next_hop: None,
        selection_reason: RouteSelectionReason::OnLink,
        destination_scope: DestinationScope::Private,
        mtu: 1_500,
        capability: LinkCapability::Layer3,
        link_type: LinkType::IPV4,
    }
}

fn lifecycle_exchange_options() -> ExchangeOptions {
    let mut options = ExchangeOptions {
        send: crate::client::send::Options {
            destination: None,
            plan: PlanOptions {
                link_mode: LinkMode::Layer3,
                ..PlanOptions::default()
            },
            ..crate::client::send::Options::default()
        },
        timeout: Duration::from_millis(1),
        max_template_packets: 1,
        max_unsolicited: 8,
        max_responses: 8,
        max_capture_queue_frames: 8,
        max_captured_bytes: 1_024,
        ..ExchangeOptions::default()
    };
    options.decode.max_packet_size = 256;
    options
}

#[test]
fn client_scan_executor_waits_for_capture_and_always_shuts_it_down() {
    for fail_send in [false, true] {
        let registry = Arc::new(default_registry().unwrap());
        let events = Arc::new(Mutex::new(Vec::new()));
        let io = LifecycleIo {
            events: Arc::clone(&events),
            fail_send,
        };
        let client = Client::new(
            Arc::clone(&registry),
            FixedRoute(lifecycle_route()),
            NoNeighbors,
            io,
            private_scan_policy(),
        );
        let mut executor = ClientExecutor::new(&client, lifecycle_exchange_options());
        let batch = ScanBatch {
            probes: vec![ScanProbe {
                sequence: 0,
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                transport: ScanTransport::Tcp,
                port: Some(443),
                attempt: 1,
            }],
            timeout: Duration::from_secs(1),
        };

        let result = executor.execute(&batch);
        assert_eq!(result.is_err(), fail_send);
        assert_eq!(
            events.lock().unwrap().as_slice(),
            ["arm", "ready", "send", "shutdown"]
        );
    }
}

#[test]
fn client_scan_executor_reuses_a_route_lookup_for_a_port_batch() {
    let registry = Arc::new(default_registry().unwrap());
    let events = Arc::new(Mutex::new(Vec::new()));
    let route_calls = Arc::new(AtomicUsize::new(0));
    let client = Client::new(
        Arc::clone(&registry),
        CountingRoute {
            decision: lifecycle_route(),
            calls: Arc::clone(&route_calls),
        },
        NoNeighbors,
        LifecycleIo {
            events: Arc::clone(&events),
            fail_send: false,
        },
        private_scan_policy(),
    );
    let mut executor = ClientExecutor::new(&client, lifecycle_exchange_options());
    let batch = ScanBatch {
        probes: vec![
            ScanProbe {
                sequence: 0,
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                transport: ScanTransport::Tcp,
                port: Some(80),
                attempt: 1,
            },
            ScanProbe {
                sequence: 1,
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                transport: ScanTransport::Tcp,
                port: Some(443),
                attempt: 1,
            },
        ],
        timeout: Duration::from_secs(1),
    };

    let result = executor.execute(&batch).unwrap();
    assert_eq!(result.sent.len(), 2);
    assert_eq!(route_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        events.lock().unwrap().as_slice(),
        ["arm", "ready", "send", "send", "shutdown"]
    );
}

#[test]
fn client_dns_executor_waits_for_capture_and_always_shuts_it_down() {
    use crate::workflow::dns::{
        Exchange as DnsExchange, Executor as DnsExecutor, Probe as DnsProbe,
        QueryType as DnsQueryType, encode_query as encode_dns_query,
    };

    for fail_send in [false, true] {
        let registry = Arc::new(default_registry().unwrap());
        let events = Arc::new(Mutex::new(Vec::new()));
        let io = LifecycleIo {
            events: Arc::clone(&events),
            fail_send,
        };
        let client = Client::new(
            Arc::clone(&registry),
            FixedRoute(lifecycle_route()),
            NoNeighbors,
            io,
            private_scan_policy(),
        );
        let mut executor = DnsClientExecutor::new(&client, lifecycle_exchange_options());
        let exchange = DnsExchange {
            probe: DnsProbe {
                attempt: 1,
                server_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                server_port: 53,
                source_port: 50_000,
                transaction_id: 7,
                query_name: "www.example.".to_owned(),
                query_type: DnsQueryType::A,
                query: encode_dns_query("www.example", DnsQueryType::A, 7, true).unwrap(),
            },
            timeout: Duration::from_secs(1),
            max_responses: 8,
        };

        let result = executor.execute(&exchange);
        assert_eq!(result.is_err(), fail_send);
        assert_eq!(
            events.lock().unwrap().as_slice(),
            ["arm", "ready", "send", "shutdown"]
        );
    }
}

#[test]
fn client_traceroute_executor_waits_for_capture_and_always_shuts_it_down() {
    use crate::workflow::traceroute::{
        Batch as TracerouteBatch, Executor as TracerouteExecutor, Probe as TracerouteProbe,
        Strategy as TracerouteStrategy,
    };

    for fail_send in [false, true] {
        let registry = Arc::new(default_registry().unwrap());
        let events = Arc::new(Mutex::new(Vec::new()));
        let io = LifecycleIo {
            events: Arc::clone(&events),
            fail_send,
        };
        let client = Client::new(
            Arc::clone(&registry),
            FixedRoute(lifecycle_route()),
            NoNeighbors,
            io,
            private_scan_policy(),
        );
        let mut executor = TracerouteClientExecutor::new(&client, lifecycle_exchange_options());
        let batch = TracerouteBatch {
            probes: vec![TracerouteProbe {
                sequence: 0,
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                strategy: TracerouteStrategy::Udp,
                destination_port: Some(33_434),
                hop_limit: 1,
                attempt: 1,
            }],
            timeout: Duration::from_secs(1),
        };

        let result = executor.execute(&batch);
        assert_eq!(result.is_err(), fail_send);
        assert_eq!(
            events.lock().unwrap().as_slice(),
            ["arm", "ready", "send", "shutdown"]
        );
    }
}

#[test]
fn client_traceroute_executor_preserves_hop_identity_and_unique_transport_probes() {
    use crate::workflow::traceroute::{
        Batch as TracerouteBatch, Executor as TracerouteExecutor, Probe as TracerouteProbe,
        Strategy as TracerouteStrategy,
    };

    for strategy in [
        TracerouteStrategy::Udp,
        TracerouteStrategy::Tcp,
        TracerouteStrategy::Icmp,
    ] {
        let registry = Arc::new(default_registry().unwrap());
        let events = Arc::new(Mutex::new(Vec::new()));
        let client = Client::new(
            Arc::clone(&registry),
            FixedRoute(lifecycle_route()),
            NoNeighbors,
            LifecycleIo {
                events: Arc::clone(&events),
                fail_send: false,
            },
            private_scan_policy(),
        );
        let mut options = lifecycle_exchange_options();
        options.max_template_packets = 3;
        let mut executor = TracerouteClientExecutor::new(&client, options);
        let batch = TracerouteBatch {
            probes: (0_u64..3)
                .map(|sequence| TracerouteProbe {
                    sequence,
                    address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    strategy,
                    destination_port: match strategy {
                        TracerouteStrategy::Udp => Some(33_434 + sequence as u16),
                        TracerouteStrategy::Tcp => Some(443),
                        TracerouteStrategy::Icmp => None,
                    },
                    hop_limit: 4,
                    attempt: sequence as u32 + 1,
                })
                .collect(),
            timeout: Duration::from_secs(1),
        };

        let result = executor.execute(&batch).unwrap();
        assert_eq!(result.sent.len(), 3);
        assert!(
            result
                .sent
                .iter()
                .all(|packet| packet.get::<Ipv4>().unwrap().ttl == 4)
        );
        assert!(
            result
                .sent
                .windows(2)
                .all(|packets| packets[0].get::<Ipv4>().unwrap().identification
                    == packets[1].get::<Ipv4>().unwrap().identification)
        );
        let field = match strategy {
            TracerouteStrategy::Udp => "destination_port",
            TracerouteStrategy::Tcp => "sequence",
            TracerouteStrategy::Icmp => "body",
        };
        assert!(result.sent.windows(2).all(|packets| {
            packets[0].iter().nth(1).unwrap().field(field)
                != packets[1].iter().nth(1).unwrap().field(field)
        }));
        assert_eq!(
            events.lock().unwrap().as_slice(),
            ["arm", "ready", "send", "send", "send", "shutdown"]
        );
    }
}

#[test]
fn client_traceroute_executor_rejects_unsupported_link_capability_before_capture_or_send() {
    use crate::workflow::traceroute::{
        Batch as TracerouteBatch, Executor as TracerouteExecutor, Probe as TracerouteProbe,
        Strategy as TracerouteStrategy,
    };

    let registry = Arc::new(default_registry().unwrap());
    let events = Arc::new(Mutex::new(Vec::new()));
    let client = Client::new(
        Arc::clone(&registry),
        FixedRoute(lifecycle_route()),
        NoNeighbors,
        LifecycleIo {
            events: Arc::clone(&events),
            fail_send: false,
        },
        private_scan_policy(),
    );
    let mut options = lifecycle_exchange_options();
    options.send.plan.link_mode = LinkMode::Layer2;
    let mut executor = TracerouteClientExecutor::new(&client, options);
    let batch = TracerouteBatch {
        probes: vec![TracerouteProbe {
            sequence: 0,
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            strategy: TracerouteStrategy::Udp,
            destination_port: Some(33_434),
            hop_limit: 1,
            attempt: 1,
        }],
        timeout: Duration::from_millis(1),
    };

    let error = executor.execute(&batch).unwrap_err();
    assert_eq!(error.classification().kind, Kind::Capability);
    assert!(events.lock().unwrap().is_empty());
}

#[test]
fn client_traceroute_executor_rejects_invalid_strategy_ports_before_capture_or_send() {
    use crate::workflow::traceroute::{
        Batch as TracerouteBatch, Executor as TracerouteExecutor, Probe as TracerouteProbe,
        Strategy as TracerouteStrategy,
    };

    let registry = Arc::new(default_registry().unwrap());
    let events = Arc::new(Mutex::new(Vec::new()));
    let client = Client::new(
        Arc::clone(&registry),
        FixedRoute(lifecycle_route()),
        NoNeighbors,
        LifecycleIo {
            events: Arc::clone(&events),
            fail_send: false,
        },
        private_scan_policy(),
    );
    let mut executor = TracerouteClientExecutor::new(&client, lifecycle_exchange_options());
    for (strategy, destination_port) in [
        (TracerouteStrategy::Udp, None),
        (TracerouteStrategy::Tcp, Some(0)),
        (TracerouteStrategy::Icmp, Some(33_434)),
    ] {
        let batch = TracerouteBatch {
            probes: vec![TracerouteProbe {
                sequence: 0,
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                strategy,
                destination_port,
                hop_limit: 1,
                attempt: 1,
            }],
            timeout: Duration::from_millis(1),
        };
        let error = executor.execute(&batch).unwrap_err();
        assert_eq!(error.classification().code, "cli.traceroute_executor");
    }
    let mixed_tcp_ports = TracerouteBatch {
        probes: [80, 443]
            .into_iter()
            .enumerate()
            .map(|(index, destination_port)| TracerouteProbe {
                sequence: index as u64,
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                strategy: TracerouteStrategy::Tcp,
                destination_port: Some(destination_port),
                hop_limit: 1,
                attempt: index as u32 + 1,
            })
            .collect(),
        timeout: Duration::from_millis(1),
    };
    let error = executor.execute(&mixed_tcp_ports).unwrap_err();
    assert_eq!(error.classification().code, "cli.traceroute_executor");
    assert!(events.lock().unwrap().is_empty());
}
